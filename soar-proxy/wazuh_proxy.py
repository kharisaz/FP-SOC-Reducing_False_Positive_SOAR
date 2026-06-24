from flask import Flask, request, jsonify
import requests
import urllib3
import logging
import json

logging.basicConfig(filename='/tmp/proxy.log', level=logging.INFO)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
WAZUH_URL = 'https://10.0.0.4:55000'
USER = 'wazuh'
PASS = 'wazuh'

def clean_agent_id(raw):
    raw = str(raw).strip()
    if raw.startswith("[") and raw.endswith("]"):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list) and len(parsed) > 0:
                return str(parsed[0]).strip().strip('"')
        except:
            pass
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    return raw

def is_valid_ip(s):
    parts = str(s).split('.')
    if len(parts) == 4:
        try:
            return all(0 <= int(p) < 256 for p in parts)
        except ValueError:
            return False
    return False

@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    try:
        app.logger.info(f"Received request body: {request.data}")
        app.logger.info(f"Original path: {path}, args: {request.args}")

        params = dict(request.args)

        # Clean agents_list from query params
        if "agents_list" in params:
            raw = params["agents_list"]
            cleaned = clean_agent_id(raw)
            params["agents_list"] = cleaned
            app.logger.info(f"Cleaned agents_list: {raw} -> {cleaned}")

        # Parse body - default to empty dict if body is empty/invalid
        try:
            body = json.loads(request.data.decode("utf-8"))
        except:
            body = {}

        new_args = []
        if "arguments" in body and isinstance(body["arguments"], list):
            for arg in body["arguments"]:
                if isinstance(arg, str):
                    arg_clean = arg.strip()
                    if arg_clean.startswith("[") and arg_clean.endswith("]"):
                        try:
                            parsed = json.loads(arg_clean)
                            if isinstance(parsed, list) and len(parsed) > 0:
                                new_args.append(str(parsed[0]))
                                continue
                        except:
                            pass
                    elif arg_clean.startswith('"') and arg_clean.endswith('"'):
                        new_args.append(arg_clean[1:-1])
                        continue
                new_args.append(arg)
            body["arguments"] = new_args

        # Move agents_list from body to params
        if "agents_list" in body:
            agents = body.pop("agents_list")
            if isinstance(agents, list):
                params["agents_list"] = ",".join(str(a).strip().strip('"') for a in agents)
            else:
                params["agents_list"] = clean_agent_id(str(agents))

        if "custom" in body:
            body.pop("custom")
        if "custom" in params:
            params.pop("custom")

        # Fix firewall-drop: rename command and inject srcip into alert
        if body.get("command") == "firewall-drop":
            body["command"] = "firewall-drop0"
            ip_to_block = None
            if new_args:
                for arg in new_args:
                    if isinstance(arg, str) and is_valid_ip(arg.strip()):
                        ip_to_block = arg.strip()
                        break
            if ip_to_block:
                body.setdefault("alert", {}).setdefault("data", {})["srcip"] = ip_to_block

        # Fix remove-threat: rename command and extract path if ClamAV
        if body.get("command") == "remove-threat":
            body["command"] = "remove-threat0"
            alert = body.get("alert", {})
            rule_id = str(alert.get("rule", {}).get("id", ""))
            # If ClamAV (rule 52502) or argument is empty/unresolved, extract from full_log
            if rule_id == "52502" or not new_args or new_args[-1] == "" or "$exec.syscheck.path" in str(new_args[-1]):
                full_log = alert.get("full_log", "")
                if ": " in full_log:
                    parts = full_log.split(": ")
                    path = None
                    for part in parts:
                        part_clean = part.strip()
                        if part_clean.startswith("/"):
                            path = part_clean
                            break
                    if path:
                        body["arguments"] = ["-", path]
                        app.logger.info(f"Extracted file path for ClamAV: {path}")

        # Wazuh API rejects empty body - always send at least {}
        req_data = json.dumps(body)
        app.logger.info(f"Final body: {req_data}")
        app.logger.info(f"Final params: {params}")

        auth_resp = requests.post(f"{WAZUH_URL}/security/user/authenticate", auth=(USER, PASS), verify=False)
        token = auth_resp.json()["data"]["token"]

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        for k, v in request.headers.items():
            if k.lower() not in ["host", "authorization", "content-length", "content-type"]:
                headers[k] = v

        url = f"{WAZUH_URL}/{path}"

        if request.method == "PUT":
            resp = requests.put(url, headers=headers, params=params, data=req_data, verify=False)
        elif request.method == "POST":
            resp = requests.post(url, headers=headers, params=params, data=req_data, verify=False)
        elif request.method == "GET":
            resp = requests.get(url, headers=headers, params=params, verify=False)
        else:
            resp = requests.delete(url, headers=headers, params=params, data=req_data, verify=False)

        app.logger.info(f"Wazuh response code: {resp.status_code}")
        app.logger.info(f"Wazuh response body: {resp.text}")

        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=15500, ssl_context="adhoc")
