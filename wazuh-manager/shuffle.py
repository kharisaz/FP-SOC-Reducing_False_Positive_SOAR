#!/usr/bin/env python3

import sys
import os
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG_FILE  = "/tmp/ai_debug.log"
ERR_FILE  = "/tmp/err.log"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def err(msg):
    with open(ERR_FILE, "a") as f:
        f.write(msg + "\n")

# ==============================================================================
# RULE-BASED PRE-FILTER (sebelum AI dipanggil)
# Kalau rule ID atau level udah jelas false positive / noise → langsung drop
# ==============================================================================
NOISE_RULE_IDS = {
    "5501",   # PAM login session opened (normal)
    "5502",   # PAM session closed (normal)
    "5715",   # SSHD: authentication success
    "1002",   # Unknown problem somewhere in the system (low confidence)
    "31101",  # Web server 200 OK (normal traffic)
    "31102",  # Web server 304 Not Modified
    "533",    # Netstat port change - SSH/DNS ports normal
}

def is_obvious_noise(alert):
    rule_id    = str(alert.get("rule", {}).get("id", ""))
    rule_level = int(alert.get("rule", {}).get("level", 0))
    groups     = alert.get("rule", {}).get("groups", [])

    # Level 1-4 dan bukan grup berbahaya → drop langsung
    dangerous_groups = {"authentication_failed", "attack", "malware_detection",
                        "web_attack", "ids", "intrusion_detection", "ddos"}
    if rule_level <= 4 and not dangerous_groups.intersection(set(groups)):
        log(f"[PRE-FILTER] Dropped noise: rule_id={rule_id} level={rule_level} groups={groups}")
        return True

    if rule_id in NOISE_RULE_IDS:
        log(f"[PRE-FILTER] Dropped known noise rule_id={rule_id}")
        return True

    return False

# ==============================================================================
# AI ANALYSIS — Qwen2.5:1.5b via Ollama
# ==============================================================================
def check_with_local_ai(alert):
    rule        = alert.get("rule", {})
    rule_id     = rule.get("id", "unknown")
    rule_level  = rule.get("level", 0)
    description = rule.get("description", "")
    groups      = ", ".join(rule.get("groups", []))
    mitre_tac   = ", ".join(rule.get("mitre", {}).get("tactic", []))
    full_log    = alert.get("full_log", "")
    src_ip      = alert.get("data", {}).get("srcip", alert.get("data", {}).get("src_ip", "unknown"))
    agent_name  = alert.get("agent", {}).get("name", "unknown")

    prompt = f"""You are a senior SOC analyst. Classify this Wazuh security alert as ATTACK or FALSE_POSITIVE.

ALERT DETAILS:
- Rule ID    : {rule_id}
- Severity   : {rule_level}/15
- Description: {description}
- Groups     : {groups}
- MITRE Tactic: {mitre_tac}
- Source IP  : {src_ip}
- Agent      : {agent_name}
- Raw Log    : {full_log[:300]}

STRICT RULES (follow exactly, no exception):
- If rule_id is 5712, 5760, 5503, 2502, 100010, 100011, 100012 → ALWAYS answer ATTACK
- If description contains 'brute force', 'flooding', 'malware', 'attack', 'unauthorized' → ALWAYS answer ATTACK
- If rule level >= 10 AND groups contain 'authentication_failed' → ALWAYS answer ATTACK
- Only answer FALSE_POSITIVE if event is clearly normal: single sudo, service start/stop, routine cron

Reply with EXACTLY one word: ATTACK or FALSE_POSITIVE"""

    try:
        response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={"model": "qwen2.5:1.5b", "prompt": prompt, "stream": False},
            timeout=10
        )
        result = response.json()
        decision = result.get("response", "").strip().upper()

        # Ambil hanya kata pertama (antisipasi model jawab lebih dari 1 kata)
        first_word = decision.split()[0] if decision.split() else "ATTACK"

        if "FALSE_POSITIVE" in first_word:
            return "FALSE_POSITIVE"
        elif "ATTACK" in first_word:
            return "ATTACK"
        else:
            # Jawaban tidak dikenali → fail-safe ke ATTACK
            log(f"[AI] Unexpected response: '{decision}' → defaulting to ATTACK")
            return "ATTACK"

    except Exception as e:
        err(f"[AI ERROR] {str(e)}")
        return "ATTACK"  # fail-safe

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    # Ambil webhook URL dari args (Wazuh: argv[1]=file, argv[2]=apikey, argv[3]=url)
    shuffle_webhook_url = ""
    for arg in sys.argv[2:]:
        if arg.startswith("http"):
            shuffle_webhook_url = arg
            break

    if not shuffle_webhook_url:
        err(f"[MAIN] No webhook URL found in args: {sys.argv}")
        sys.exit(1)

    # Baca alert JSON
    try:
        with open(sys.argv[1], "r") as f:
            alert = json.load(f)
    except Exception as e:
        err(f"[MAIN] Failed to read alert file: {e}")
        sys.exit(1)

    rule_id    = alert.get("rule", {}).get("id", "?")
    rule_level = alert.get("rule", {}).get("level", 0)
    desc       = alert.get("rule", {}).get("description", "")

    log(f"\n[ALERT] rule_id={rule_id} level={rule_level} desc={desc[:80]}")

    # Stage 1: Rule-based pre-filter
    if is_obvious_noise(alert):
        log(f"[DECISION] FALSE_POSITIVE (pre-filter) → DROPPED")
        sys.exit(0)

    # Stage 2: AI classification
    ai_result = check_with_local_ai(alert)
    log(f"[AI DECISION] {ai_result}")

    if "FALSE_POSITIVE" in ai_result:
        log(f"[DECISION] FALSE_POSITIVE (AI) → DROPPED")
        sys.exit(0)

    # Lolos semua filter → kirim ke Shuffle SOAR
    log(f"[DECISION] ATTACK → forwarding to Shuffle")
    try:
        resp = requests.post(
            shuffle_webhook_url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(alert),
            verify=False,
            timeout=10
        )
        log(f"[SHUFFLE] status={resp.status_code} response={resp.text[:100]}")
    except Exception as e:
        err(f"[SHUFFLE ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
