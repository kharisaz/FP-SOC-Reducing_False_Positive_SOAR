#!/bin/bash
MONITOR_DIRS="/tmp /home/azureuser/uploads"

echo "Starting ClamAV inotify monitor on: $MONITOR_DIRS"

# Monitor for file creation and write completion
inotifywait -m -r -e create -e close_write --format '%w%f' $MONITOR_DIRS | while read FILE
do
    # Check if it is a regular file and still exists
    if [ -f "$FILE" ]; then
        # Scan file using clamdscan (uses memory-resident signatures, takes milliseconds)
        SCAN_RESULT=$(clamdscan --fdpass --no-summary "$FILE" 2>/dev/null)
        if echo "$SCAN_RESULT" | grep -q "FOUND"; then
            # Extract the scan result line (e.g. /tmp/test.exe: Win.Test.EICAR_HSTR-2 FOUND)
            THREAT_LINE=$(echo "$SCAN_RESULT" | grep "FOUND" | head -n 1)
            # Log to syslog using the standard 'clamd' program tag so Wazuh decodes it automatically
            logger -t clamd "$THREAT_LINE"
            echo "[ALERT] Malware found and logged: $THREAT_LINE"
        fi
    fi
done
