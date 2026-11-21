#!/usr/bin/env bash
# Network attack simulation, run from Kali (10.10.66.100) in the isolated lab only.
# Non-destructive probes: nothing is exploited or modified on the victim.

VICTIM=192.168.1.10
FIREWALL=10.10.66.1

echo "=== 1. ICMP sweep toward the victim ==="
ping -c4 "$VICTIM"

echo "=== 2. TCP port scan (connect scan, no root needed) ==="
nmap -Pn -sT --top-ports 50 -T4 "$VICTIM"

echo "=== 3. SMB connection attempt (lateral movement style) ==="
nc -vz -w3 "$VICTIM" 445

echo "=== 4. HTTP request with an offensive tool User-Agent ==="
curl -s -m10 -A "sqlmap/1.8" -o /dev/null -w "HTTP %{http_code}\n" http://example.com/

echo "=== 5. Attempt to reach the firewall itself (must be blocked) ==="
nc -vz -w3 "$FIREWALL" 443

echo "=== done ==="
