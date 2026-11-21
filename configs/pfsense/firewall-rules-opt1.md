# pfSense: OPT1 (attacker segment) firewall rules

pfSense CE 2.7.2. Interface OPT1 (`em2`, 10.10.66.0/24) is the attacker segment where Kali lives.
Rules are evaluated top to bottom, first match wins. Anything not matched is dropped by the default deny rule.

| # | Action | Source | Destination | Port | Log | Purpose |
|---|--------|--------|-------------|------|-----|---------|
| 1 | Pass  | OPT1 subnets | OPT1 address | 53 TCP/UDP | no  | DNS through pfSense only |
| 2 | Block | OPT1 subnets | 192.168.56.0/24 | any | yes | Protect the admin / SIEM network |
| 3 | Block | OPT1 subnets | This Firewall (self) | any | yes | No access to the firewall itself (web UI, SSH...) |
| 4 | Pass  | OPT1 subnets | LAN subnets | any | yes | Attack traffic toward the victim, fully logged |
| 5 | Pass  | OPT1 subnets | any | any | no  | Internet for tool updates |

## Validation (from Kali, 10.10.66.100)

| Test | Expected | Result |
|------|----------|--------|
| `ping` / `nmap` to the victim 192.168.1.10 | pass + logged | pass, logged under rule 4 |
| `ping 1.1.1.1` | pass | pass |
| `curl https://10.10.66.1` (pfSense UI) | blocked | blocked (timeout), logged under rule 3 |
| `curl https://192.168.56.2` / `ping 192.168.56.1` | blocked | blocked, logged under rule 2 |

## Lesson learned: duplicate tracker IDs

Rules 3 and 4 were created within the same second and received the **same tracker ID**.
The traffic was correctly blocked, but the firewall log attributed it to the wrong rule
description ("Kali -> victim"). This matters for a SOC: a log line pointing to the wrong
rule misleads the analyst.

Fix: copy the rule (new tracker ID), delete the original, apply, re-test.
After the fix the block is logged under the correct description (see `evidence/01-...`).
