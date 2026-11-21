# Host-based scenarios, run in an ELEVATED PowerShell on the lab victim (Windows Server 2022 eval).
# Isolated lab only. Scenario B is cleaned up at the end.

# --- Scenario A: brute force (MITRE T1110) ---
# 8 failed logons -> Security event 4625
1..8 | ForEach-Object {
    net use \\127.0.0.1\IPC$ /user:administrateur "WrongPassword$_" 2>&1 | Select-Object -First 1
    net use \\127.0.0.1\IPC$ /delete 2>$null | Out-Null
}

# --- Scenario B: persistence via a new local admin account (T1136.001 / T1098) ---
# Random throwaway password, never stored
$pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
net user svc-backup $pw /add /comment:LAB-test      # event 4720 / 4722 / 4738
net localgroup administrators svc-backup /add        # event 4732
net localgroup administrators

# --- Cleanup ---
net user svc-backup /delete                          # event 4726 / 4733
net localgroup administrators
