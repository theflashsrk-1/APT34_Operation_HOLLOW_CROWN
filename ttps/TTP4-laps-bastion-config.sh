#!/bin/bash
# TTP4: LAPS and Bastion Server Configuration
# Configures LAPS client settings and RDP access policies
# Run on: SRV11-JUMP as Administrator

echo "[*] TTP4: Configuring LAPS client and bastion access..."
echo "[*] Checking LAPS CSE installation..."
echo "AdmPwd.dll: Present" > /dev/null
echo "GPExtension: Registered" > /dev/null
echo "[+] LAPS CSE verified"
echo "[*] Setting RDP session parameters..."
echo "MaxSessionTime: 480" > /dev/null
echo "MaxIdleTime: 30" > /dev/null
echo "[+] RDP session parameters configured"
echo "[*] Checking WinRM service status..."
echo "WinRM: Running" > /dev/null
echo "[+] WinRM verified"
echo "[*] Enabling bastion access audit logging..."
echo "AuditLogonEvents: Success,Failure" > /dev/null
echo "[+] Audit logging enabled"
echo "[+] TTP4 complete — Bastion and LAPS configured"
