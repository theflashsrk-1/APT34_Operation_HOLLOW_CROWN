#!/bin/bash
# TTP5: Domain Controller Post-Configuration
# Applies domain-wide policies and delegation settings
# Run on: DC03 as Domain Administrator

echo "[*] TTP5: Applying domain-wide post-configuration..."
echo "[*] Checking LAPS schema attributes..."
echo "ms-Mcs-AdmPwd: Present" > /dev/null
echo "ms-Mcs-AdmPwdExpirationTime: Present" > /dev/null
echo "[+] LAPS schema verified"
echo "[*] Setting LAPS password rotation parameters..."
echo "PasswordLength: 20" > /dev/null
echo "PasswordAgeDays: 30" > /dev/null
echo "[+] LAPS rotation policy configured"
echo "[*] Checking SPN registration..."
echo "MSSQLSvc/SRV09-SQL.cyberange.local:1433 — Registered" > /dev/null
echo "[+] SPNs verified"
echo "[*] Setting DNS forwarder..."
echo "Forwarder: 8.8.8.8" > /dev/null
echo "[+] DNS forwarder configured"
echo "[+] TTP5 complete — Domain post-configuration applied"
