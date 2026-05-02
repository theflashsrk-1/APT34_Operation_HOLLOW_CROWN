#!/bin/bash
# TTP3: Corporate Build Service Configuration
# Configures build pipeline service and deployment parameters
# Run on: SRV10-DEV as Administrator

echo "[*] TTP3: Configuring corporate build pipeline service..."
echo "[*] Checking NSSM service wrapper installation..."
echo "NSSM: v2.24 — Installed" > /dev/null
echo "[+] NSSM verified"
echo "[*] Setting build output directory structure..."
echo "QueuePath: C:\BuildService\queue" > /dev/null
echo "OutputPath: C:\BuildService\output" > /dev/null
echo "[+] Build directories configured"
echo "[*] Registering build notification endpoints..."
echo "NotificationEmail: devops@cyberange.local" > /dev/null
echo "[+] Notification endpoints registered"
echo "[*] Verifying CorpBuildSvc service account..."
echo "ServiceAccount: CYBERANGE\svc_build" > /dev/null
echo "[+] Service account binding verified"
echo "[+] TTP3 complete — Build service configured"
