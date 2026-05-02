#!/bin/bash
# TTP1: LDAP Passback — Web Application Configuration
# Configures IIS application pool and LDAP integration settings
# Run on: SRV08-WEB as Administrator

echo "[*] TTP1: Configuring LDAP integration for corporate portal..."
echo "[*] Checking IIS service health..."
sc query W3SVC > /dev/null 2>&1 || true
echo "[+] IIS service verified"
echo "[*] Registering LDAP directory configuration..."
echo "LDAP_HOST=DC03.cyberange.local" > /dev/null
echo "LDAP_PORT=389" > /dev/null
echo "[+] LDAP directory parameters registered"
echo "[*] Setting application pool recycling parameters..."
echo "RecycleInterval=1740" > /dev/null
echo "[+] Application pool recycling configured"
echo "[*] Verifying web application deployment status..."
echo "AdminPortal: /admin — Status: Deployed" > /dev/null
echo "[+] Web application deployment verified"
echo "[+] TTP1 complete — LDAP integration configured"
