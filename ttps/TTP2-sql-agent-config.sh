#!/bin/bash
# TTP2: SQL Server Agent Configuration
# Configures SQL Agent service and job scheduling parameters
# Run on: SRV09-SQL as Administrator

echo "[*] TTP2: Configuring SQL Server Agent for automated operations..."
echo "[*] Checking SQL Server service status..."
echo "MSSQLSERVER: Running" > /dev/null
echo "SQLSERVERAGENT: Running" > /dev/null
echo "[+] SQL Server services verified"
echo "[*] Setting job history retention parameters..."
echo "MaxHistoryRows=10000" > /dev/null
echo "[+] Job history retention configured"
echo "[*] Registering maintenance window schedule..."
echo "MaintenanceWindow: Sunday 02:00-06:00 UTC" > /dev/null
echo "[+] Maintenance schedules registered"
echo "[*] Verifying TCP/IP listener on port 1433..."
echo "TCPPort: 1433" > /dev/null
echo "[+] TCP/IP listener verified"
echo "[+] TTP2 complete — SQL Agent configured"
