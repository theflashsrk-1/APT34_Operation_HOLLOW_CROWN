# Operation HOLLOW CROWN — Assessment Questions

## Red Team Assessment (25 Questions)

### Step 1 — LDAP Passback
1. What default credentials does the admin portal use?
2. What protocol does the "Test Connection" button use to send credentials?
3. What is the AuthType used (making credentials capturable in cleartext)?
4. What tool can you use to capture the LDAP bind request?
5. What are the captured svc_ldap credentials?

### Step 2 — SQL Impersonation
6. What SQL privilege does svc_ldap have that enables escalation?
7. What SQL command escalates your context to sa?
8. What SQL subsystem runs OS commands via SQL Agent?
9. What domain account does the SQL Agent CmdExec step run as?
10. What contingency path bypasses IMPERSONATE via TRUSTWORTHY?

### Step 3 — Service Hijack
11. What service runs as svc_build on SRV10-DEV?
12. What file does the attacker modify to execute code as svc_build?
13. What AD permission does svc_build have that progresses the attack?
14. What PowerShell command reads the LAPS password from AD?
15. What contingency uses an MSI payload for SYSTEM access?

### Step 4 — LAPS + DPAPI
16. What nxc module reads LAPS passwords?
17. Where are DPAPI credential blobs stored on disk?
18. What mimikatz command dumps DPAPI master keys from LSASS?
19. Whose saved RDP credentials are extracted from SRV11-JUMP?
20. What contingency reveals credentials in PowerShell command history?

### Step 5 — AdminSDHolder
21. What ACL does svc_itadmin have on AdminSDHolder?
22. What process propagates AdminSDHolder ACEs to protected groups?
23. How often does SDProp run in this lab environment?
24. Why does removing svc_itadmin from Domain Admins NOT break persistence?
25. What must the blue team clean to permanently break the attack chain?

## Answer Key

1. admin:admin
2. LDAP (port 389)
3. AuthType.Basic (cleartext Simple Bind)
4. Responder, netcat, or custom LDAP listener
5. svc_ldap / Ld@pB1nd#2025!
6. IMPERSONATE on sa
7. EXECUTE AS LOGIN = 'sa'
8. CmdExec
9. cyberange\svc_dev
10. TRUSTWORTHY database + db_owner → EXECUTE AS USER = 'dbo'
11. CorpBuildSvc (NSSM-wrapped)
12. C:\BuildService\BuildMonitor.ps1
13. ReadLAPSPassword on OU=Servers (via BuildOps group)
14. Get-AdmPwdPassword -ComputerName SRV11-JUMP (or DirectorySearcher for ms-Mcs-AdmPwd)
15. C3c: AlwaysInstallElevated — msfvenom MSI payload
16. -M laps
17. C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\ and Local\Microsoft\Credentials\
18. sekurlsa::dpapi
19. svc_itadmin (saved RDP creds for DC03)
20. C4b: PSReadline history in ConsoleHost_history.txt
21. WriteDACL
22. SDProp (Security Descriptor Propagator)
23. Every 2 minutes (lab accelerated via scheduled task)
24. SDProp re-propagates the GenericAll ACE from AdminSDHolder to Domain Admins every cycle
25. The GenericAll ACE on AdminSDHolder itself (CN=AdminSDHolder,CN=System)
