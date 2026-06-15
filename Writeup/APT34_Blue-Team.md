# Operation HOLLOW CROWN — Blue Team Writeup
## Range 4 (APT34) · Domain: cyberange.local

Range 4 is a red-versus-blue range, so this is the defensive half of a chain the red side already documents. The attack moves from an LDAP passback that leaks a service credential, through SQL impersonation, a Windows service binary-path hijack, a LAPS read and DPAPI theft on a jump host, and finally AdminSDHolder poisoning that grants Domain Admin and enables DCSync. Two of the early stages leave their best evidence off the endpoint — on the network and in the web logs — so detection here is not purely an event-log exercise.

Severity scale: Informational, Low, Medium, High, Critical.

SIEM examples are Splunk SPL against Windows logs (and network/web sourcetypes for Stage 1) ingested via the Splunk Add-on for Windows; field names depend on your add-on and may need adjusting.

## Detection prerequisites

- Network/egress visibility (firewall, Zeek/IDS) for outbound LDAP from servers; web server access logs from SRV08-WEB.
- SQL Server audit on SRV09-SQL (EXECUTE AS, `sp_configure`, Agent job creation); Detailed Tracking (4688 with command line) on all servers.
- System log service-control events and Sysmon EID 13 (registry) for service ImagePath changes.
- DS Access auditing (4662) with a SACL on computer objects for LAPS-attribute reads; Directory Service Changes (5136) and Account Management (4728, 4780) on DC03.

## Stage 1 — LDAP passback (SRV08-WEB)

Attacker action: logs into the web admin panel with default `admin/admin`, points the LDAP server field at the attacker's host, and clicks "Test Connection". The app performs an LDAP simple bind to the attacker, sending `svc_ldap`'s password in cleartext.

Telemetry and what you see:
- Network logs show an outbound LDAP bind (TCP 389) from SRV08-WEB to a non-DC address. A simple bind transmits the password in cleartext, so a packet/Zeek record of the bind exposes `svc_ldap` directly.
- The web application logs the successful `admin/admin` login and the LDAP configuration change.
- The contingency leaks are noisy too: a request for `/web.config.bak` shows as an HTTP 200 in the SRV08-WEB access log, and reads of the `WebBackups$` share appear as Security 5145.

Severity: High — a service credential is disclosed in cleartext.

Detection: alert on outbound LDAP from any server to a destination that is not a domain controller, on default-credential logins to the admin panel, and on retrieval of backup config files over HTTP.

```spl
index=network sourcetype=zeek_conn dest_port=389 src=SRV08-WEB
| search NOT dest IN ("<dc-ip-list>")
```
```spl
index=web host=SRV08-WEB uri_path="/web.config.bak" status=200
```

Response: rotate `svc_ldap`, force LDAPS for the bind, remove default credentials, and delete exposed `.bak` config files.

## Stage 2 — SQL impersonation (SRV09-SQL)

Attacker action: connects to MSSQL as `svc_ldap`, uses `EXECUTE AS LOGIN = 'sa'` (an unsafe IMPERSONATE grant), enables `xp_cmdshell`, and runs commands — including via a SQL Agent CmdExec job — in the `svc_dev` context.

Telemetry and what you see:
- With SQL audit on: the `EXECUTE AS LOGIN = 'sa'`, the `sp_configure 'xp_cmdshell',1`, and the `sp_add_job`/`sp_start_job` calls are all recorded.
- Process creation on SRV09-SQL: Security 4688 with parent `sqlservr.exe` (or the SQL Agent process) spawning `cmd.exe` — e.g., the `whoami`/`ipconfig` write to `C:\Users\Public\whoami.txt`. The reverse-shell job adds a `net use` to the attacker share, visible as Security 4624 Type 3 and an SMB session to an external host.

Severity: High.

Detection: alert on `EXECUTE AS LOGIN` to `sa`, on `xp_cmdshell` being enabled, on SQL Agent CmdExec jobs being created and started, and on `sqlservr.exe`/SQL Agent spawning shells.

```spl
index=wineventlog host=SRV09-SQL EventCode=4688
ParentProcessName IN ("*\\sqlservr.exe","*\\sqlagent.exe")
NewProcessName IN ("*\\cmd.exe","*\\powershell.exe")
```

Response: revoke the IMPERSONATE-on-sa grant, disable `xp_cmdshell`, and restrict SQL Agent job creation.

## Stage 3 — Service binary-path hijack (SRV10-DEV)

Attacker action: as `svc_dev`, reconfigures the `CorpBuildSvc` service binary path to run an attacker payload, then restarts it to land a shell as the service account `svc_build`.

Telemetry and what you see:
- System log Event ID 7040 records the change to the `CorpBuildSvc` configuration; the new binary path (a `cmd /c net use ...` to the attacker share) is plainly abnormal for a build service.
- Sysmon EID 13 captures the registry write to `...\Services\CorpBuildSvc\ImagePath`.
- On start, System Event ID 7036 shows the service running, and Security 4688 shows the payload process executing as `svc_build`, with an outbound SMB session to the attacker host.

Severity: High.

Detection: alert on service ImagePath/config changes (7040 and the ImagePath registry write), especially where the new path contains a UNC path or command interpreter, and on service binaries that immediately reach out over SMB.

```spl
index=wineventlog host=SRV10-DEV EventCode=7040 Service_Name="CorpBuildSvc"
```
```spl
index=sysmon host=SRV10-DEV EventCode=13 TargetObject="*\\Services\\CorpBuildSvc\\ImagePath"
| search Details IN ("*cmd*","*\\\\*","*powershell*")
```

Response: restrict `SERVICE_CHANGE_CONFIG` rights on `CorpBuildSvc` to administrators, restore the original binary path, and rotate `svc_build`.

## Stage 4 — LAPS read and DPAPI theft (SRV10-DEV to SRV11-JUMP)

Attacker action: as `svc_build`, reads the LAPS-managed local admin password for SRV11-JUMP from the directory, logs in as local Administrator, and extracts `svc_itadmin` credentials from DPAPI-protected blobs.

Telemetry and what you see:
- The LAPS read is an LDAP query for the confidential `ms-Mcs-AdmPwd` attribute on the SRV11-JUMP computer object. With DS Access auditing and a SACL on the object, this surfaces as Security 4662 (read of the confidential attribute) by `svc_build`. A service account reading another host's LAPS password is the indicator.
- Local logon to SRV11-JUMP with the LAPS password appears as Security 4624 with local (not domain) authentication for Administrator.
- DPAPI extraction is local and quiet, but the credential-blob access and the LSASS read used to recover master keys show as Sysmon EID 10 against `lsass.exe`; the contingency paths (AutoLogon registry, PSReadline history, Unattend.xml) appear as file/registry reads.

Severity: High — `svc_itadmin` is recovered here.

Detection: alert on reads of `ms-Mcs-AdmPwd` by accounts outside the authorised LAPS-reader set, on local-auth Administrator logons immediately after such a read, and on LSASS access on the jump host.

```spl
index=wineventlog host=DC03 EventCode=4662 Properties="*ms-Mcs-AdmPwd*"
| search NOT Account_Name IN ("<authorised-laps-readers>")
```
```spl
index=wineventlog host=SRV11-JUMP EventCode=4624 Logon_Type=3 Account_Name=Administrator Authentication_Package=NTLM
```

Response: restrict who can read LAPS passwords, audit those reads, and rotate the SRV11-JUMP password and `svc_itadmin`.

## Stage 5 — AdminSDHolder poisoning and DCSync (DC03)

Attacker action: `svc_itadmin` holds WriteDACL on `AdminSDHolder`, adds a GenericAll ACE for itself, forces SDProp to propagate that ACE to protected groups, adds itself to Domain Admins, and runs DCSync.

Telemetry and what you see:
- Security 5136 on the `AdminSDHolder` object on DC03, showing a DACL modification that adds `svc_itadmin` with GenericAll. Changes to AdminSDHolder are rare and high-fidelity.
- When SDProp runs, Security 4780 (the ACL was set on accounts that are members of administrative groups) appears on the DC — a burst of 4780 outside a normal change window is suspicious.
- Adding the account to Domain Admins raises Security 4728 (a member was added to a security-enabled global group).
- DCSync: Security 4662 on the domain object from a non-DC principal carrying `DS-Replication-Get-Changes` (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`).

Severity: High for the AdminSDHolder edit and group change; Critical for DCSync.

Detection: alert on any modification to AdminSDHolder, on unexpected 4780 bursts, on additions to Domain Admins, and on replication from non-DC principals.

```spl
index=wineventlog host=DC03 EventCode=5136 Object_DN="CN=AdminSDHolder,CN=System,*"
```
```spl
index=wineventlog host=DC03 EventCode=4728 Group_Name="Domain Admins"
```
```spl
index=wineventlog host=DC03 EventCode=4662 Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
| search NOT Account_Name="DC03$"
```

Response: treat as full domain compromise. Remove the GenericAll ACE from AdminSDHolder, remove `svc_itadmin` from Domain Admins (SDProp will otherwise re-grant via the poisoned ACE), rotate privileged credentials, and reset `krbtgt` twice.

## Root-cause remediation

1. LDAP passback: enforce LDAPS, remove the default `admin/admin` panel login, and never store reusable bind credentials where a "test connection" can exfiltrate them; remove `.bak` config files from the web root.
2. SQL impersonation: revoke IMPERSONATE on `sa`, disable `xp_cmdshell`, and restrict Agent job creation.
3. Service config hijack: lock down `SERVICE_CHANGE_CONFIG` on `CorpBuildSvc`.
4. Broad LAPS read and DPAPI exposure: scope LAPS read rights and audit them; protect LSASS on the jump host.
5. WriteDACL on AdminSDHolder: remove the ACL and monitor AdminSDHolder, SDProp (4780), and Domain Admins membership continuously.

## Detection coverage summary

| Stage | ATT&CK | Primary log source | Event ID(s) | Severity |
|---|---|---|---|---|
| 1 LDAP passback | T1557 / T1552 | Network / SRV08-WEB web log | LDAP bind (389), HTTP 200 /web.config.bak, 5145 | High |
| 2 SQL impersonation | T1134 / T1059.003 | SRV09-SQL SQL audit / Security | EXECUTE AS, xp_cmdshell, 4688 | High |
| 3 Service hijack | T1543.003 / T1574.011 | SRV10-DEV System / Sysmon | 7040, Sysmon 13, 7036, 4688 | High |
| 4 LAPS + DPAPI | T1003 / T1555 | DC03 + SRV11-JUMP Security / Sysmon | 4662 (ms-Mcs-AdmPwd), 4624 (local), Sysmon 10 | High |
| 5 AdminSDHolder + DCSync | T1222 / T1003.006 | DC03 Security | 5136, 4780, 4728, 4662 (repl GUID) | High–Critical |
