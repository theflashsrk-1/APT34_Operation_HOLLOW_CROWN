# Operation HOLLOW CROWN — Storyline

## Background

CybeRange Solutions, a mid-size technology consulting firm, maintains a Windows Active Directory environment for internal operations. Their IT team recently deployed LAPS for local admin password management and uses a custom-built web portal for LDAP directory management. The environment follows a typical corporate topology: web frontend, SQL backend, development build server, and a jump/bastion host for privileged access.

## Threat Actor

APT34 (OilRig), an Iranian state-sponsored group attributed to MOIS, has been conducting espionage operations against technology companies to steal intellectual property and gain persistent access to partner organizations. Their tradecraft emphasizes credential harvesting, web application exploitation, and patient lateral movement.

## Attack Narrative

APT34 identifies the target's externally-reachable web management portal. The portal uses default credentials and has a configuration page that leaks LDAP bind credentials through a passback vulnerability. Using these credentials, the operator pivots to the SQL database server, escalates via IMPERSONATE privileges, and establishes command execution through SQL Agent jobs. From the SQL server, lateral movement to the build server exploits a weak service ACL to execute code as a privileged build account. This account can read LAPS passwords, providing local admin access to the bastion server. DPAPI-protected RDP credentials on the bastion reveal an IT admin account. The final stage poisons the AdminSDHolder container, causing SDProp to propagate elevated permissions to all protected groups — achieving persistent domain dominance.

## Operational Impact

Full Active Directory compromise. All domain credentials extractable via DCSync. AdminSDHolder persistence survives manual group membership cleanup — blue team must identify and clean the AdminSDHolder ACE to break the persistence chain.
