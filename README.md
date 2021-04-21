# SIGMA detection rules

## Project purpose:
**SIGMA detection rules** provides a free set of advanced correlation rules to be used for suspicious activity hunting. 

## How to use the rules:
The SIGMA rules can be used in different ways together with your SIEM:
* Using the native SIGMA converter: https://github.com/Neo23x0/sigma
* Using SOC Prime online SIGMA converter: https://uncoder.io/
* Using the SOC Prime free Kibana plugin: https://github.com/socprime/SigmaUI

## Microsoft products used:
* Windows 7 and higher
* Windows Server 2008 R2 and higher
* Active Directory Domain Services (ADDS)
* Active Directory Certification Services (ADCS / PKI) with online responder (OCSP)
* SQL Server 2014
* Windows Defender
* SYSMON v11 -- *pending*

## SIGMA rules content

Att@ck Tactic	| Att@ck  Technique	| Description | 	Event IDs   |
|:-------------------------|:------------------|:-------------------------|:------------------|
Antivirus | Antivirus | Defender: antivirus not up to date | 1151
Antivirus | Antivirus | Defender: exception added | 5007
Antivirus | Antivirus | Defender: massive malware outbreak detected on multiple hosts | 1116
Antivirus | Antivirus | Defender: massive malwares detected on a single host | 1116
TA0002-Execution | T1059.001-Command and Scripting Interpreter: PowerShell  | Encoded PowerShell MSF payload via process execution | 4688
TA0002-Execution | T1059.003-Windows Command Shell  | SQL Server payload injectection for reverse shell (MSF) | 4688
TA0002-Execution | T1569.002-Service Execution  | PSexec installation detected | 4688
TA0003-Persistence | T1078.002-Valid accounts-Domain accounts | Account renamed to "admin" (or likely) | 4738
TA0003-Persistence | T1098.xxx-Account Manipulation  | User performing massive group membership changes on multiple differents groups | 4728, 4756
TA0003-Persistence | T1098.xxx-Account manipulation | Computer account set with new SPN | 4742
TA0003-Persistence | T1098.xxx-Account manipulation | Fake domain controller set with new SPN (DCshadow) | 4742
TA0003-Persistence | T1098.xxx-Account manipulation | Fake self password reset performing by Mimikatz (changeNTLM) | 4723
TA0003-Persistence | T1098.xxx-Account manipulation | Kerberos account password reset | 4723/4724
TA0003-Persistence | T1098.xxx-Account manipulation | Member added to a built-in Exchange security group | 4756
TA0003-Persistence | T1098.xxx-Account manipulation | SQL Server: Member had new privileges added to a database  | 33205
TA0003-Persistence | T1098.xxx-Account manipulation | SQL Server: Member had new privileges added to an instance | 33205
TA0003-Persistence | T1098.xxx-Account manipulation | SQL Server: new member added to a database role | 33205
TA0003-Persistence | T1098.xxx-Account manipulation | SQL Server: new member added to server role | 33205
TA0003-Persistence | T1098.xxx-Account manipulation | User account created and/or set with reversible encryption detected | 4738
TA0003-Persistence | T1098.xxx-Account manipulation | User account marked as "sensitive and cannot be delegated" its had protection removed | 4738
TA0003-Persistence | T1098.xxx-Account manipulation | User account set to not require Kerberos pre-authentication | 4738
TA0003-Persistence | T1098.xxx-Account manipulation | User account set to use Kerberos DES encryption | 4738
TA0003-Persistence | T1098.xxx-Account manipulation | User account set with new SPN | 5136
TA0003-Persistence | T1098.xxx-Account manipulation | User account with password set to never expire detected | 4738
TA0003-Persistence | T1098.xxx-Account manipulation | User account with password set to not require detected | 4738
TA0003-Persistence | T1136.001-Create account-Local account | Disbled Guest (and support_388945a0) accounts enabled | 4722
TA0003-Persistence | T1136.001-Create account-Local account | SQL Server: disabled SA account enabled | 33205
TA0003-Persistence | T1136.002-Create account-Domain account | Computer account created by a computer account | 4741
TA0003-Persistence | T1136.002-Create account-Domain account | User account created to fake a computer account (ends with "$") | 4720
TA0003-Persistence | T1505.001-SQL Stored Procedures  | SQL Server xp_cmdshell procedure activated | 18457
TA0003-Persistence | T1505.001-SQL Stored Procedures  | SQL Server: sqlcmd & ossql utilities abuse | 4688
TA0003-Persistence | T1505.001-SQL Stored Procedures  | SQL Server: started in single mode for password recovery | 4688
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Mimikatz service driver installation detected (mimidrv.sys) | 4697/7045
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | MSF payload deployed via service | 4697/7045
TA0003-Persistence | T1546-Event Triggered Execution | AdminSDHolder container permissions modified | 5136
TA0003-Persistence | T1546-Event Triggered Execution | localizationDisplayId attribute abuse for backdoor introduction | 5136
TA0004-Privilege Escalation | T1134-Access Token Manipulation | New access rights granted to an account by a standard user | 4717
TA0004-Privilege Escalation | T1134-Access Token Manipulation | User right granted to an account by a standard user | 4704
TA0004-Privilege Escalation | T1484.001-Domain Policy Modification-Group Policy Modification | Modification of a sensitive Group Policy  | 5136
TA0004-Privilege Escalation | T1543.003-Create or Modify System Process-Windows Service | PSexec service installation detected | 4697/7045
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit object deleted | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit object disabled | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit specifications deleted | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit specifications disabled | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Database audit specifications deleted | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Database audit specifications disabled | 33205
TA0005-Defense Evasion | T1078.002-Valid accounts-Domain accounts | Login from a user member of a "special group" detected (special logon) | 4964
TA0005-Defense Evasion | T1207-Rogue domain controller | Sensitive attributes accessed (DCshadow) | 4662
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Computer account modifying AD permissions (PrivExchange) | 5136
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Network share permissions changed | 5143
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | OCSP security settings changed | 5124 (OCSP)
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Permissions changed on a GPO | 5136
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Sensitive GUID related to "Replicate directory changes" detected  | 4662
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | Firewall rule created by a suspicious command (netsh.exe, wmiprvse.exe) | 2004
TA0005-Defense Evasion | T1564.006-Hide Artifacts: Run Virtual Instance  | WSL for Windows installation detected | 4688
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | LSASS process accessed by a non system account | 4656/4663
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | SAM database accessed by a non system account | 4661
TA0006-Credential Access | T1003.006-DCSync | Member added to a sensitive Exchange security group to perform DCsync attack | 4756
TA0006-Credential Access | T1003.006-DCSync | Replication privileges granted to perform DCSync attack | 5136
TA0006-Credential Access | T1040-Network sniffing | Windows native sniffing tool Pktmon usage | 4688
TA0006-Credential Access | T1110.xxx-Brut force | Login failure from a single source with a disabled account | 33205
TA0006-Credential Access | T1110.xxx-Brut force | Login failure from a single source with different non existing accounts | 33205
TA0006-Credential Access | T1555-Credentials from Password Stores | Suspicious Active Directory DPAPI attributes accessed | 4662
TA0006-Credential Access | T1558.003-Kerberoasting  | KerberOAST ticket (TGS) request detected (low encryption) | 4769
TA0006-Credential Access | T1558-Steal or Forge Kerberos Tickets  | Susipicious Kerberos ticket (TGS) with constrained delegation (S4U2Proxy) | 4769
TA0006-Credential Access | T1558-Steal or Forge Kerberos Tickets  | Susipicious Kerberos ticket (TGS) with unconstrained delegation (TrustedForDelegation) | 4769
TA0007-Discovery | T1016-System Network Configuration Discovery  | Tentative of zone transfer from a non DNS server detected | 6004 (DNS server)
TA0007-Discovery | T1087.002-Domain Account discovery | Honeypot object (container, computer, group, user) enumerated | 4662/4624
TA0007-Discovery | T1087.002-Domain Account discovery | Single source performing host enumeration over Kerberos ticket (TGS) detected | 4769
TA0007-Discovery | T1087-Account discovery | Command execution related to Kerberos SPN enumeration activity detected | 4688 / 1
TA0007-Discovery | T1087-Account discovery | Command execution related to Kerberos SPN enumeration activity detected | 800/4103/4104
TA0008-Lateral Movement | T1021.001-Remote Desktop Protocol | Denied RDP authentication with valid credentials | 4825
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | New file share created on a host | 5142
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Remote service creation over SMB | 5145
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Admin share accessed via SMB (basic) | 5140/5145
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Psexec remote execution via SMB | 5145
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Remote shell execuction via SMB admin share | 5145
TA0008-Lateral Movement | T1021-Remote Services | Honeypot used for lateral movement | 4624/4625/47**