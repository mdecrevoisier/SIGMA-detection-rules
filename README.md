# SIGMA detection rules

## Project purpose:
**SIGMA detection rules** provides a free set of advanced correlation rules to be used for suspicious activity hunting. 

## How to use the rules:
The SIGMA rules can be used in different ways together with your SIEM:
* Using the native SIGMA converter: https://github.com/Neo23x0/sigma
* Using SOC Prime online SIGMA converter: https://uncoder.io/
* Using the SOC Prime free Kibana plugin: https://github.com/socprime/SigmaUI

## Microsoft products used:
* Windows 10
* Windows Server 2021 R2 and higher
* Active Directory Domain Services (ADDS)
* Active Directory Certification Services (ADCS / PKI) with online responder (OCSP)
* SQL Server 2014
* Windows Defender
* SYSMON v11 and higher
* Exchange 2016
* Internet Information Services (IIS web server) -- *planned*

## SIGMA rules content

Att@ck Tactic	| Att@ck  Technique	| Description | 	Event IDs   |
|:-------------------------|:------------------|:-------------------------|:------------------|
Antivirus | Antivirus | Defender: antivirus not up to date | 1151
Antivirus | Antivirus | Defender: exception added | 5007
Antivirus | Antivirus | Defender: massive malware outbreak detected on multiple hosts | 1116
Antivirus | Antivirus | Defender: massive malwares detected on a single host | 1116
TA0001-Initial access | T1078.002-Valid accounts-Domain accounts | Login failure from a single source with a disabled account | 33205
TA0001-Initial access | T1078.002-Valid accounts-Domain accounts | Success login on OpenSSH server | 4624/4
TA0002-Execution | T1047-Windows Management Instrumentation  | Impacket WMIexec process execution | 4688
TA0002-Execution | T1053.005-Scheduled Task | Persistent scheduled task with SYSTEM privileges creation | 4688
TA0002-Execution | T1053.005-Scheduled Task | Scheduled task creation | 4688
TA0002-Execution | T1059.001-Command and Scripting Interpreter: PowerShell  | Encoded PowerShell payload deployed (PowerShell) | 800/4103/4104
TA0002-Execution | T1059.001-Command and Scripting Interpreter: PowerShell  | Interactive PipeShell over SMB named pipe | 800/4103/4104
TA0002-Execution | T1059.003-Windows Command Shell  | Encoded PowerShell payload deployed via process execution | 4688
TA0002-Execution | T1059.003-Windows Command Shell  | SQL Server payload injectection for reverse shell (MSF) | 4688
TA0002-Execution | T1569.002-Service Execution  | PSexec installation detected | 4688
TA0003-Persistence | T1098.xxx-Account Manipulation  | High risk domain group membership change | 4728/4756
TA0003-Persistence | T1098.xxx-Account Manipulation  | High risk local-domain local group membership change | 4732
TA0003-Persistence | T1098.xxx-Account Manipulation  | Medium risk local-domain local group membership change | 4732
TA0003-Persistence | T1098.xxx-Account Manipulation  | User performing massive group membership changes on multiple differents groups | 4728,4756
TA0003-Persistence | T1098.xxx-Account manipulation | Computer account set with new SPN | 4742
TA0003-Persistence | T1098.xxx-Account manipulation | Fake domain controller set with new SPN (DCshadow) | 4742
TA0003-Persistence | T1098.xxx-Account manipulation | Fake self password reset performing by Mimikatz (changeNTLM) | 4723
TA0003-Persistence | T1098.xxx-Account manipulation | Host delegation settings changed for potential abuse (any protocol) | 4742
TA0003-Persistence | T1098.xxx-Account manipulation | Host delegation settings changed for potential abuse (any service, Kerberos only) | 4742
TA0003-Persistence | T1098.xxx-Account manipulation | Host delegation settings changed for potential abuse (Kerberos only) | 4742
TA0003-Persistence | T1098.xxx-Account manipulation | Kerberos account password reset | 4723/4724
TA0003-Persistence | T1098.xxx-Account manipulation | Member added to a built-in Exchange security group | 4756
TA0003-Persistence | T1098.xxx-Account manipulation | Member added to DNSadmin group for DLL abuse | 4732
TA0003-Persistence | T1098.xxx-Account manipulation | New admin (or likely) created by a non administrative account | 4720
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
TA0003-Persistence | T1098-Account Manipulation | New member added to administration group related to OCS/Lync/Skype4B  | 4732/4756
TA0003-Persistence | T1098-Account Manipulation | SPN added to an account by command line | 4688/1
TA0003-Persistence | T1136.001-Create account-Local account | Disbled Guest (and support_388945a0) accounts enabled | 4722
TA0003-Persistence | T1136.001-Create account-Local account | SQL Server: disabled SA account enabled | 33205
TA0003-Persistence | T1136.002-Create account-Domain account | Computer account created by a computer account | 4741
TA0003-Persistence | T1136.002-Create account-Domain account | User account created to fake a computer account (ends with "$") | 4720
TA0003-Persistence | T1505.001-SQL Stored Procedures  | SQL lateral movement with CLR | 15457
TA0003-Persistence | T1505.001-SQL Stored Procedures  | SQL Server xp_cmdshell procedure activated | 18457
TA0003-Persistence | T1505.001-SQL Stored Procedures  | SQL Server: sqlcmd & ossql utilities abuse | 4688
TA0003-Persistence | T1505.001-SQL Stored Procedures  | SQL Server: started in single mode for password recovery | 4688
TA0003-Persistence | T1505.002-Server Software Component: Transport Agent | Exchange transport agent injection via configuration file | 11
TA0003-Persistence | T1505.002-Server Software Component: Transport Agent | Exchange transport agent installation artifacts (PowerShell) | 800/4103/4104
TA0003-Persistence | T1505.002-Server Software Component: Transport Agent | Exchange transport agent installation artifacts | 1/6
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Encoded PowerShell payload deployed via service installation | 4697/7045
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Mimikatz service driver installation detected (mimidrv.sys) | 4697/7045
TA0003-Persistence | T1543.003-Create or Modify System Process-Windows Service | Service created for RDP session hijack | 7045/4697
TA0003-Persistence | T1546.003 -Windows Management Instrumentation Event Subscription | WMI registration (PowerShell) | 800,4103,4104
TA0003-Persistence | T1546.003 -Windows Management Instrumentation Event Subscription | WMI registration | 19,20,21
TA0003-Persistence | T1546.007-Netsh Helper DLL | Netsh helper DLL command abuse | 4688
TA0003-Persistence | T1546.007-Netsh Helper DLL | Netsh helper DLL registry abuse | 12/13
TA0003-Persistence | T1546-Event Triggered Execution | AdminSDHolder container permissions modified | 5136
TA0003-Persistence | T1546-Event Triggered Execution | localizationDisplayId attribute abuse for backdoor introduction | 5136
TA0003-Persistence | T1574.002-DLL Side-Loading | DNS DLL "serverlevelplugindll" command execution (+registry set) | 1/13
TA0003-Persistence | T1574.002-DLL Side-Loading | Failed DLL loaded by DNS server | 150
TA0003-Persistence | T1574.002-DLL Side-Loading | Success DLL loaded by DNS server | 770
TA0004-Privilege Escalation | T1134-Access Token Manipulation | New access rights granted to an account by a standard user | 4717
TA0004-Privilege Escalation | T1134-Access Token Manipulation | User right granted to an account by a standard user | 4704
TA0004-Privilege Escalation | T1484.001-Domain Policy Modification-Group Policy Modification | Modification of a sensitive Group Policy  | 5136
TA0004-Privilege Escalation | T1543.003-Create or Modify System Process-Windows Service | PSexec service installation detected | 4697/7045
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features  | CMD executed by stickey key and detected via hash | 1
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features  | Sticky key called CMD via command execution | 4688/1
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features  | Sticky key failed sethc replacement by CMD | 4656
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features  | Sticky key file created from CMD copy | 11
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features  | Sticky key IFEO command for registry change | 4688
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features  | Sticky key IFEO registry changed | 12/13
TA0004-Privilege Escalation | T1546.008-Event Triggered Execution: Accessibility Features  | Sticky key sethc command for replacement by CMD | 4688
TA0004-Privilege Escalation | T1547.010-Port Monitors  | Print spooler privilege escalation via printer added (CVE-2020-1048) | 800/4103/4104
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit object deleted | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit object disabled | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit specifications deleted | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Audit specifications disabled | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Database audit specifications deleted | 33205
TA0005-Defense Evasion | T1070.xxx-Audit policy disabled | SQL Server: Database audit specifications disabled | 33205
TA0005-Defense Evasion | T1078.002-Valid accounts-Domain accounts | Login from a user member of a "special group" detected (special logon) | 4964
TA0005-Defense Evasion | T1112-Modify registry | Impacket SMBexec stealthy service registration | 13
TA0005-Defense Evasion | T1207-Rogue domain controller | Sensitive attributes accessed (DCshadow) | 4662
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Computer account modifying AD permissions (PrivExchange) | 5136
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Network share permissions changed | 5143
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | OCSP security settings changed | 5124(OCSP)
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Permissions changed on a GPO | 5136
TA0005-Defense Evasion | T1222.001-File and Directory Permissions Modification | Sensitive GUID related to "Replicate directory changes" detected  | 4662
TA0005-Defense Evasion | T1562.004-Disable or Modify System Firewall  | Firewall deactivation (cmd) | 4688
TA0005-Defense Evasion | T1562.004-Disable or Modify System Firewall  | Firewall deactivation (firewall) | 2003/4950
TA0005-Defense Evasion | T1562.004-Disable or Modify System Firewall  | Firewall deactivation (PowerShell) | 800/4103/4104
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | Firewall rule created by a suspicious command (netsh.exe, wmiprvse.exe) | 2004
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | OpenSSH server firewall configuration (command) | 4688/1
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | OpenSSH server firewall configuration (firewall) | 2004
TA0005-Defense Evasion | T1562.004-Disable/modify firewall (rule) | OpenSSH server firewall configuration (PowerShell) | 800/4103/4104
TA0005-Defense Evasion | T1564.006-Hide Artifacts: Run Virtual Instance  | WSL for Windows installation detected | 4688
TA0006-Credential Access | 1558.004-Steal or Forge Kerberos Tickets: AS-REP Roasting | erberoas AS-REP Roasting ticket request detected | 4768
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | LSASS process accessed by a non system account | 4656/4663
TA0006-Credential Access | T1003.001-Credential dumping: LSASS | SAM database user credential dump with Mimikatz | 4661
TA0006-Credential Access | T1003.002-Security Account Manager | SAM database access during DCshadow | 4661
TA0006-Credential Access | T1003.002-Security Account Manager | Secretdump password dump over SMB ADMIN$ | 5145
TA0006-Credential Access | T1003.003-NTDS | IFM created | 325/327
TA0006-Credential Access | T1003.003-NTDS | IFM created from command line | 4688
TA0006-Credential Access | T1003.006-DCSync | Member added to a sensitive Exchange security group to perform DCsync attack | 4756
TA0006-Credential Access | T1003.006-DCSync | Replication privileges granted to perform DCSync attack | 5136
TA0006-Credential Access | T1003-Credential dumping | Diskshadow abuse | 4688
TA0006-Credential Access | T1040-Network sniffing | Windows native sniffing tool Pktmon usage | 4688
TA0006-Credential Access | T1110.xxx-Brut force | Brutforce enumeration on Windows OpenSSH server with non existing user | 4625/4
TA0006-Credential Access | T1110.xxx-Brut force | Brutforce on Windows OpenSSH server with valid user | 4625/4
TA0006-Credential Access | T1110.xxx-Brut force | Login failure from a single source with different non existing accounts | 33205
TA0006-Credential Access | T1555-Credentials from Password Stores | Suspicious Active Directory DPAPI attributes accessed | 4662
TA0006-Credential Access | T1557.001-MiM:LLMNR/NBT-NS Poisoning and SMB Relay  | Discovery for print spooler bug abuse via named pipe | 5145
TA0006-Credential Access | T1557.001-MiM:LLMNR/NBT-NS Poisoning and SMB Relay  | Exchange server impersonation via PrivExchange relay attack | 4624
TA0006-Credential Access | T1558.001-Golden Ticket  | SMB Admin share accessed with a forged Golden ticket | 5140/5145
TA0006-Credential Access | T1558.001-Golden Ticket  | Success login impersonation with forged Golden ticket | 4624
TA0006-Credential Access | T1558.003-Kerberoasting  | KerberOAST ticket (TGS) request detected (low encryption) | 4769
TA0006-Credential Access | T1558-Steal or Forge Kerberos Tickets  | Susipicious Kerberos ticket (TGS) with constrained delegation (S4U2Proxy) | 4769
TA0006-Credential Access | T1558-Steal or Forge Kerberos Tickets  | Susipicious Kerberos ticket (TGS) with unconstrained delegation (TrustedForDelegation) | 4769
TA0007-Discovery | T1016-System Network Configuration Discovery  | Tentative of zone transfer from a non DNS server detected | 6004(DNSserver)
TA0007-Discovery | T1069.001-Discovery local groups | Remote local administrator group enumerated via SharpHound | 4799
TA0007-Discovery | T1069.002-Discovery domain groups | Massive SAM domain users & groups discovery | 4661
TA0007-Discovery | T1069.002-Discovery domain groups | Sensitive SAM domain user & groups discovery | 4661
TA0007-Discovery | T1087.002-Domain Account discovery | Honeypot object (container, computer, group, user) enumerated | 4662/4624
TA0007-Discovery | T1087.002-Domain Account discovery | Single source performing host enumeration over Kerberos ticket (TGS) detected | 4769
TA0007-Discovery | T1087-Account discovery | Command execution related to Kerberos SPN enumeration activity detected | 4688/1
TA0007-Discovery | T1087-Account discovery | Command execution related to Kerberos SPN enumeration activity detected | 800/4103/4104
TA0007-Discovery | T1135.xxx-Network Share Discovery | Host performing advanced named pipes enumeration on different hosts via SMB | 5145
TA0008-Lateral Movement | T1021.001-Remote Desktop Protocol | Denied RDP authentication with valid credentials | 4825
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Admin share accessed via SMB (basic) | 5140/5145
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Impacket WMIexec execution via SMB admin share | 5145
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | New file share created on a host | 5142
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Psexec remote execution via SMB | 5145
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Remote service creation over SMB | 5145
TA0008-Lateral Movement | T1021.002-SMB Windows Admin Shares | Remote shell execuction via SMB admin share | 5145
TA0008-Lateral Movement | T1021.003-DCOM | DCOM lateral movement (via MMC20) | 4104
TA0008-Lateral Movement | T1021.003-DCOM | DCOMexec privilege abuse | 4674
TA0008-Lateral Movement | T1021.003-DCOM | DCOMexec process abuse via MMC | 4688
TA0008-Lateral Movement | T1021.004-Remote services: SSH | OpenSSH native server feature installation | 800/4103/4104
TA0008-Lateral Movement | T1021.004-Remote services: SSH | OpenSSH server for Windows activation/configuration detected | 800/4103/4104
TA0008-Lateral Movement | T1021-Remote Services | Honeypot used for lateral movement | 4624/4625/47**
TA0008-Lateral Movement | T1563.002-RDP hijacking | RDP session hijack via TSCON abuse command | 4688
TA0011-Command and control | T1090-Proxy | Netsh port forwarding abuse via proxy | 4688