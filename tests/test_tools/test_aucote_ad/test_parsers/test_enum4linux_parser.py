from unittest import TestCase

from tools.acuote_ad.parsers.enum4linux_parser import Enum4linuxParser


class Enum4linuxParserTest(TestCase):
    OS_INFORMATION = r""" ===================================== 
|    OS information on 10.12.2.175    |
 ===================================== 
[+] Got OS info for 10.12.2.175 from smbclient: Domain=[CS] OS=[Windows Server 2012 R2 Standard 9600] Server=[Windows Server 2012 R2 Standard 6.3]
[+] Got OS info for 10.12.2.175 from srvinfo:
	10.12.2.175    Wk Sv PDC Tim NT     
	platform_id     :	500
	os version      :	6.3
	server type     :	0x280102b"""

    USERS = r""" ============================ 
|    Users on 10.12.2.175    |
 ============================ 
index: 0xf4d RID: 0x1f4 acb: 0x00000010 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0x101e RID: 0x451 acb: 0x00000210 Account: jkowalski	Name: Jan JK. Kowalski	Desc: (null)

user:[Administrator] rid:[0x1f4]
user:[jkowalski] rid:[0x451]"""

    SHARES = r""" ======================================== 
|    Share Enumeration on 10.12.2.175    |
 ======================================== 
WARNING: The "syslog" option is deprecated
Domain=[CS] OS=[Windows Server 2012 R2 Standard 9600] Server=[Windows Server 2012 R2 Standard 6.3]

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Connection to 10.12.2.175 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
NetBIOS over TCP disabled -- no workgroup available

[+] Attempting to map shares on 10.12.2.175
//10.12.2.175/ADMIN$	Mapping: OK, Listing: OK
//10.12.2.175/C$	[E] Can't understand response:
WARNING: The "syslog" option is deprecated
Domain=[CS] OS=[Windows Server 2012 R2 Standard 9600] Server=[Windows Server 2012 R2 Standard 6.3]
  $Recycle.Bin                      DHS        0  Sat Nov 22 05:17:48 2014
  bootmgr                          AHSR   404250  Sat Nov 22 01:45:46 2014
  BOOTNXT                           AHS        1  Tue Jun 18 12:18:29 2013
  Documents and Settings            DHS        0  Thu Aug 22 14:48:41 2013
  history.js                          A       70  Wed Aug 16 21:01:41 2017
  inetpub                             D        0  Wed Aug 23 12:24:07 2017
  pagefile.sys                      AHS 1677721600  Thu Aug 24 07:45:30 2017
  PerfLogs                            D        0  Thu Aug 22 15:52:33 2013
  Program Files                      DR        0  Wed Aug 23 12:24:10 2017
  Program Files (x86)                 D        0  Wed Aug 23 12:24:10 2017
  ProgramData                        DH        0  Thu Aug 24 07:47:19 2017
  rb_config.js                        A      234  Wed Aug 16 21:01:41 2017
  System Volume Information         DHS        0  Wed Aug 23 12:25:05 2017
  Users                              DR        0  Wed Aug 23 12:26:16 2017
  Windows                             D        0  Thu Aug 24 07:43:48 2017

		13017087 blocks of size 4096. 10049765 blocks available
//10.12.2.175/IPC$	Mapping: OK	Listing: DENIED
//10.12.2.175/NETLOGON	Mapping: OK, Listing: OK
//10.12.2.175/SYSVOL	Mapping: OK, Listing: OK"""

    OUTPUT = r"""WARNING: ldapsearch is not in your path.  Check that package is installed and your PATH is sane.
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Aug 30 18:49:59 2017

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.12.2.175
RID Range ........ 500-550,1000-1050
Username ......... 'administrator'
Password ......... 'Iseisebaby!2'
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =================================================== 
|    Enumerating Workgroup/Domain on 10.12.2.175    |
 =================================================== 
[+] Got domain/workgroup name: CS.ISE

 =========================================== 
|    Nbtstat Information for 10.12.2.175    |
 =========================================== 
Looking up status of 10.12.2.175
No reply from 10.12.2.175

 ==================================== 
|    Session Check on 10.12.2.175    |
 ==================================== 
[+] Server 10.12.2.175 allows sessions using username 'administrator', password 'Iseisebaby!2'

 ========================================== 
|    Getting domain SID for 10.12.2.175    |
 ========================================== 
Domain Name: CS
Domain Sid: S-1-5-21-3794042296-3353869093-3402567874
[+] Host is part of a domain (not a workgroup)

{os_information}

{users}

{shares}

 =================================================== 
|    Password Policy Information for 10.12.2.175    |
 =================================================== 

[+] Attaching to 10.12.2.175 using administrator:Iseisebaby!2

	[+] Trying protocol 445/SMB...

[+] Found domain(s):

	[+] CS
	[+] Builtin

[+] Password Info for Domain: CS

	[+] Minimum password length: 7
	[+] Password history length: 24
	[+] Maximum password age: 41 days 23 hours 52 minutes
	[+] Password Complexity Flags: 000001

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 1

	[+] Minimum password age: 1 day 
	[+] Reset Account Lockout Counter: 30 minutes
	[+] Locked Account Duration: 30 minutes
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: Not Set

[+] Retieved partial password policy with rpcclient:

Password Complexity: Enabled
Minimum Password Length: 7


 ============================= 
|    Groups on 10.12.2.175    |
 ============================= 

[+] Getting builtin groups:
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[Server Operators] rid:[0x225]
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]

[+] Getting builtin group memberships:
Group 'Users' (RID: 545) has member: NT AUTHORITY\INTERACTIVE
Group 'Users' (RID: 545) has member: NT AUTHORITY\Authenticated Users
Group 'Users' (RID: 545) has member: CS\Domain Users
Group 'IIS_IUSRS' (RID: 568) has member: NT AUTHORITY\IUSR
Group 'Administrators' (RID: 544) has member: CS\Administrator
Group 'Administrators' (RID: 544) has member: CS\Enterprise Admins
Group 'Administrators' (RID: 544) has member: CS\Domain Admins
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: NT AUTHORITY\Authenticated Users
Group 'Guests' (RID: 546) has member: CS\Guest
Group 'Guests' (RID: 546) has member: CS\Domain Guests
Group 'Windows Authorization Access Group' (RID: 560) has member: NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[WinRMRemoteWMIUsers__] rid:[0x3e8]
group:[DnsAdmins] rid:[0x44e]

[+] Getting local group memberships:
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CS\krbtgt
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CS\Domain Controllers
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CS\Schema Admins
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CS\Enterprise Admins
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CS\Cert Publishers
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CS\Domain Admins
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CS\Group Policy Creator Owners
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CS\Read-only Domain Controllers

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44f]

[+] Getting domain group memberships:
Group 'Enterprise Admins' (RID: 519) has member: CS\Administrator
Group 'Domain Controllers' (RID: 516) has member: CS\WIN-DUSS7GPO657$
Group 'Group Policy Creator Owners' (RID: 520) has member: CS\Administrator
Group 'Domain Computers' (RID: 515) has member: CS\CSISE$
Group 'Domain Guests' (RID: 514) has member: CS\Guest
Group 'Schema Admins' (RID: 518) has member: CS\Administrator
Group 'Domain Users' (RID: 513) has member: CS\Administrator
Group 'Domain Users' (RID: 513) has member: CS\krbtgt
Group 'Domain Users' (RID: 513) has member: CS\jdoe
Group 'Domain Users' (RID: 513) has member: CS\jkowalski
Group 'Domain Admins' (RID: 512) has member: CS\Administrator

 ====================================================================== 
|    Users on 10.12.2.175 via RID cycling (RIDS: 500-550,1000-1050)    |
 ====================================================================== 
[I] Found new SID: S-1-5-21-3794042296-3353869093-3402567874
[I] Found new SID: S-1-5-21-833310794-1261029646-3490875958
[I] Found new SID: S-1-5-90
[I] Found new SID: S-1-5-82-3876422241-1344743610-1729199087-774402673
[I] Found new SID: S-1-5-82-3006700770-424185619-1745488364-794895919
[I] Found new SID: S-1-5-82-271721585-897601226-2024613209-625570482
[I] Found new SID: S-1-5-80-3139157870-2983391045-3678747466-658725712
[I] Found new SID: S-1-5-80
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-21-3794042296-3353869093-3402567874 and logon username 'administrator', password 'Iseisebaby!2'
S-1-5-21-3794042296-3353869093-3402567874-500 CS\Administrator (Local User)
S-1-5-21-3794042296-3353869093-3402567874-501 CS\Guest (Local User)
S-1-5-21-3794042296-3353869093-3402567874-502 CS\krbtgt (Local User)
S-1-5-21-3794042296-3353869093-3402567874-503 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-504 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-505 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-506 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-507 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-508 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-509 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-510 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-511 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-512 CS\Domain Admins (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-513 CS\Domain Users (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-514 CS\Domain Guests (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-515 CS\Domain Computers (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-516 CS\Domain Controllers (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-517 CS\Cert Publishers (Local Group)
S-1-5-21-3794042296-3353869093-3402567874-518 CS\Schema Admins (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-519 CS\Enterprise Admins (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-520 CS\Group Policy Creator Owners (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-521 CS\Read-only Domain Controllers (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-522 CS\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-523 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-525 CS\Protected Users (Domain Group)
S-1-5-21-3794042296-3353869093-3402567874-526 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-527 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-528 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-529 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-530 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-531 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-532 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-533 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-534 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-535 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-536 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-537 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-538 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-539 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-540 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-541 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-542 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-543 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-544 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-545 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-546 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-547 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-548 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-549 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-550 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1000 CS\WinRMRemoteWMIUsers__ (Local Group)
S-1-5-21-3794042296-3353869093-3402567874-1001 CS\WIN-DUSS7GPO657$ (Local User)
S-1-5-21-3794042296-3353869093-3402567874-1002 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1003 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1004 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1005 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1006 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1007 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1008 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1009 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1010 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1011 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1012 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1013 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1014 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1015 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1016 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1017 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1018 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1019 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1020 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1021 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1022 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1023 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1024 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1025 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1026 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1027 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1028 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1029 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1030 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1031 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1032 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1033 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1034 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1035 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1036 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1037 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1038 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1039 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1040 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1041 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1042 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1043 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1044 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1045 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1046 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1047 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1048 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1049 *unknown*\*unknown* (8)
S-1-5-21-3794042296-3353869093-3402567874-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-82-3006700770-424185619-1745488364-794895919 and logon username 'administrator', password 'Iseisebaby!2'
S-1-5-82-3006700770-424185619-1745488364-794895919-500 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-501 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-502 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-503 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-504 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-505 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-506 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-507 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-508 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-509 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-510 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-511 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-512 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-513 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-514 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-515 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-516 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-517 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-518 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-519 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-520 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-521 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-522 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-523 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-524 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-525 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-526 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-527 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-528 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-529 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-530 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-531 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-532 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-533 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-534 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-535 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-536 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-537 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-538 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-539 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-540 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-541 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-542 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-543 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-544 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-545 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-546 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-547 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-548 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-549 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-550 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1000 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1001 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1002 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1003 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1004 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1005 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1006 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1007 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1008 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1009 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1010 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1011 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1012 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1013 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1014 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1015 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1016 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1017 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1018 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1019 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1020 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1021 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1022 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1023 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1024 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1025 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1026 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1027 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1028 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1029 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1030 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1031 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1032 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1033 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1034 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1035 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1036 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1037 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1038 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1039 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1040 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1041 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1042 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1043 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1044 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1045 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1046 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1047 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1048 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1049 *unknown*\*unknown* (8)
S-1-5-82-3006700770-424185619-1745488364-794895919-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-80 and logon username 'administrator', password 'Iseisebaby!2'
S-1-5-80-500 *unknown*\*unknown* (8)
S-1-5-80-501 *unknown*\*unknown* (8)
S-1-5-80-502 *unknown*\*unknown* (8)
S-1-5-80-503 *unknown*\*unknown* (8)
S-1-5-80-504 *unknown*\*unknown* (8)
S-1-5-80-505 *unknown*\*unknown* (8)
S-1-5-80-506 *unknown*\*unknown* (8)
S-1-5-80-507 *unknown*\*unknown* (8)
S-1-5-80-508 *unknown*\*unknown* (8)
S-1-5-80-509 *unknown*\*unknown* (8)
S-1-5-80-510 *unknown*\*unknown* (8)
S-1-5-80-511 *unknown*\*unknown* (8)
S-1-5-80-512 *unknown*\*unknown* (8)
S-1-5-80-513 *unknown*\*unknown* (8)
S-1-5-80-514 *unknown*\*unknown* (8)
S-1-5-80-515 *unknown*\*unknown* (8)
S-1-5-80-516 *unknown*\*unknown* (8)
S-1-5-80-517 *unknown*\*unknown* (8)
S-1-5-80-518 *unknown*\*unknown* (8)
S-1-5-80-519 *unknown*\*unknown* (8)
S-1-5-80-520 *unknown*\*unknown* (8)
S-1-5-80-521 *unknown*\*unknown* (8)
S-1-5-80-522 *unknown*\*unknown* (8)
S-1-5-80-523 *unknown*\*unknown* (8)
S-1-5-80-524 *unknown*\*unknown* (8)
S-1-5-80-525 *unknown*\*unknown* (8)
S-1-5-80-526 *unknown*\*unknown* (8)
S-1-5-80-527 *unknown*\*unknown* (8)
S-1-5-80-528 *unknown*\*unknown* (8)
S-1-5-80-529 *unknown*\*unknown* (8)
S-1-5-80-530 *unknown*\*unknown* (8)
S-1-5-80-531 *unknown*\*unknown* (8)
S-1-5-80-532 *unknown*\*unknown* (8)
S-1-5-80-533 *unknown*\*unknown* (8)
S-1-5-80-534 *unknown*\*unknown* (8)
S-1-5-80-535 *unknown*\*unknown* (8)
S-1-5-80-536 *unknown*\*unknown* (8)
S-1-5-80-537 *unknown*\*unknown* (8)
S-1-5-80-538 *unknown*\*unknown* (8)
S-1-5-80-539 *unknown*\*unknown* (8)
S-1-5-80-540 *unknown*\*unknown* (8)
S-1-5-80-541 *unknown*\*unknown* (8)
S-1-5-80-542 *unknown*\*unknown* (8)
S-1-5-80-543 *unknown*\*unknown* (8)
S-1-5-80-544 *unknown*\*unknown* (8)
S-1-5-80-545 *unknown*\*unknown* (8)
S-1-5-80-546 *unknown*\*unknown* (8)
S-1-5-80-547 *unknown*\*unknown* (8)
S-1-5-80-548 *unknown*\*unknown* (8)
S-1-5-80-549 *unknown*\*unknown* (8)
S-1-5-80-550 *unknown*\*unknown* (8)
S-1-5-80-1000 *unknown*\*unknown* (8)
S-1-5-80-1001 *unknown*\*unknown* (8)
S-1-5-80-1002 *unknown*\*unknown* (8)
S-1-5-80-1003 *unknown*\*unknown* (8)
S-1-5-80-1004 *unknown*\*unknown* (8)
S-1-5-80-1005 *unknown*\*unknown* (8)
S-1-5-80-1006 *unknown*\*unknown* (8)
S-1-5-80-1007 *unknown*\*unknown* (8)
S-1-5-80-1008 *unknown*\*unknown* (8)
S-1-5-80-1009 *unknown*\*unknown* (8)
S-1-5-80-1010 *unknown*\*unknown* (8)
S-1-5-80-1011 *unknown*\*unknown* (8)
S-1-5-80-1012 *unknown*\*unknown* (8)
S-1-5-80-1013 *unknown*\*unknown* (8)
S-1-5-80-1014 *unknown*\*unknown* (8)
S-1-5-80-1015 *unknown*\*unknown* (8)
S-1-5-80-1016 *unknown*\*unknown* (8)
S-1-5-80-1017 *unknown*\*unknown* (8)
S-1-5-80-1018 *unknown*\*unknown* (8)
S-1-5-80-1019 *unknown*\*unknown* (8)
S-1-5-80-1020 *unknown*\*unknown* (8)
S-1-5-80-1021 *unknown*\*unknown* (8)
S-1-5-80-1022 *unknown*\*unknown* (8)
S-1-5-80-1023 *unknown*\*unknown* (8)
S-1-5-80-1025 *unknown*\*unknown* (8)
S-1-5-80-1026 *unknown*\*unknown* (8)
S-1-5-80-1027 *unknown*\*unknown* (8)
S-1-5-80-1028 *unknown*\*unknown* (8)
S-1-5-80-1029 *unknown*\*unknown* (8)
S-1-5-80-1030 *unknown*\*unknown* (8)
S-1-5-80-1031 *unknown*\*unknown* (8)
S-1-5-80-1032 *unknown*\*unknown* (8)
S-1-5-80-1033 *unknown*\*unknown* (8)
S-1-5-80-1034 *unknown*\*unknown* (8)
S-1-5-80-1035 *unknown*\*unknown* (8)
S-1-5-80-1036 *unknown*\*unknown* (8)
S-1-5-80-1037 *unknown*\*unknown* (8)
S-1-5-80-1038 *unknown*\*unknown* (8)
S-1-5-80-1039 *unknown*\*unknown* (8)
S-1-5-80-1040 *unknown*\*unknown* (8)
S-1-5-80-1041 *unknown*\*unknown* (8)
S-1-5-80-1042 *unknown*\*unknown* (8)
S-1-5-80-1043 *unknown*\*unknown* (8)
S-1-5-80-1044 *unknown*\*unknown* (8)
S-1-5-80-1045 *unknown*\*unknown* (8)
S-1-5-80-1046 *unknown*\*unknown* (8)
S-1-5-80-1047 *unknown*\*unknown* (8)
S-1-5-80-1048 *unknown*\*unknown* (8)
S-1-5-80-1049 *unknown*\*unknown* (8)
S-1-5-80-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-80-3139157870-2983391045-3678747466-658725712 and logon username 'administrator', password 'Iseisebaby!2'
S-1-5-80-3139157870-2983391045-3678747466-658725712-500 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-501 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-502 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-503 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-504 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-505 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-506 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-507 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-508 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-509 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-510 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-511 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-512 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-513 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-514 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-515 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-516 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-517 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-518 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-519 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-520 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-521 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-522 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-523 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-524 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-525 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-526 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-527 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-528 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-529 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-530 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-531 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-532 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-533 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-534 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-535 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-536 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-537 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-538 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-539 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-540 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-541 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-542 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-543 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-544 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-545 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-546 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-547 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-548 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-549 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-550 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1000 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1001 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1002 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1003 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1004 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1005 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1006 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1007 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1008 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1009 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1010 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1011 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1012 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1013 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1014 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1015 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1016 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1017 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1018 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1019 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1020 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1021 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1022 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1023 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1024 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1025 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1026 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1027 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1028 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1029 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1030 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1031 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1032 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1033 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1034 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1035 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1036 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1037 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1038 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1039 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1040 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1041 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1042 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1043 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1044 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1045 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1046 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1047 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1048 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1049 *unknown*\*unknown* (8)
S-1-5-80-3139157870-2983391045-3678747466-658725712-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-21-833310794-1261029646-3490875958 and logon username 'administrator', password 'Iseisebaby!2'
S-1-5-21-833310794-1261029646-3490875958-500 WIN-DUSS7GPO657\Administrator (Local User)
S-1-5-21-833310794-1261029646-3490875958-501 WIN-DUSS7GPO657\Guest (Local User)
S-1-5-21-833310794-1261029646-3490875958-502 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-503 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-504 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-505 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-506 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-507 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-508 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-509 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-510 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-511 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-512 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-513 WIN-DUSS7GPO657\None (Domain Group)
S-1-5-21-833310794-1261029646-3490875958-514 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-515 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-516 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-517 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-518 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-519 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-520 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-521 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-522 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-523 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-524 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-525 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-526 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-527 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-528 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-529 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-530 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-531 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-532 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-533 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-534 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-535 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-537 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-538 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-539 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-540 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-541 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-542 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-543 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-544 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-545 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-546 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-547 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-548 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-549 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-550 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1000 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1001 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1002 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1003 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1004 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1005 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1006 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1007 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1008 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1009 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1010 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1011 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1012 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1013 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1014 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1015 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1016 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1017 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1018 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1019 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1020 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1021 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1022 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1023 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1024 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1025 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1026 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1027 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1028 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1029 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1030 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1031 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1032 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1033 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1034 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1035 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1036 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1037 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1038 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1039 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1040 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1041 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1042 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1043 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1044 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1045 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1046 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1047 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1048 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1049 *unknown*\*unknown* (8)
S-1-5-21-833310794-1261029646-3490875958-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-32 and logon username 'administrator', password 'Iseisebaby!2'
S-1-5-32-500 *unknown*\*unknown* (8)
S-1-5-32-501 *unknown*\*unknown* (8)
S-1-5-32-502 *unknown*\*unknown* (8)
S-1-5-32-503 *unknown*\*unknown* (8)
S-1-5-32-504 *unknown*\*unknown* (8)
S-1-5-32-505 *unknown*\*unknown* (8)
S-1-5-32-506 *unknown*\*unknown* (8)
S-1-5-32-507 *unknown*\*unknown* (8)
S-1-5-32-508 *unknown*\*unknown* (8)
S-1-5-32-509 *unknown*\*unknown* (8)
S-1-5-32-510 *unknown*\*unknown* (8)
S-1-5-32-511 *unknown*\*unknown* (8)
S-1-5-32-512 *unknown*\*unknown* (8)
S-1-5-32-513 *unknown*\*unknown* (8)
S-1-5-32-514 *unknown*\*unknown* (8)
S-1-5-32-515 *unknown*\*unknown* (8)
S-1-5-32-516 *unknown*\*unknown* (8)
S-1-5-32-517 *unknown*\*unknown* (8)
S-1-5-32-518 *unknown*\*unknown* (8)
S-1-5-32-519 *unknown*\*unknown* (8)
S-1-5-32-520 *unknown*\*unknown* (8)
S-1-5-32-521 *unknown*\*unknown* (8)
S-1-5-32-522 *unknown*\*unknown* (8)
S-1-5-32-523 *unknown*\*unknown* (8)
S-1-5-32-524 *unknown*\*unknown* (8)
S-1-5-32-525 *unknown*\*unknown* (8)
S-1-5-32-526 *unknown*\*unknown* (8)
S-1-5-32-527 *unknown*\*unknown* (8)
S-1-5-32-528 *unknown*\*unknown* (8)
S-1-5-32-529 *unknown*\*unknown* (8)
S-1-5-32-530 *unknown*\*unknown* (8)
S-1-5-32-531 *unknown*\*unknown* (8)
S-1-5-32-532 *unknown*\*unknown* (8)
S-1-5-32-533 *unknown*\*unknown* (8)
S-1-5-32-534 *unknown*\*unknown* (8)
S-1-5-32-535 *unknown*\*unknown* (8)
S-1-5-32-536 *unknown*\*unknown* (8)
S-1-5-32-537 *unknown*\*unknown* (8)
S-1-5-32-538 *unknown*\*unknown* (8)
S-1-5-32-539 *unknown*\*unknown* (8)
S-1-5-32-540 *unknown*\*unknown* (8)
S-1-5-32-541 *unknown*\*unknown* (8)
S-1-5-32-542 *unknown*\*unknown* (8)
S-1-5-32-543 *unknown*\*unknown* (8)
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 *unknown*\*unknown* (8)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
S-1-5-32-1000 *unknown*\*unknown* (8)
S-1-5-32-1001 *unknown*\*unknown* (8)
S-1-5-32-1002 *unknown*\*unknown* (8)
S-1-5-32-1003 *unknown*\*unknown* (8)
S-1-5-32-1004 *unknown*\*unknown* (8)
S-1-5-32-1005 *unknown*\*unknown* (8)
S-1-5-32-1006 *unknown*\*unknown* (8)
S-1-5-32-1007 *unknown*\*unknown* (8)
S-1-5-32-1008 *unknown*\*unknown* (8)
S-1-5-32-1009 *unknown*\*unknown* (8)
S-1-5-32-1010 *unknown*\*unknown* (8)
S-1-5-32-1011 *unknown*\*unknown* (8)
S-1-5-32-1012 *unknown*\*unknown* (8)
S-1-5-32-1013 *unknown*\*unknown* (8)
S-1-5-32-1014 *unknown*\*unknown* (8)
S-1-5-32-1015 *unknown*\*unknown* (8)
S-1-5-32-1016 *unknown*\*unknown* (8)
S-1-5-32-1017 *unknown*\*unknown* (8)
S-1-5-32-1018 *unknown*\*unknown* (8)
S-1-5-32-1019 *unknown*\*unknown* (8)
S-1-5-32-1020 *unknown*\*unknown* (8)
S-1-5-32-1021 *unknown*\*unknown* (8)
S-1-5-32-1022 *unknown*\*unknown* (8)
S-1-5-32-1023 *unknown*\*unknown* (8)
S-1-5-32-1024 *unknown*\*unknown* (8)
S-1-5-32-1025 *unknown*\*unknown* (8)
S-1-5-32-1026 *unknown*\*unknown* (8)
S-1-5-32-1027 *unknown*\*unknown* (8)
S-1-5-32-1028 *unknown*\*unknown* (8)
S-1-5-32-1029 *unknown*\*unknown* (8)
S-1-5-32-1030 *unknown*\*unknown* (8)
S-1-5-32-1031 *unknown*\*unknown* (8)
S-1-5-32-1032 *unknown*\*unknown* (8)
S-1-5-32-1033 *unknown*\*unknown* (8)
S-1-5-32-1034 *unknown*\*unknown* (8)
S-1-5-32-1035 *unknown*\*unknown* (8)
S-1-5-32-1036 *unknown*\*unknown* (8)
S-1-5-32-1037 *unknown*\*unknown* (8)
S-1-5-32-1038 *unknown*\*unknown* (8)
S-1-5-32-1039 *unknown*\*unknown* (8)
S-1-5-32-1040 *unknown*\*unknown* (8)
S-1-5-32-1041 *unknown*\*unknown* (8)
S-1-5-32-1042 *unknown*\*unknown* (8)
S-1-5-32-1043 *unknown*\*unknown* (8)
S-1-5-32-1044 *unknown*\*unknown* (8)
S-1-5-32-1045 *unknown*\*unknown* (8)
S-1-5-32-1046 *unknown*\*unknown* (8)
S-1-5-32-1047 *unknown*\*unknown* (8)
S-1-5-32-1048 *unknown*\*unknown* (8)
S-1-5-32-1049 *unknown*\*unknown* (8)
S-1-5-32-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-82-271721585-897601226-2024613209-625570482 and logon username 'administrator', password 'Iseisebaby!2'
S-1-5-82-271721585-897601226-2024613209-625570482-500 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-501 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-502 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-503 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-504 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-505 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-506 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-507 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-508 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-509 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-510 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-511 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-512 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-513 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-514 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-515 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-516 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-517 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-518 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-519 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-520 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-521 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-522 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-523 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-524 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-525 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-526 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-527 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-528 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-529 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-530 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-531 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-532 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-533 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-534 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-535 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-536 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-537 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-538 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-539 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-540 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-541 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-542 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-543 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-544 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-545 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-546 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-547 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-548 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-549 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-550 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1000 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1001 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1002 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1003 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1004 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1005 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1006 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1007 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1009 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1010 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1011 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1012 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1013 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1014 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1015 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1016 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1017 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1018 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1019 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1020 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1021 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1022 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1023 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1024 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1025 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1026 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1027 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1028 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1029 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1030 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1031 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1032 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1033 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1034 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1035 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1036 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1037 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1038 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1039 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1040 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1041 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1042 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1043 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1044 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1045 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1046 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1047 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1048 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1049 *unknown*\*unknown* (8)
S-1-5-82-271721585-897601226-2024613209-625570482-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-82-3876422241-1344743610-1729199087-774402673 and logon username 'administrator', password 'Iseisebaby!2'
S-1-5-82-3876422241-1344743610-1729199087-774402673-500 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-501 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-502 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-503 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-504 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-505 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-506 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-507 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-508 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-509 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-510 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-511 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-512 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-513 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-514 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-515 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-516 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-517 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-518 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-519 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-520 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-521 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-522 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-523 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-524 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-525 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-526 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-527 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-528 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-529 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-530 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-531 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-532 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-533 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-534 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-535 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-536 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-537 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-538 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-539 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-540 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-541 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-542 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-543 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-544 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-545 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-546 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-547 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-548 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-549 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-550 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1000 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1001 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1002 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1003 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1004 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1005 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1006 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1007 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1008 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1009 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1010 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1011 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1012 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1013 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1014 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1015 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1016 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1017 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1018 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1019 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1020 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1021 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1022 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1023 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1024 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1025 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1026 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1027 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1028 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1029 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1030 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1031 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1032 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1033 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1034 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1035 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1036 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1037 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1038 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1039 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1040 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1041 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1042 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1043 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1044 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1045 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1046 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1047 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1048 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1049 *unknown*\*unknown* (8)
S-1-5-82-3876422241-1344743610-1729199087-774402673-1050 *unknown*\*unknown* (8)
[+] Enumerating users using SID S-1-5-90 and logon username 'administrator', password 'Iseisebaby!2'
S-1-5-90-500 *unknown*\*unknown* (8)
S-1-5-90-501 *unknown*\*unknown* (8)
S-1-5-90-502 *unknown*\*unknown* (8)
S-1-5-90-503 *unknown*\*unknown* (8)
S-1-5-90-504 *unknown*\*unknown* (8)
S-1-5-90-505 *unknown*\*unknown* (8)
S-1-5-90-506 *unknown*\*unknown* (8)
S-1-5-90-507 *unknown*\*unknown* (8)
S-1-5-90-508 *unknown*\*unknown* (8)
S-1-5-90-509 *unknown*\*unknown* (8)
S-1-5-90-510 *unknown*\*unknown* (8)
S-1-5-90-511 *unknown*\*unknown* (8)
S-1-5-90-512 *unknown*\*unknown* (8)
S-1-5-90-513 *unknown*\*unknown* (8)
S-1-5-90-514 *unknown*\*unknown* (8)
S-1-5-90-515 *unknown*\*unknown* (8)
S-1-5-90-516 *unknown*\*unknown* (8)
S-1-5-90-517 *unknown*\*unknown* (8)
S-1-5-90-518 *unknown*\*unknown* (8)
S-1-5-90-519 *unknown*\*unknown* (8)
S-1-5-90-520 *unknown*\*unknown* (8)
S-1-5-90-521 *unknown*\*unknown* (8)
S-1-5-90-522 *unknown*\*unknown* (8)
S-1-5-90-523 *unknown*\*unknown* (8)
S-1-5-90-524 *unknown*\*unknown* (8)
S-1-5-90-525 *unknown*\*unknown* (8)
S-1-5-90-526 *unknown*\*unknown* (8)
S-1-5-90-527 *unknown*\*unknown* (8)
S-1-5-90-528 *unknown*\*unknown* (8)
S-1-5-90-529 *unknown*\*unknown* (8)
S-1-5-90-530 *unknown*\*unknown* (8)
S-1-5-90-531 *unknown*\*unknown* (8)
S-1-5-90-532 *unknown*\*unknown* (8)
S-1-5-90-533 *unknown*\*unknown* (8)
S-1-5-90-534 *unknown*\*unknown* (8)
S-1-5-90-535 *unknown*\*unknown* (8)
S-1-5-90-536 *unknown*\*unknown* (8)
S-1-5-90-537 *unknown*\*unknown* (8)
S-1-5-90-538 *unknown*\*unknown* (8)
S-1-5-90-539 *unknown*\*unknown* (8)
S-1-5-90-540 *unknown*\*unknown* (8)
S-1-5-90-541 *unknown*\*unknown* (8)
S-1-5-90-542 *unknown*\*unknown* (8)
S-1-5-90-543 *unknown*\*unknown* (8)
S-1-5-90-544 *unknown*\*unknown* (8)
S-1-5-90-545 *unknown*\*unknown* (8)
S-1-5-90-546 *unknown*\*unknown* (8)
S-1-5-90-547 *unknown*\*unknown* (8)
S-1-5-90-548 *unknown*\*unknown* (8)
S-1-5-90-549 *unknown*\*unknown* (8)
S-1-5-90-550 *unknown*\*unknown* (8)
S-1-5-90-1000 *unknown*\*unknown* (8)
S-1-5-90-1001 *unknown*\*unknown* (8)
S-1-5-90-1002 *unknown*\*unknown* (8)
S-1-5-90-1003 *unknown*\*unknown* (8)
S-1-5-90-1004 *unknown*\*unknown* (8)
S-1-5-90-1005 *unknown*\*unknown* (8)
S-1-5-90-1006 *unknown*\*unknown* (8)
S-1-5-90-1007 *unknown*\*unknown* (8)
S-1-5-90-1008 *unknown*\*unknown* (8)
S-1-5-90-1009 *unknown*\*unknown* (8)
S-1-5-90-1010 *unknown*\*unknown* (8)
S-1-5-90-1011 *unknown*\*unknown* (8)
S-1-5-90-1012 *unknown*\*unknown* (8)
S-1-5-90-1013 *unknown*\*unknown* (8)
S-1-5-90-1014 *unknown*\*unknown* (8)
S-1-5-90-1015 *unknown*\*unknown* (8)
S-1-5-90-1016 *unknown*\*unknown* (8)
S-1-5-90-1017 *unknown*\*unknown* (8)
S-1-5-90-1018 *unknown*\*unknown* (8)
S-1-5-90-1019 *unknown*\*unknown* (8)
S-1-5-90-1020 *unknown*\*unknown* (8)
S-1-5-90-1021 *unknown*\*unknown* (8)
S-1-5-90-1022 *unknown*\*unknown* (8)
S-1-5-90-1023 *unknown*\*unknown* (8)
S-1-5-90-1024 *unknown*\*unknown* (8)
S-1-5-90-1025 *unknown*\*unknown* (8)
S-1-5-90-1026 *unknown*\*unknown* (8)
S-1-5-90-1027 *unknown*\*unknown* (8)
S-1-5-90-1028 *unknown*\*unknown* (8)
S-1-5-90-1029 *unknown*\*unknown* (8)
S-1-5-90-1030 *unknown*\*unknown* (8)
S-1-5-90-1031 *unknown*\*unknown* (8)
S-1-5-90-1032 *unknown*\*unknown* (8)
S-1-5-90-1033 *unknown*\*unknown* (8)
S-1-5-90-1034 *unknown*\*unknown* (8)
S-1-5-90-1035 *unknown*\*unknown* (8)
S-1-5-90-1036 *unknown*\*unknown* (8)
S-1-5-90-1037 *unknown*\*unknown* (8)
S-1-5-90-1038 *unknown*\*unknown* (8)
S-1-5-90-1039 *unknown*\*unknown* (8)
S-1-5-90-1040 *unknown*\*unknown* (8)
S-1-5-90-1041 *unknown*\*unknown* (8)
S-1-5-90-1042 *unknown*\*unknown* (8)
S-1-5-90-1043 *unknown*\*unknown* (8)
S-1-5-90-1044 *unknown*\*unknown* (8)
S-1-5-90-1045 *unknown*\*unknown* (8)
S-1-5-90-1046 *unknown*\*unknown* (8)
S-1-5-90-1047 *unknown*\*unknown* (8)
S-1-5-90-1048 *unknown*\*unknown* (8)
S-1-5-90-1049 *unknown*\*unknown* (8)
S-1-5-90-1050 *unknown*\*unknown* (8)

 ============================================ 
|    Getting printer info for 10.12.2.175    |
 ============================================ 
	flags:[0x800000]
	name:[\\10.12.2.175\Microsoft XPS Document Writer]
	description:[\\10.12.2.175\Microsoft XPS Document Writer,Microsoft XPS Document Writer v4,]
	comment:[]



enum4linux complete on Wed Aug 30 20:42:06 2017

""".format(os_information=OS_INFORMATION, users=USERS, shares=SHARES)

    def setUp(self):
        self.parser = Enum4linuxParser()

    def test_parse_os_information(self):
        result = self.parser.parse_os_information(self.OS_INFORMATION)
        expected = {
            'domain': 'CS',
            'os': 'Windows Server 2012 R2 Standard 9600',
            'server': 'Windows Server 2012 R2 Standard 6.3'
        }
        self.assertEqual(result, expected)

    def test_parse_users(self):
        result = self.parser.parse_users(self.USERS)
        expected = [
            {
                'index': '0xf4d',
                'rid': '0x1f4',
                'acb': '0x00000010',
                'account': 'Administrator',
                'name': None,
                'desc': 'Built-in account for administering the computer/domain'
            },
            {
                'index': '0x101e',
                'rid': '0x451',
                'acb': '0x00000210',
                'account': 'jkowalski',
                'name': 'Jan JK. Kowalski',
                'desc': None
            }
        ]

        self.assertEqual(result, expected)

    def test_parse_shares(self):
        result = self.parser.parse_shares(self.SHARES)
        expected = [
            {
                'name': 'ADMIN$',
                'type': 'Disk',
                'comment': 'Remote Admin'
            },
            {
                'name': 'C$',
                'type': 'Disk',
                'comment': 'Default share'
            },
            {
                'name': 'IPC$',
                'type': 'IPC',
                'comment': 'Remote IPC'
            },
            {
                'name': 'NETLOGON',
                'type': 'Disk',
                'comment': 'Logon server share'
            },
            {
                'name': 'SYSVOL',
                'type': 'Disk',
                'comment': 'Logon server share'
            },
        ]

        self.assertEqual(result, expected)
