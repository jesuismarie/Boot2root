# Initial Access via GRUB Exploit

1. Start the Machine

Once the machine is powered on (or started from a hypervisor), wait for the boot process to reach the GRUB menu prompt.

2. Interrupt the Boot Process

* Press the **Alt + Shift + ESC** key during the boot process to **interrupt the default boot sequence** and access the **GRUB menu**.

3. List Boot Options

* At the **GRUB menu**, press the **TAB** key. This will list the available boot entries.
* You should see a prompt like:

	```
	boot:
		live
	```

4. Exploit GRUB to Gain Root Shell

* At the `boot:` prompt, type the following command:

	```bash
	live init=/bin/bash
	```
* This command tells the system to boot using the `live` image, but overrides the default init process with a direct call to `/bin/bash`.

5. Root Shell Access

* The system boots directly into a **root shell**, bypassing any login mechanisms.
* You now have **full root privileges** on the machine.

Why This Works

* GRUB allows kernel parameter overrides via the command line.
* By specifying `init=/bin/bash`, the normal init system (which handles user login, services, etc.) is skipped entirely.
* Instead, the kernel launches a bash shell directly as **PID 1**, giving root access without authentication.
