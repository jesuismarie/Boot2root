# Boot2Root

## Project Description

**Boot2Root** is a hands-on cybersecurity challenge designed to simulate real-world penetration testing and privilege escalation. Your objective is to gain full root access on the target system by leveraging discovered vulnerabilities — from initial reconnaissance through to root exploitation.

Each challenge mirrors a vulnerable server environment and provides an opportunity to sharpen your offensive security skills.

This repository includes:

* Full walkthroughs for each vulnerable machine
* Technical notes on vulnerabilities, tools, and techniques
* Relevant external references and learning resources

## Setup Instructions

To begin your Boot2Root challenge, download the designated vulnerable machine image (e.g., from VulnHub or Offensive Security) and run it inside a virtual environment.

### Requirements

* A **64-bit host operating system**
* A **virtualization platform** (e.g., VirtualBox, VMware, QEMU)
* The Boot2Root **VM image**
* Ensure both attacker and target machines are on the **same internal network**

> Use tools like `netdiscover`, `nmap`, or `arp-scan` to identify the VM's IP address after boot.

---

## Challenge Rules & Integrity

To maintain the integrity of this Boot2Root challenge, please adhere to the following strict guidelines:

* **Do not modify or tamper with the ISO** file in any way.
* **Creating altered versions** of the ISO or reverse-engineering it directly is **strictly forbidden**.
* The focus is on **exploiting the server**, not manipulating the file system, bootloader (e.g., GRUB), or VM infrastructure.
* Any approach involving tricks like ISO exploitation, direct kernel parameter tampering, or GRUB-based bypasses will be considered **cheating** and disqualified.

---

## Mandatory Objective

To validate the **mandatory requirement**, you **must obtain root access** on the server using **two distinct exploitation methods**.

For each method:

* Provide a **complete, step-by-step write-up**
* Clearly document the **exploit path**, commands used, and **technical reasoning**
* Screenshots, logs, and explanations are highly encouraged

*Your write-up must demonstrate that root access was achieved by exploiting actual services, applications, or configurations on the server — not by bypassing security mechanisms outside of the operating system (e.g., bootloader hacks).*

---

## Bonus Objectives

The system may contain **additional vulnerabilities** that allow for **alternative root access paths**.

For each **new and valid method** you discover:

* Submit a complete and functional write-up
* Earn **+1 or +2 bonus points (out of 5 total)** based on originality and depth

> Think creatively — there is more than one way to become root.

---

## Repository Structure

```ini
.
├── bonus/
│   ├── writeup3
│   ├── writeup4
│   ├── writeup5
│   └── ...
├── scripts/
│   ├── exploit.sh
│   └── ...
├── writeup1
└── writeup2
```

---

## Completion Criteria

A level is considered **complete** when:

* Root/system access is successfully obtained
* The full attack chain is documented
* Steps are **logical, reproducible, and clearly explained**
* At least **two distinct root access methods** are submitted

---

## Contact

Have questions or need help with the VM image?

📧 **[mari.nazaryan7173@gmail.com](mailto:mari.nazaryan7173@gmail.com)**

---

Happy hacking, and remember:

> *Hack the box — not the planet.* 🐚
