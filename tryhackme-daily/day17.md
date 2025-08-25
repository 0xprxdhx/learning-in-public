# Day 17 – Security Journey
## 🎯 Platforms

TryHackMe: Blue (EternalBlue exploitation)
OverTheWire: Bandit Level 18 → 19

## 🔎 Reconnaissance & Enumeration (TryHackMe – Blue)

Target machine: Windows 7 Professional SP1 (JON-PC)
Environment: Xen HVM domU

Command executed: systeminfo

## Key output (from screenshot):
'''bash
Host Name:                 JON-PC
OS Name:                   Microsoft Windows 7 Professional
OS Version:                6.1.7601 Service Pack 1 Build 7601
System Manufacturer:       Xen
System Model:              HVM domU
Total Physical Memory:     2,048 MB
Hotfix(s):                 2 Hotfix(s) Installed.'''
## 💥 Exploitation (EternalBlue – MS17-010)

### Steps:

Ran EternalBlue exploit with Metasploit

Obtained a shell

Verified NT AUTHORITY\SYSTEM access

## 🔧 Post-Exploitation

### Commands executed to gather system info:

whoami
ipconfig
net user

## 🖥️ Wargames (OverTheWire – Bandit 15 → 28)

### Challenge: auto-logout when connecting to level 19.

Normal login attempt: ssh bandit__@bandit.labs.overthewire.org -p 2220

(Result: auto logout)

Bypass by executing command directly: ssh bandit__@bandit.labs.overthewire.org -p 2220 "cat ~/*.txt"

Output: (password for next level – stored privately)

## ✨ Key Learnings

 Enumeration is king: simple commands like systeminfo, whoami, and net user reveal critical details.

 Creativity matters: executing commands inline with SSH helped bypass the auto-logout.

 Practicing Windows + Linux exploitation in parallel strengthens overall problem-solving ability.
 
<img width="1920" height="1080" alt="Screenshot from 2025-08-25 12-57-52" src="https://github.com/user-attachments/assets/3d8a56d9-4383-4d1a-8272-2f8cba6e3e75" />
<img width="1920" height="1080" alt="Screenshot from 2025-08-25 12-56-54" src="https://github.com/user-attachments/assets/4617f605-bcf6-4bfe-96bf-aed68a416d62" />
<img width="1920" height="1080" alt="Screenshot from 2025-08-25 17-08-28" src="https://github.com/user-attachments/assets/c1766f1d-32c2-4e44-b991-dbbdad10c900" />
<img width="1920" height="1080" alt="Screenshot from 2025-08-25 15-29-56" src="https://github.com/user-attachments/assets/b110d871-1f39-421e-b3b3-948c8ea19701" />

