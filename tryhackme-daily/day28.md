# 📝 What We Learned – Study & Revision Notes

This post is not about the specific rooms or challenges we solved, but about the **knowledge, topics, and commands** we gained along the way.  
It’s written in a simple way so it can be used for **learning, practicing, or revision**.  

---

## 🔑 Topics Covered (with simple explanations)

### 1. Linux Basics
- Linux is the operating system used in most hacking labs and servers.
- Knowing how to move around the file system, read files, and check permissions is essential.

### 2. File Permissions
- Files in Linux have 3 types of permissions:  
  - **Read (r)** → can view contents of the file  
  - **Write (w)** → can modify or delete the file  
  - **Execute (x)** → can run the file (if it’s a script/program)  
- Permissions apply to:
  - **User** (owner of the file)
  - **Group** (members of a group)
  - **Others** (everyone else)

### 3. Networking
- Computers talk to each other using **IP addresses** (like a home address).
- Communication happens through **ports** (like doors into the system).
- Example:  
  - Web server → Port 80 (HTTP), Port 443 (HTTPS)  
  - SSH → Port 22  

### 4. Enumeration
- Enumeration means **collecting information** about the target.  
- This includes open ports, running services, hidden files, and misconfigurations.  

### 5. Privilege Escalation
- Many times, we start with a **low-privileged user**.  
- The goal is to find ways to **escalate privileges** to become `root` (admin).  
- This usually involves:  
  - Misconfigured permissions  
  - SUID binaries  
  - Weak `sudo` rules  
  - Sensitive files containing passwords  

### 6. Documentation
- Always write down:
  - Commands used  
  - Results/output  
  - Notes on interesting findings  
- This makes troubleshooting and reporting easier later.

---

## 🛠️ Commands with Explanations

### 🔹 Linux Basics
```bash
ls -la        # List all files (including hidden ones) with details
pwd           # Show current directory (where you are)
cd /path      # Change to a different directory
cat file.txt  # Display contents of a file
whoami        # Show current logged-in user
```

🔹 File Permissions
```
chmod 755 file.sh        # Give owner full rights, others can read/execute
chown user:group file.txt # Change ownership of a file
ls -l                    # Check file permissions in detail
```

### Example:
```
-rwxr-xr-- 1 user group 1234 file.sh

rwx → owner can read, write, execute

r-x → group can read and execute

r-- → others can only read
```

### 🔹 Networking

```bash
ifconfig          # Show network interfaces and IP addresses
ping target       # Test if a target is reachable
netstat -tuln     # Show open/listening ports
```

### 🔹 Enumeration
```bash
nmap -sV target            # Scan for open ports and services
nmap -A target             # Aggressive scan (OS + services + scripts)
gobuster dir -u URL -w wordlist.txt   # Brute-force directories on a website
curl -I http://target.com   # Fetch HTTP headers of a website
```

### 🔹 Privilege Escalation
```bash
sudo -l               # Show commands allowed with sudo
find / -perm -4000 2>/dev/null   # Find SUID binaries (may allow privilege escalation)
cat /etc/passwd       # Check user accounts
cat /etc/shadow       # Check password hashes (if accessible)
```

## 📌 Key Lessons
Start with reconnaissance – gather as much information as possible before trying attacks.

Understand what you see – don’t just run tools, analyze outputs.

Misconfigurations matter – small issues like weak permissions can lead to full system compromise.

Take good notes – saves time and helps in reporting.

Practice, practice, practice – using these commands regularly makes them second nature.
