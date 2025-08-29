# 🚀 Day 20 of 100 Days of Cybersecurity

Today was a mix of **CTF problem-solving** and **enumeration fundamentals** with TryHackMe.

---

## 🎯 CTF Practice (picoCTF & General Skills)

- **General Skills**
  - Decoding with `base64` and ROT13 (`tr 'A-Za-z' 'N-ZA-Mn-za-m'`)
  - Searching text with `grep`, `awk`, and `strings`
  - Practiced regex for pattern matching

- **Forensics**
  - Analyzed `.pcap` files using **Wireshark**
  - Extracted traffic details and hidden data

- **Web Exploitation**
  - Tested hidden parameters with `curl` and `wget`
  - Script manipulation for input discovery

- **Privilege Escalation**
  - Practiced with **SUID binaries**
  - Common commands:
    ```bash
    find / -perm -4000 -type f 2>/dev/null
    ltrace ./binary
    strings ./binary
    ```

---

## 🛡️ TryHackMe – Gobuster the Basics

Practiced **directory brute-forcing** and web enumeration:

- Example commands:
  ```bash
  gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
  gobuster dir -u http://target.com -w /usr/share/wordlists/rockyou.txt -x php,html,txt

## 🔑 Key Takeaways

- Enumeration is the foundation of web exploitation  
- Wordlist choice (`/usr/share/wordlists/`) significantly affects results  
- Small discoveries often open the entire attack path  

---

## 🔍 Burp Suite Exploration (First Steps)

- Intercepted and modified HTTP requests with **Proxy**  
- Replayed variations using **Repeater**  
- Started mapping applications to uncover hidden parameters  

---

## ✨ Key Learnings

- Enumeration is not optional — it’s the backbone of CTFs & pentesting  
- Privilege escalation requires patience and systematic testing  
- **Gobuster** and **Burp Suite** complement each other in web security testing  

---

## 📌 Reflection

Day 20 connected **enumeration (Gobuster, regex, command-line)** with **privilege escalation (SUID binaries)** and **web exploitation (Burp Suite)**.  
The jump from “easy” to “medium” challenges is about combining multiple skills and persisting past dead ends.  
<img width="1920" height="1080" alt="Screenshot at 2025-08-29 21-49-07" src="https://github.com/user-attachments/assets/5eb4d78d-bfcb-4d73-b45b-540a358c8ccb" />

<img width="1920" height="1080" alt="Screenshot at 2025-08-29 22-07-28" src="https://github.com/user-attachments/assets/a04f2c6c-3941-48dc-89e1-593f004ad135" />

<img width="1920" height="1080" alt="Screenshot at 2025-08-29 21-50-59" src="https://github.com/user-attachments/assets/5b144dd5-ad20-4d7a-9484-8fcd8765feaf" />



✔️ **Day 20 complete — step by step leveling up!**
