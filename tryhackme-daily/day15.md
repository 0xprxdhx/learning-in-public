# 🚀 Day 15 — TryHackMe EternalBlue (MS17-010) & RDP Access

Today’s focus was exploiting a Windows 7 machine using the **EternalBlue (MS17-010)** vulnerability, gaining a shell, and converting it into full **RDP access**.

---

## 🔎 Reconnaissance (Nmap)

- **Open ports:** 135, 139, 445, 3389  
- **OS:** Windows 7 Professional SP1 (x64)  
- **Hostname:** `JON-PC`  
- **Vulnerability check:** `smb-vuln-ms17-010` → **VULNERABLE**

This confirmed that the target could be exploited with EternalBlue.

---

## 💥 Exploitation (Metasploit)

- Ran EternalBlue exploit  
- Got a **Meterpreter** session  
- Privilege check: `NT AUTHORITY\SYSTEM` → full system-level access

---

## 🔧 Post-Exploitation

- Enabled **RDP**  
- Created a new user: `hacker / Passw0rd!`  
- Added the new user to the **Administrators** group

---

## 🖥️ Persistence & Access

- Connected via **rdesktop** using the new user credentials  
- Successfully logged in through **RDP**  
- Moved from just a shell → to full **graphical desktop access**

---

## ✨ Key Learnings

- **Enumeration is crucial** before exploiting  
- **EternalBlue → Meterpreter → SYSTEM access → RDP** is a full exploitation chain  
- **Post-exploitation persistence** (e.g., enabling RDP, creating users) enables long-term access

---

## 📌 Reflection

This exercise helped me understand the importance of post-exploitation and persistence.  
For the first time, I completed a realistic attack chain: **Recon → Exploit → Shell → Persistence → RDP**.

---

**Day 15 complete** ✔️ Step by step, I’m strengthening my foundation in exploitation and post-exploitation.

<img width="1920" height="1080" alt="Screenshot from 2025-08-23 19-26-30" src="https://github.com/user-attachments/assets/ccfade3b-fd27-4f00-b9ff-59a49b2617ca" />
