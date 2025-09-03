# 🚀 Day 25 — Defensive Security Tooling (TryHackMe)

Today I completed the **Defensive Security Tooling** module on [TryHackMe](https://tryhackme.com/module/defensive-security-tooling), which introduced me to four powerful tools widely used in malware analysis, digital forensics, and incident response:  
**CyberChef, CAPA, REMnux, and FlareVM**.  

This write-up documents my key learnings so it can also serve as a quick reference for others.

---

## 📂 Module Overview
The module consisted of the following rooms:
1. **CyberChef: The Basics**
2. **CAPA: The Basics**
3. **REMnux: Getting Started**
4. **FlareVM: Arsenal of Tools**

---

## 🍳 CyberChef: The Basics
CyberChef is often called the *Swiss Army Knife for cyber professionals*.  
It allows you to perform a wide variety of operations on data, including:
- Encoding/decoding (Base64, Hex, URL, etc.)
- Data manipulation (extracting strings, parsing, formatting)
- Encryption/decryption (AES, ROT13, XOR, etc.)
- File analysis (hashing, parsing JSON, regex extraction)

🔑 **Key Takeaway**:  
CyberChef is best for quick data transformations without needing to write custom scripts.  
It’s an essential first step in malware triage or log analysis.

📘 [CyberChef Online](https://gchq.github.io/CyberChef/)

---

## 🔎 CAPA: The Basics
[CAPA](https://github.com/mandiant/capa) (by Mandiant) is a tool that automatically identifies capabilities in executable files.  
Instead of manually reversing malware, CAPA analyzes binaries and tells you *what* the file is capable of doing.

### Example Capabilities CAPA Detects:
- Persistence mechanisms (e.g., registry run keys)
- Communication methods (e.g., HTTP, DNS, sockets)
- Credential access techniques
- File system or process manipulation

🔑 **Key Takeaway**:  
CAPA helps quickly answer: *What does this malware do?* — making it a perfect tool for triaging large sets of suspicious binaries.

---

## 🐧 REMnux: Getting Started
[REMnux](https://remnux.org/) is a Linux toolkit specifically designed for reverse engineering and malware analysis.  
It comes with pre-installed tools for:
- **Static analysis** (strings, disassembly, file inspection)
- **Dynamic analysis** (sandboxing, debugging)
- **Memory forensics**
- **Network forensics**

🔑 **Key Takeaway**:  
REMnux is your go-to Linux environment for malware analysis, covering both static and dynamic workflows.

---

## 💻 FlareVM: Arsenal of Tools
[FlareVM](https://github.com/mandiant/flare-vm) is the Windows counterpart to REMnux.  
It transforms a Windows machine into a full malware analysis and reverse engineering environment.

### Some Tools in FlareVM:
- **x64dbg** – Debugger
- **Ghidra/IDA Free** – Disassembly and reverse engineering
- **PEStudio** – Executable analysis
- **Wireshark** – Network analysis
- **YARA** – Malware classification and detection rules

🔑 **Key Takeaway**:  
FlareVM is perfect for analyzing Windows-specific malware and complements REMnux for cross-platform investigations.

---

## ✨ Key Learnings
- **CyberChef** is great for quick transformations and decoding tasks.  
- **CAPA** accelerates malware triage by identifying binary capabilities.  
- **REMnux** provides a robust Linux environment for malware analysis.  
- **FlareVM** offers a Windows-focused analysis toolkit.  

Together, they form a **powerful defensive toolkit** for malware analysts, incident responders, and SOC teams.

---

## 📌 Reflection
Day 25 showed me the importance of having the *right tools for the job*.  
Defensive security tooling is not about one solution but about combining multiple specialized tools to gain visibility, speed, and accuracy in identifying and responding to threats.

✔️ Day 25 complete — onward to the next challenge! 🚀

---

## 🔗 Resources
- [CyberChef](https://gchq.github.io/CyberChef/)  
- [CAPA GitHub](https://github.com/mandiant/capa)  
- [REMnux Documentation](https://remnux.org/docs/)  
- [FlareVM GitHub](https://github.com/mandiant/flare-vm)  

---

### 📝 Author
Part of my **#100DaysOfCyberSecurity Journey**  
GitHub Repo: [learning-in-public](https://github.com/Prxdhxman/learning-in-public/tree/main/tryhackme-daily)

<img width="1920" height="1080" alt="Screenshot at 2025-09-03 20-09-22" src="https://github.com/user-attachments/assets/8004ee90-814f-46f7-af6f-78ff82317aa1" />
