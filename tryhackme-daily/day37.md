```markdown
# 🔐 **Vulnerabilities 101** 

> A clean, structured, and practical guide to understanding and working with **vulnerabilities** in penetration testing.  
> Inspired by the [TryHackMe — Vulnerabilities 101](https://tryhackme.com/r/room/vulnerabilities101) room

---

## 📖 Table of Contents
1. [What is a Vulnerability?](#-what-is-a-vulnerability)
2. [Types of Vulnerabilities](#-types-of-vulnerabilities)
3. [Scoring & Prioritization](#-scoring--prioritization)
4. [Vulnerability Databases](#-vulnerability-databases)
5. [Essential Tools](#-essential-tools)
6. [Sample Penetration Testing Workflow](#-sample-penetration-testing-workflow)
7. [Cheat Sheet Commands](#-cheat-sheet-commands)
8. [Further Resources](#-further-resources)

---

## 📌 What is a Vulnerability?
A **vulnerability** is a weakness in a system, network, or application that can be exploited to compromise **confidentiality, integrity, or availability (CIA triad)**.

**Formal definitions:**
- **ISO 27005**: “A weakness of an asset or group of assets that can be exploited by one or more threats.”
- **NIST**: “A flaw or weakness in system security procedures, design, implementation, or internal controls.”

---

## 🧩 Types of Vulnerabilities
Vulnerabilities can occur in different layers:

- **Design flaws** → insecure architecture, weak encryption, bad logic.  
- **Implementation flaws** → buffer overflows, SQL injection, XSS.  
- **Configuration issues** → default creds, open ports, weak permissions.  
- **Human factors** → phishing, weak passwords, social engineering.  

---

## 📊 Scoring & Prioritization
How do we measure and prioritize vulnerabilities?

- **CVSS (Common Vulnerability Scoring System)**  
  - Scores 0.0 – 10.0 (Low → Critical).  
  - [CVSS Calculator](https://www.first.org/cvss/calculator/3.1).  

- **VPR (Vulnerability Priority Rating)**  
  - Context-based (threat intel, exploit availability, business context).  

- **Risk equation:**  
```

Risk = Likelihood × Impact

````

---

## 🌐 Vulnerability Databases
Places to research vulnerabilities and public exploits:

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)  
- [CVE Details](https://www.cvedetails.com/)  
- [Exploit-DB](https://www.exploit-db.com/)  
- [Rapid7 Vulnerability DB](https://www.rapid7.com/db/)  
- [Metasploit Modules Search](https://www.rapid7.com/db/modules/)  
- [Packet Storm](https://packetstormsecurity.com/)  
- [0day.today](https://0day.today/)  

---

## 🛠 Essential Tools
Tools penetration testers use for vulnerability discovery & exploitation:

- **Scanning & Enumeration**  
- `nmap` — port scanning & version detection  
- `nikto` — web server scanning  
- `dirsearch` / `gobuster` — directory & file brute forcing  

- **Vulnerability Scanners**  
- `OpenVAS` / `Greenbone`  
- `Nessus`  
- `Qualys`  

- **Exploit Tools**  
- `searchsploit` — local exploit search (Exploit-DB)  
- `msfconsole` — Metasploit Framework  

- **Post-Exploitation / Analysis**  
- `BloodHound` (AD attacks)  
- `Responder` (network poisoning)  
- `Burp Suite` (web app testing)  

---

## 🧭 Sample Penetration Testing Workflow
A simple, structured approach:

### 1️⃣ Recon & Scanning
```bash
# Discover live hosts
nmap -sn 192.168.1.0/24

# Service & version detection
nmap -sV -sC -p- 192.168.1.10
````

### 2️⃣ Enumeration

* Identify services (HTTP, FTP, SMB, SSH, databases).
* Grab banners and version numbers.
* Enumerate directories (for web apps):

  ```bash
  gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  ```

### 3️⃣ Research

* Look up versions in **Exploit-DB** or **CVE Details**.
* Check for misconfigurations, weak defaults.

### 4️⃣ Exploitation

* Use `searchsploit` to find PoCs:

  ```bash
  searchsploit apache 2.4.49
  ```
* Import into Metasploit or use manual exploit code.

### 5️⃣ Post-Exploitation

* Privilege escalation (Linux/Windows).
* Data exfiltration / persistence.
* Cleanup (ethical testing requires no lasting damage).

---

## ⚡ Cheat Sheet Commands

```bash
# Nmap: fast scan
nmap -T4 -F <target>

# Nmap: full port + service + OS detection
nmap -A -p- <target>

# Nikto: basic web scan
nikto -h http://target.com

# Searchsploit: find public exploits
searchsploit <service> <version>

# Metasploit: start console
msfconsole
```

---

## 📚 Further Resources

* [OWASP Top 10](https://owasp.org/www-project-top-ten/)
* [MITRE ATT\&CK](https://attack.mitre.org/)
* [HackTricks](https://book.hacktricks.xyz/) — a pentester’s bible
* [GTFOBins](https://gtfobins.github.io/) — Linux privilege escalation
* [LOLBAS](https://lolbas-project.github.io/) — Windows privilege escalation

---

✨ *“Exploitation is the art of turning vulnerabilities into opportunities.”*

```
