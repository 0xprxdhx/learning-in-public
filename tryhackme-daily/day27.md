# RECONNAISSANCE in Penetration Testing – The First Step to Ethical Hacking

Reconnaissance (or recon) is the foundation of every penetration test. It’s about gathering information on a target before exploitation, helping you understand the attack surface, vulnerabilities, and potential entry points. Mastering recon separates a competent ethical hacker from someone blindly trying exploits.

---

## Path Overview

Recon is typically split into two types:

### Passive Recon
Collects information without directly interacting with the target.  

**Examples:** WHOIS lookups, DNS enumeration, social media intelligence, public breach databases.  

**Tools & Techniques:**
- `whois <domain>` → domain ownership details  
- `nslookup <domain>` → DNS info  
- `theHarvester` → email addresses, subdomains  
- Google dorking → sensitive information discovery  

### Active Recon
Directly interacts with the target to discover services and vulnerabilities.  

**Examples:** ping sweeps, port scanning, banner grabbing, network mapping.  

**Tools & Techniques:**
- `Nmap` → port scanning, service detection  
- `Netcat` → banner grabbing, simple connections  
- `Nikto` / `DirBuster` / `Gobuster` → web directory discovery  
- `Shodan` → exposed devices and services  

---

## Essential Recon Tools

### Nmap – Network Mapper
Discover live hosts, open ports, and services.  

**Commands:**
```bash
# Quick scan  
nmap -sV <target_ip>

# Aggressive scan with OS & service detection  
nmap -A <target_ip>

# Scan specific ports  
nmap -p 21,22,80,443 <target_ip>
```

### theHarvester – OSINT Gathering
Harvest subdomains, emails, IP ranges, and cloud data.  

**Command:**
```bash
theHarvester -d <target.com> -b google
```

### DNS Enumeration Tools
Use `dig`, `nslookup`, or `host` to discover DNS records.  

**Example:**  
```bash
dig @8.8.8.8 <target.com> ANY
```

### Web Recon Tools
- `Nikto` → web server scanning for known vulnerabilities  
- `Gobuster` / `Dirb` → directory & file brute-forcing  
- **Manual checks** → Inspect responses, cookies, and parameters using browser dev tools  

---

## Key Recon Concepts
- **OSINT is powerful** – Public information can reveal emails, subdomains, technology stack, and even employee details.  
- **Enumeration first, exploitation later** – Accurate recon reduces trial-and-error exploits.  
- **Passive vs Active trade-offs** – Passive is stealthy; active is faster but detectable.  
- **Web recon matters** – Many vulnerabilities appear in unpatched web apps or exposed endpoints.  
- **Document everything** – Every finding is a potential pivot point or privilege escalation vector.  

---

## Reflection
Recon is more than scanning — it’s strategic observation. By combining passive and active methods, ethical hackers map targets before launching any attack, improving efficiency and reducing noise.  

Mastering recon builds a mental model of the target, which guides exploitation, post-exploitation, and reporting.  

**In short: Good recon = half the pentest done.**  

Reconnaissance complete — next stop: **Scanning & Enumeration!**

---

## Resources
- Nmap Official Documentation: https://nmap.org/book/man.html  
- theHarvester GitHub: https://github.com/laramies/theHarvester  
- OWASP Recon Guide: https://owasp.org/www-project-web-security-testing-guide/  
- Shodan Search Engine: https://www.shodan.io/  

---

## Author
Part of my **#100DaysOfCyberSecurity** Journey  
GitHub Repo: https://github.com/Prxdhxman/learning-in-public
