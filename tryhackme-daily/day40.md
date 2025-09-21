# 🌐 Performing Post-Exploitation Techniques  
*(Easy & safe guide — footholds, persistence, lateral movement, detection avoidance, enumeration)*

![Learning Badge](https://img.shields.io/badge/Learning-Day39-blue)
![Category](https://img.shields.io/badge/Category-Cybersecurity-green)
![Status](https://img.shields.io/badge/Status-Active-lightgrey)

---

> **Audience:** Beginners, students, and anyone learning cybersecurity.  
> **⚠️ Note:** This guide is **educational only**. No hacking commands are included.

---

## 📖 Index
<details>
<summary>Click to expand</summary>

1. [Quick Overview](#quick-overview)  
2. [Simple Definitions](#simple-definitions)  
3. [Post-Exploitation Flow](#post-exploitation-flow)  
4. [Common Techniques](#common-techniques)  
5. [Tools for Learning & Defense](#tools-for-learning--defense)  
6. [Helpful Commands (Defensive)](#helpful-commands-defensive)  
7. [What to Watch / Log](#what-to-watch--log)  
8. [Alerts / SIEM Examples](#alerts--siem-examples)  
9. [Incident Response Checklist](#incident-response-checklist)  
10. [Study Tips](#study-tips)  
11. [Cheat Sheet](#cheat-sheet)  
12. [Resources & License](#resources--license)

</details>

---

## 📌 Quick Overview
Post-exploitation happens **after an attacker enters a system**.  
Goal for defenders: **detect**, **contain**, **remove** footholds before damage.

---

## 🧩 Simple Definitions
<details>
<summary>Click to expand definitions</summary>

- **Foothold** — Attacker stays on one machine (like a beachhead).  
- **Persistence** — Way for attacker to come back after reboot or reset.  
- **Lateral movement** — Attacker moves to other machines.  
- **Enumeration** — Searching for users, systems, and resources.  
- **Detection avoidance** — Hiding actions, e.g., tampering logs.  
- **Telemetry** — Logs and data to detect suspicious activity.

</details>

---

## 🛠️ Post-Exploitation Flow
<details>
<summary>Click to expand flow</summary>

1. **Consolidate access** → keep a foothold  
2. **Enumerate** → find users, services, targets  
3. **Move laterally** → go to other machines  
4. **Hide & persist** → avoid being detected  
5. **Act / Exfiltrate** → steal or access data (defenders prevent this!)

</details>

---

## ⚡ Common Techniques
<details>
<summary>Click to expand techniques</summary>

- Using stolen or reused passwords  
- Using admin tools like PowerShell, remote management  
- Creating hidden services or scheduled tasks  
- Using built-in tools (no new software)  
- Looking for credentials in memory or files  
- Deleting or stopping logs

</details>

---

## 🛡️ Tools for Learning & Defense
<details>
<summary>Click to expand tools</summary>

- **EDR / XDR** → monitors endpoints continuously  
- **Sysmon** → records Windows process & network events  
- **osquery** → query system data  
- **Velociraptor / GRR** → forensic collection  
- **Wireshark / tcpdump** → network analysis  
- **SIEM** → Splunk, ELK, Microsoft Sentinel  
- **BloodHound (defensive)** → maps AD connections  
- **Honeypots / Canary tokens** → detect reconnaissance

</details>

---

## 💻 Helpful Commands (Defensive)
<details>
<summary>Click to expand commands</summary>

### Linux
```bash
whoami
ps aux | head
ss -tulpen
ls -la /etc/cron*
journalctl -xe
````

### Windows

```powershell
whoami
quser
Get-Process | Select-Object -First 10
Get-Service | Where-Object {$_.Status -eq 'Running'}
Get-ScheduledTask | Select-Object -First 10
Get-EventLog -LogName System -Newest 50
```

> ⚠️ Defensive commands only. No backdoors or credential theft.

</details>

---

## 📊 What to Watch / Log

<details>
<summary>Click to expand detection ideas</summary>

* Login anomalies (new IPs, impossible travel)
* New services / scheduled tasks
* Strange process ancestry
* Admin tools used unexpectedly
* Missing or tampered logs
* Network anomalies (unexpected SMB / remote admin)

</details>

---

## 📈 Alerts / SIEM Examples

<details>
<summary>Click to expand alerts</summary>

* New service created by unknown process → High alert
* User login from unusual IP → Medium/High alert
* Many hosts accessing same server → Possible lateral movement
* Host stopped sending logs → Investigate

</details>

---

## 📝 Incident Response Checklist

<details>
<summary>Click to expand checklist</summary>

1. Detect & verify
2. Isolate affected host(s)
3. Collect logs & volatile data
4. Identify scope (accounts, hosts, services)
5. Contain → block accounts, tighten rules
6. Eradicate → remove persistence, rotate credentials
7. Recover → restore backups
8. Monitor for re-entry
9. Document & improve playbooks

</details>

## 🗂️ Cheat Sheet

<details>
<summary>Click to expand cheat sheet</summary>

* **Foothold** = beachhead
* **Persistence** = way back in
* **Enumeration** = discover users & resources
* **Lateral movement** = spread inside network
* **Detection avoidance** = hide → watch logs & telemetry
* **Tools** = Sysmon, osquery, EDR, SIEM, Wireshark
* **First actions** = isolate → collect → identify → contain → eradicate → recover → monitor

</details>

---

## 🌐 Resources & License

* MITRE ATT\&CK: [https://attack.mitre.org](https://attack.mitre.org)
* Sysmon / EDR vendor docs
* DFIR blogs for practice & exercises

**License:** CC0 — use for learning and defensive purposes only.
