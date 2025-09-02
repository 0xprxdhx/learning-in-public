# 🚀 Day 24 of My Security Journey

## 🛡️ Security Solutions – Defensive Fundamentals

Today’s focus was on **core defensive security solutions**: Firewalls, IDS, Vulnerability Scanners, and SIEM.  
These are essential for understanding how organizations protect their digital infrastructure — and equally important when learning how attackers try to evade or bypass them.

---

## 📖 Key Topics Covered

### 🔹 Security Information and Event Management (SIEM)
- **What it does:** Centralizes logs from across systems and correlates events to detect threats.  
- **Why it matters:** Helps SOC teams see the bigger picture, detect anomalies, and respond quickly.  
- **Offensive relevance:** Attackers may try **log tampering**, **time-stomping**, or **log evasion** to avoid detection.

---

### 🔹 Firewall Fundamentals
- **What it does:** Controls inbound and outbound traffic based on predefined rules.  
- **Hands-on:** Explored Windows and Linux built-in firewalls.  
- **Offensive relevance:** Pentesters/testers must learn to:
  - Identify open ports/services.
  - Use tunneling or port-knocking to bypass restrictions.
  - Exploit misconfigurations (e.g., overly permissive rules).

---

### 🔹 Intrusion Detection Systems (IDS)
- **What it does:** Detects malicious traffic patterns (e.g., Snort).  
- **How it works:** Signature-based or anomaly-based detection.  
- **Offensive relevance:** Red teamers test IDS evasion by:
  - Fragmenting payloads.
  - Encoding/obfuscating malicious traffic.
  - Using “low and slow” attack techniques to stay under thresholds.

---

### 🔹 Vulnerability Scanners
- **What it does:** Automatically identifies known vulnerabilities (e.g., outdated software, weak configs).  
- **Why important:** Provides a roadmap for defenders to patch weaknesses.  
- **Offensive relevance:** Attackers often run similar scans (e.g., Nmap + NSE scripts, Nessus alternatives) to map targets before exploitation.

---

## ✨ Key Learnings
- SIEM = centralized visibility; attackers will try to avoid or poison the data.  
- Firewalls = first line of defense; but misconfigurations = attacker’s entry point.  
- IDS = watchtower of the network; evasion is a critical offensive skill.  
- Vulnerability scanners = defenders’ patch guide, attackers’ target map.  

---

## 📌 Reflection
Day 24 highlighted that **defense and offense are two sides of the same coin**.  
- As a defender → these tools protect the enterprise.  
- As an attacker/pentester → knowing how they work helps understand how to **evade, bypass, and exploit gaps**.  

✔️ **Day 24 complete — Security Solutions mastered for both defense and offense.**

---

### 🔖 Tags
`#CyberSecurity` `#DefensiveSecurity` `#OffensiveSecurity` `#SIEM` `#Firewall` `#IDS` `#VulnerabilityManagement` `#SecurityJourney`
<img width="1920" height="1080" alt="Screenshot at 2025-09-02 23-29-06" src="https://github.com/user-attachments/assets/d8e84f4e-70f2-4fe9-99ed-bd4ff72cd22f" />
<img width="1920" height="1080" alt="Screenshot at 2025-09-02 21-11-58" src="https://github.com/user-attachments/assets/6db1f45a-c496-4928-bbe1-e9aaaaceda7a" />
<img width="1920" height="1080" alt="Screenshot at 2025-09-02 19-42-27" src="https://github.com/user-attachments/assets/203fcf70-213d-49be-8a34-4b5a1fd44eb1" />
<img width="1920" height="1080" alt="Screenshot at 2025-09-02 12-59-19" src="https://github.com/user-attachments/assets/da941104-7a1b-4f34-ae0d-7a99a154a475" />
<img width="1920" height="1080" alt="Screenshot at 2025-09-02 10-41-57" src="https://github.com/user-attachments/assets/7ecfdc9d-5158-46e0-9ee1-fc4c28a561f4" />
