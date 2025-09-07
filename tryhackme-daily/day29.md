
# 🚀**Day 29 – Security Journey**

Today’s focus was on **Web Exploitation** and **Network Attacks** through **TryHackMe** and **Hack The Box**.

---

### TryHackMe – Intro to Cross-Site Scripting (XSS)  
### TryHackMe – Intro to SSRF  
### Hack The Box – Responder Machine

---

#### 🔹 1. Cross-Site Scripting (XSS)  
**📖 Theory**  
XSS is a *client-side* vulnerability where an attacker injects malicious scripts into a web application. These scripts are executed in the victim’s browser, often leading to:  
- Session hijacking (stealing cookies/tokens)  
- Credential theft  
- Defacement or phishing attacks

**Types of XSS:**  
- Reflected XSS – Script comes from the current request (URL/query params).  
- Stored XSS – Script is saved on the server (e.g., in a database) and delivered to multiple users.  
- DOM-based XSS – Injection happens in the client-side JavaScript.

**⚡ Practical Notes**  
Common injection points:  
- Search bars  
- Comment sections  
- URL parameters (`?q=<script>alert(1)</script>`)  

Test Payloads:
```
<script>alert('XSS')</script>  
<img src=x onerror=alert('XSS')>  
"><svg/onload=alert('XSS')>
```

**🔗 Resources**  
- [OWASP XSS Overview]()  
- [PortSwigger XSS Labs]()  
- [TryHackMe – Intro to XSS]()


#### 🔹 2. Server-Side Request Forgery (SSRF)  
**📖 Theory**  
SSRF occurs when an attacker tricks a vulnerable server into making unauthorized requests on its behalf. This often leads to:  
- Accessing internal services (e.g., `http://localhost:8080`)  
- Bypassing firewalls  
- Cloud metadata access (e.g., AWS `http://169.254.169.254/latest/meta-data/`)

**⚡ Practical Notes**  
Common vulnerable features:  
- URL fetchers (image upload & preview, PDF generators)  
- APIs that accept URLs

Payload Examples:  
- `http://127.0.0.1:80`  
- `http://localhost/admin`  
- `http://169.254.169.254/latest/meta-data/`

Bypassing filters:  
- `http://127.0.0.1`  
- `http://[::1]`        # IPv6 localhost  
- `http://2130706433`  # Decimal IP for 127.0.0.1

**🔗 Resources**  
- [OWASP SSRF]()  
- [PortSwigger SSRF Labs]()  
- [TryHackMe – Intro to SSRF]()

---

#### 🔹 3. Hack The Box – Responder  
**📖 Theory**  
The **Responder** tool is used for **LLMNR/NBT-NS/MDNS poisoning**.  
When a machine can’t resolve a hostname, it broadcasts a request.  
Responder listens to these requests and responds with a fake server, tricking the victim into sending authentication data.  
This allows attackers to capture **NTLMv2 hashes** for offline cracking.

**⚡ Commands & Workflow**  
- Start Responder:  
```
responder -I eth0
```  
- Captured Hashes:  
Responder saves them in `/usr/share/responder/logs/`.  
- Crack with hashcat:  
```
hashcat -m 5600 hash.txt rockyou.txt
```  
- Verify Access:  
Once cracked, reuse credentials with `smbclient`, `psexec.py`, or RDP depending on the box.

**🔗 Resources**  
- [HTB Responder Machine]()  
- [Responder GitHub](https://github.com/lgandx/Responder)  
- [HackTricks – Responder]()

---

### ✨ Key Takeaways  
- **XSS** → Always sanitize and encode user input to prevent script injection.  
- **SSRF** → Restrict server-side URL fetchers and validate outbound requests.  
- **Responder** → Disable LLMNR/NBT-NS, enforce strong password policies, and use Kerberos where possible.

---

### 📌 Reflection  
Day 29 taught me how *client-side* (XSS), *server-side* (SSRF), and *network-layer* (Responder) vulnerabilities all connect in the attack chain. Each layer of an application needs to be secured because attackers look for the weakest link.
