# 🚀 Security Journey — Day 18
## 🔎 TryHackMe Rooms
### 1. Web Application Basics
HTTP Methods:
```
GET → retrieve data
POST → send data to server
PUT → update resource
DELETE → remove resource
```

Response Codes:

```
200 OK → success
301/302 → redirects
401 Unauthorized / 403 Forbidden
500 Internal Server Error
```

Headers:

```
Host → defines target domain
User-Agent → identifies client/browser
Cookie → maintains sessions
Referer → shows the origin of request
```

🛠️ Tools/Commands:

```
curl -v http://example.com → view request/response details
wget --header "User-Agent: custom" → send requests with modified headers
```

### 2. JavaScript Essentials

Core Concepts:

Runs client-side in browsers → affects DOM (Document Object Model)
Can be manipulated to bypass client-side validation

Security Concerns:

Input validation in JS is not enough — must validate on server
eval() usage can lead to code injection

🛠️ Commands/Tricks:

Open DevTools Console → run

```
document.cookie        // view cookies
document.forms[0]      // inspect form data
localStorage           // check browser storage
```

Edit requests with browser DevTools → change form values before submission

### 3. SQL Fundamentals

Basic Commands:

```
SELECT * FROM users;
SELECT username, email FROM users WHERE id=1;
INSERT INTO users (name, role) VALUES ('admin', 'super');
UPDATE users SET role='guest' WHERE id=2;
DELETE FROM users WHERE id=3;
```


Key Knowledge:

Databases store user credentials, sessions, logs
SQL Injection happens when input is unsanitized

🛠️ Testing Commands:

Input: ' OR '1'='1 → bypass authentication (classic SQLi)
Input: admin' -- → comment out password check

### 🐧 OverTheWire Bandit Progress

Levels 19 → 22 Highlights

Level 19: Learned how to use setuid binaries to execute commands as another user

```
./bandit20-do cat /etc/bandit_pass/bandit20
```

Level 20: Practiced networking with nc

```
echo "<password>" | nc -l -p 1234
```


Level 21: Dealt with cron jobs by inspecting /etc/cron.d/

```
cat /etc/cron.d/*
```


Level 22: Read scripts in ```  /usr/bin/  ```to discover automated tasks and extract credentials

### ✨ Key Takeaways

HTTP: Knowing methods, codes, and headers is essential for understanding web traffic
JavaScript: Client-side code can be bypassed — validation must be server-side
SQL: Small query mistakes → big vulnerabilities
Linux (Bandit): Privilege escalation often hides in plain sight (setuid, cron jobs, networking tricks)

### ✔️ Day 18 Complete — Fundamentals + Linux wargames make the perfect combo for building strong offensive security skills.

<img width="1920" height="1080" alt="Screenshot from 2025-08-26 22-03-57" src="https://github.com/user-attachments/assets/eb2e19f9-734d-4a05-b725-b3ae217917ee" />
<img width="1920" height="1080" alt="Screenshot from 2025-08-26 19-35-14" src="https://github.com/user-attachments/assets/c1323648-8d6b-4752-9611-295f41574908" />
<img width="1920" height="1080" alt="Screenshot from 2025-08-26 17-29-40" src="https://github.com/user-attachments/assets/c75bc4e1-0cbb-475b-b56e-608df723cf5f" />
<img width="1920" height="1080" alt="Screenshot from 2025-08-26 15-52-44" src="https://github.com/user-attachments/assets/ad57314d-7e7e-48b2-ac42-9a1418bbd70e" />

