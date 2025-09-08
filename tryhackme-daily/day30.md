
````markdown
# ⚡ Race Conditions in Cybersecurity

Race conditions are a common software vulnerability where the **system's behavior depends on the sequence or timing of uncontrollable events**. Attackers exploit them to manipulate execution order, bypass security checks, or gain unauthorized access.

---

## 📌 What is a Race Condition?

A **race condition** occurs when:
- Two or more processes access shared resources concurrently, and  
- The system’s output depends on the **timing of events**.  

This makes the program **unpredictable**, since a tiny difference in execution order can cause security flaws.

> 💡 Example: Two users trying to withdraw money at the same time, resulting in a double withdrawal due to improper synchronization.

---

## 🛠️ Types of Race Conditions

| Type | Description | Example |
|------|-------------|---------|
| **TOCTOU** (Time-of-Check to Time-of-Use) | A gap exists between checking a condition and using the result. | File permission check → attacker swaps file before access. |
| **Signal Handling Races** | Exploiting signals or interrupts that arrive during unsafe states. | Triggering interrupts at specific times. |
| **Thread/Process Synchronization Races** | Unsynchronized shared memory or variable access. | Multi-threaded applications updating the same counter. |
| **Atomicity Violation** | When compound operations are not executed atomically. | `read-modify-write` operations without locks. |
| **Web Application Race** | Exploiting concurrent HTTP requests to bypass logic. | Submitting multiple coupon codes before the system validates them. |

---

## 🚨 Why Are Race Conditions Dangerous?

- 🔓 **Privilege Escalation** – gaining root/admin access.  
- 🛠️ **Bypassing Security Checks** – tricking programs into trusting manipulated data.  
- 💾 **Data Corruption** – inconsistent database or file system states.  
- 💰 **Financial Fraud** – double-spending or duplicate transactions.  
- 🌍 **Web Exploits** – bypassing rate limits, authentication, or inventory systems.  

---

## 💻 Demonstration Examples

### TOCTOU Exploit (Linux - C Code)
```c
// Example: Exploiting a file access race
if (access("secret.txt", R_OK) != -1) {
    // Attacker swaps file before open()
    int fd = open("secret.txt", O_RDONLY);
    read(fd, buffer, sizeof(buffer));
}
````

🔴 Here, the attacker replaces `secret.txt` with a malicious symlink between **access()** and **open()**.

---

### Web Application Race Condition (Curl Example)

Imagine an online shop where you can redeem a coupon once.
An attacker can send **two requests simultaneously**:

```bash
curl -X POST "https://shop.com/redeem?coupon=DISCOUNT50" &
curl -X POST "https://shop.com/redeem?coupon=DISCOUNT50" &
```

⚠️ If the server checks before updating, **both requests succeed**, giving the attacker **double discounts**.

---

## 🧪 Real-World Incidents

* **Stripe (2016)** – Researchers found that making multiple refund requests simultaneously could trigger duplicate refunds.
* **Google Chrome (2019)** – A race condition in the audio component led to a **remote code execution** vulnerability.
* **Tesla Bug Bounty (2020)** – Researchers exploited race conditions in Tesla’s web apps to gain free credits.

---

## 🔍 How to Detect Race Conditions

* **Code Review** – Look for shared resource access without locks.
* **Fuzzing Tools** – Automated testing (e.g., AFL, syzkaller).
* **Thread Sanitizers** – Built-in tools that detect concurrency bugs.
* **Load Testing** – Simulate concurrent requests with tools like `ab` or `wrk`.
* **Manual Testing** – Trigger parallel requests (Burp Suite Intruder, Turbo Intruder).

---

## 🛡️ How to Prevent Race Conditions

✔️ Use **atomic operations** (e.g., `O_CREAT | O_EXCL` with `open()`).
✔️ Apply **file locks** (`flock`, `fcntl`).
✔️ Minimize **time gap** between check and use.
✔️ Prefer **thread-safe libraries**.
✔️ Validate **server-side** instead of client-side only.
✔️ Enforce **principle of least privilege**.
✔️ Use **database transactions** to prevent concurrent logic bypasses.
✔️ Test applications under **concurrent load**.

---

## ⚙️ Useful Tools

| Tool                          | Purpose                                          | Link                                                              |
| ----------------------------- | ------------------------------------------------ | ----------------------------------------------------------------- |
| **strace**                    | Trace system calls & signals                     | [strace](https://strace.io)                                       |
| **syzkaller**                 | Kernel fuzzer for race bugs                      | [syzkaller](https://github.com/google/syzkaller)                  |
| **Valgrind (Helgrind)**       | Detect race conditions in multithreaded programs | [Valgrind](https://valgrind.org)                                  |
| **rr**                        | Record & replay debugging (great for races)      | [rr-project](https://rr-project.org/)                             |
| **AFL (American Fuzzy Lop)**  | Fuzzing tool to detect concurrency bugs          | [AFL](https://lcamtuf.coredump.cx/afl/)                           |
| **Burp Suite Turbo Intruder** | Send concurrent HTTP requests                    | [Turbo Intruder](https://portswigger.net/research/turbo-intruder) |

---

## 📖 Additional Resources

* [OWASP Race Condition Cheat Sheet](https://owasp.org/www-community/attacks/Time_of_check_to_time_of_use)
* [MITRE CWE-362: Race Condition](https://cwe.mitre.org/data/definitions/362.html)
* [Linux Man Pages - flock](https://man7.org/linux/man-pages/man2/flock.2.html)
* [Practical Race Condition Attacks in Web Applications](https://blog.sqreen.com/race-conditions-in-web-applications/)
* [PortSwigger: Race Conditions in Web Apps](https://portswigger.net/web-security/race-conditions)

---

## 📝 Summary

* **Race conditions** happen when execution order matters.
* They can affect **filesystems, databases, web apps, and even hardware**.
* Real-world attacks caused **financial losses, privilege escalation, and data breaches**.
* Prevention requires **secure coding, atomic operations, locking, and concurrency testing**.

---

✨ Stay safe, code securely, and always test for concurrency issues!

```

---

