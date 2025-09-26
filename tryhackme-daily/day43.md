# Windows Privilege Escalation

Learn the fundamentals of Windows privilege escalation techniques. During a penetration test, you will often have access to some Windows hosts with an **unprivileged user**. Unprivileged users have limited access, mostly confined to their own files and folders, and cannot perform administrative tasks on the host. This limits the control you have over your target.

This guide covers fundamental techniques attackers can use to elevate privileges in a Windows environment. Understanding these will let you leverage any initial unprivileged foothold on a host to escalate to an administrator account where possible.

***

## Introduction

During a penetration test, it's common to start with limited access as an unprivileged user on a Windows machine. Such users:

- Only access their own files and folders  
- Cannot execute administrative tasks  
- Are restricted from making system-wide changes  

Privilege escalation techniques help you break these limitations and gain administrative control.

***

## Core Windows Privilege Escalation Techniques

### 1. Harvesting Passwords from Usual Spots

Attackers often look for stored credentials or password remnants in places like:

- **Credential Manager (Vault)**  
- **Registry hives (e.g., SAM database)**  
- **LSASS process memory**  
- **Cached domain credentials**  
- **Configuration files with embedded passwords**  

Tools like Mimikatz can extract passwords, hashes, or Kerberos tickets from memory.

***

### 2. Abusing Service Misconfigurations

Many Windows services run with SYSTEM or Administrator privileges. Misconfigurations can allow privilege escalation by:

- **Unquoted service path:** If the service executable path has spaces and is unquoted, attackers can place a malicious executable in an earlier path segment.  
- **Insecure service permissions:** Non-admin users have modify permissions on a service and can replace its binary or change parameters.  
- **Weak service executable files:** Executables writable by unprivileged users.  

Check the service list using `sc query` and inspect configurations with tools like PowerShell or `accesschk`.

***

### 3. Abusing Dangerous Privileges

Some user privileges can be abused to escalate rights:

- **SeImpersonatePrivilege:** Allows a user to impersonate other users or tokens.  
- **SeAssignPrimaryTokenPrivilege:** Can assign tokens to processes, leading to elevated actions.  
- **SeTakeOwnershipPrivilege:** Allows taking ownership of files and registry keys.  
- **SeDebugPrivilege:** Lets you debug and manipulate processes running as SYSTEM or other users.  

Check user privileges with `whoami /priv` and leverage corresponding exploitation methods.

***

### 4. Abusing Vulnerable Software

Installed software with known vulnerabilities or running services with outdated versions can be exploited for privilege escalation:

- Unpatched system components  
- Vulnerable third-party software (e.g., outdated Adobe, Java, browsers)  
- Misconfigured or automatically running vulnerable scripts or schedulers  

Use vulnerability scanners or manually identify the version and research publicly known exploits.

***

## Tools of the Trade

Here are some common tools to assist with Windows privilege escalation:

| Tool           | Purpose                                  |
|----------------|------------------------------------------|
| **Mimikatz**   | Extract hashes, passwords, and tickets  |
| **PowerUp**    | Automated Windows privilege escalation checks |
| **WinPEAS**    | Enumerates possible privilege escalation vectors |
| **accesschk**  | Checks permissions, service configurations |
| **Sysinternals Suite** | Utilities to check system info and processes |
| **SharpUp**    | C# tool for privilege escalation enumeration |

***

## Summary

Windows privilege escalation is a vital skill during penetration testing to achieve full control over a target system. Focus on:

- Harvesting credentials from memory or common storage locations  
- Identifying and abusing service misconfigurations  
- Leveraging dangerous privileges held by users  
- Exploiting vulnerable installed software  

Use specialized tools to automate enumeration and exploitation where possible.

***  
Keep practicing to sharpen your Windows hacking skills.

***
