# Vulnerability Capstone

> Final capstone for the Vulnerability Research module — a concise, GitHub-ready learning note with **step-by-step guidance**, practical hints, and defensive takeaways.
> **Goal:** find the vulnerable app, map to a public vulnerability, adapt a PoC, confirm RCE, and collect the flag — all as learning exercises.

---

## TL;DR

Target runs **Fuel CMS ≤ 1.4.1**, which is vulnerable to **CVE-2018-16763** (pre-auth PHP code evaluation via `pages/select` `filter` or preview `data` params). Use reconnaissance → search public PoCs → adapt exploit (often a small parsing tweak) → verify safe commands → capture flag. ([NVD][1])

## Step-by-step guidance

> Each numbered step has a short explanation + concrete commands (safe, non-destructive). **Do not run exploits against systems you do not own or have permission to test.**

### 1) Boot the machine & basic discovery

* Run an `nmap` scan to list open ports and service versions.

```bash
nmap -sC -sV -oA scans/initial <TARGET_IP>
```

* Note open web ports (80/443). If only web is open, focus on HTTP enumeration.

**Why:** knowing services and versions focuses research and reduces blind fuzzing.

### 2) Web enumeration & fingerprinting

* Open `http://<TARGET_IP>` in a browser. Look for:

  * Footers, meta tags, `CHANGELOG`, `README`, `robots.txt`, JS files.
  * App name/version strings in page source or comments.
* Use automated fingerprinting as backup:

```bash
whatweb http://<TARGET_IP>
# or
curl -sS http://<TARGET_IP> | sed -n '1,200p'
```

**Why:** Fuel CMS often exposes version info on the site — that directly maps to public CVEs. ([InfoSec Write-ups][2])

### 3) Vulnerability Research (map product+version → CVE/PoC)

* Search these sources:

  * Exploit-DB (search by product & version).
  * GitHub (PoC repos).
  * NVD / vendor advisories for the CVE description.

```bash
# searchsploit example (offline copies)
searchsploit "Fuel CMS 1.4"
```

* Confirm: Fuel CMS ≤ **1.4.1** → **CVE-2018-16763** (RCE via `pages/select` `filter` or `preview` `data`). ([NVD][1])

**Tip:** PoC entries commonly mention the exact endpoint (e.g., `/fuel/pages/select/`) — use that to craft tests.

### 4) Retrieve a public PoC (read first — don’t blindly run)

* Clone or view PoCs on Exploit-DB / GitHub (several Python/Ruby scripts exist). Example repos/entries exist for this CVE. ([exploit-db.com][3])
* **Read the code**: note the request path, parameters used, response parsing logic, and any assumptions (HTML indices, JSON locations).

**Safety note:** Inspect PoC code locally before running. Replace dangerous payloads with safe commands like `id` or `uname -a` for initial verification.

### 5) Dry run a benign command via the PoC

* Run PoC with a benign command (not a reverse shell yet).

```bash
# conceptual: run PoC to execute 'id' on the target
python3 exploit.py -u http://<TARGET_IP> --cmd 'id'
```

* If the PoC prints command output (e.g., `uid=...`), you have RCE.

**If nothing appears:** proceed to step 6 (debugging).

### 6) Debugging: intercept & adapt

* Intercept the PoC requests with **Burp Suite** (set `--proxy http://127.0.0.1:8080` or similar) and compare the real requests/responses to what the PoC expects.
* Common causes when PoC “almost” works:

  * Response HTML structure differs → the PoC extracts output by splitting HTML and using an index (e.g., `split('<pre>')[1]`). A one-index change can fix it.
  * Extra wrappers or whitespace in the response.
  * Different content-type or status code handling.
* Fixes:

  * Adjust parsing index or regex used to extract command output.
  * URL-encode payloads exactly how the PoC expects (some PoCs use `quote()` or manual encoding).
  * Re-run the PoC after each small tweak until safe output is visible.

**Why:** many community writeups highlight that the exploit itself is correct but minor parsing tweaks are required for different target output. ([System Weakness][4])

### 7) Confirm stable access (then escalate carefully)

* After confirming simple commands, you can:

  * Upload a small webshell (if lab rules permit and only for learning).
  * Or test a bind shell / reverse shell **only if the lab allows interactive connections**.
* Example safe verification: read likely flag locations, e.g.:

```bash
# via PoC-run command
ls -la /home/ubuntu
cat /home/ubuntu/flag.txt
```

**Important:** always follow lab rules — in TryHackMe labs, retrieving the flag proves success; avoid any destructive actions.

### 8) Document & clean up

* Save command outputs showing proof of RCE (screenshots / terminal logs).
* Note exact PoC used and any adaptations (parsing lines changed, encoding adjustments).
* If you created uploaded artifacts in the lab, remove them when done (if the exercise expects it).

---

## Hints & troubleshooting cheat-sheet

* If PoC returns HTML but no command output: inspect where the output is embedded — change the parsing split index or regex. ([exploit-db.com][3])
* If PoC times out or gets errors: confirm the full request URL and required params (`filter` vs `data` endpoints).
* Use `curl -v` to see full response headers and body when debugging.
* Try multiple PoC implementations (Python, Ruby, or community repos) — one may handle response parsing more robustly. ([exploit-db.com][5])

---

## Example commands (conceptual / safe)

```bash
# reconnaissance
nmap -sC -sV -oA scans/initial <TARGET_IP>

# find PoCs locally with searchsploit (if installed)
searchsploit "Fuel CMS 1.4"

# inspect request/response manually
curl -sS "http://<TARGET_IP>/fuel/pages/select/?filter=phpinfo()" | sed -n '1,200p'
```

(Replace `phpinfo()` with safe commands in PoC workflow; do not run destructive payloads.)

---

## References (read these before running anything)

* NVD / CVE-2018-16763 — vulnerability summary. ([NVD][1])
* Exploit-DB PoC entries for Fuel CMS ≤1.4.1 — multiple PoCs available. ([exploit-db.com][6])
* GitHub PoC repositories (example: `p0dalirius` repo for CVE-2018-16763). ([GitHub][7])
* Community walkthroughs & writeups — useful for parsing gotchas and lab-specific hints. ([arth0s' cybersecurity blog][8])

---
