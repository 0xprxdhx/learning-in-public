# Reporting and Communication 📝🔐

Module 9 focuses on creating professional penetration-testing reports, analyzing findings and recommending remediation, communicating effectively during an engagement, and managing post-report delivery activities. ([netacad.com][1])

---

## Table of contents

1. [Learning objectives (quick)](#learning-objectives-quick)
2. [Why reporting matters](#why-reporting-matters)
3. [Core concepts — broken down](#core-concepts---broken-down)
4. [Practical tips & writing best practices](#practical-tips--writing-best-practices)
5. [Ready-to-use Markdown pentest report template](#ready-to-use-markdown-pentest-report-template)
6. [Quick checklist](#quick-checklist)
7. [Mini exercises / practice lab ideas](#mini-exercises--practice-lab-ideas)
8. [Key resources & further reading (official + practical)](#key-resources--further-reading-official--practical)

---

## Learning objectives (quick)

* Describe the **major components** of a written pentest report. ([netacad.com][1])
* Recommend **appropriate remediation** based on pentest findings. ([netacad.com][1])
* Explain the **importance of communication** during the pentesting process (stakeholders, cadence, non-technical summaries). ([netacad.com][1])
* Understand **post-report delivery activities** (debriefs, retests, evidence handoff, engagement closure). ([netacad.com][1])

---

## Why reporting matters

You can find bugs and exploits — but if you **cannot explain** them clearly to the people who can fix them, your work has little business value. A good report translates technical evidence into prioritized, actionable steps for engineering, security operations, and management. This module trains you to bridge the technical → non-technical gap and close the loop on engagements. ([Cisco Blogs][2])

---

## Core concepts — broken down

### 1) Report structure (the golden sections)

A standard pentest report should include:

* **Title & metadata** — engagement name, date, author, scope summary.
* **Executive summary** — one-page, non-technical: scope, high-level risk posture, top 3 findings, remediation priorities.
* **Scope & objectives** — what was tested, exclusions, rules of engagement.
* **Methodology** — tools, techniques, test types (black/gray/white box), time window, authentication used.
* **Findings (detailed)** — each finding as a repeatable block: Title → Description → Evidence (screenshots, POC) → Impact → Likelihood/Severity → CVE/CVSS (if applicable) → Remediation recommendation.
* **Risk prioritization** — mapping severity to business impact and recommended timeline.
* **Appendix & raw evidence** — logs, full command output, PoC code (safeguarded).

> These components align directly with the Module 9 learning outcomes. ([netacad.com][1])

---

### 2) Prioritization: CVSS & CVE (use standards)

To standardize severity and make prioritization defensible, use industry standards:

* **CVE** (Common Vulnerabilities and Exposures) — canonical identifier for public vulnerabilities. Use CVE IDs when available so teams can lookup vendor fixes and advisories. ([cve.org][3])
* **CVSS** (Common Vulnerability Scoring System) — numeric/severity score for vulnerability impact and exploitability; use it to justify remediation priority and timelines. Use the official CVSS calculator/spec when assigning scores. ([first.org][4])

**Practice note:** When a finding is not a public vulnerability (no CVE), document your rationale, and — if useful — map its impact to the CVSS metric categories when recommending priority.

---

### 3) Communication: tailoring your message

* **Audience segmentation:** Executive (risk & timeline), Engineering (technical fix steps), Security Ops (detection & monitoring), Legal/Compliance (disclosure timeline).
* **Tone & language:** Executive summary → plain language & business impact; technical findings → precise, reproducible steps.
* **Cadence:** Share interim, high-impact findings immediately (responsible disclosure style), reserve full report for agreed delivery. ([netacad.com][1])

---

### 4) Post-report delivery activities

* **Debrief / walk-throughs** with stakeholders (Q\&A + remediation handover).
* **Remediation verification** (retest or verify fixes).
* **Handoff artifacts** (PoC code, evidence, screenshots) under agreed rules.
* **Closeout & lessons learned**: what improved in scanning/detection? What repeatable fixes are required? ([netacad.com][1])

---

## Practical tips & writing best practices

* **Start with the executive summary** — write this last, but place it first in the report. Make it one page max.
* **Use the “finding block” template** (Title → Severity → CVE/CVSS → Description → Steps to reproduce → Evidence → Remediation → Notes). Keep each block consistent.
* **Screenshots + commands + timestamps**: always include reproducible evidence.
* **Remediation recommendations: SMART** — Specific, Measurable, Achievable, Relevant, Time-bound. E.g., *“Apply vendor patch X.Y by 2025-MM-DD; if patch unavailable, restrict service to 10.0.0.0/24 and add WAF rule #42.”*
* **Prioritize quick wins** for immediate risk reduction (e.g., turn off unnecessary services, apply patches, rotate credentials).
* **Avoid blame** in wording — focus on facts and remediation. Use “we recommend” language.
* **Keep sensitive content protected** — redact credentials and production data in shared PDFs unless explicitly allowed.

---

## Ready-to-use Markdown pentest report template

> Copy this into `REPORT.md`, fill placeholders, and iterate.

```markdown
# Penetration Test Report — <ENGAGEMENT NAME>

**Date:** YYYY-MM-DD  
**Authors:** Name(s)  
**Scope:** (brief)  
**Engagement type:** (blackbox / graybox / whitebox)

---

## Executive Summary
- Scope: ...
- Top 3 findings: 1) ... — High, 2) ... — Medium, 3) ... — Low
- Business impact summary & recommended timelines.

---

## Scope & Objectives
- Target assets: ...
- In-scope: ...
- Out-of-scope: ...
- Rules of engagement: ...

---

## Methodology
- Tools used: Nmap, Burp, Nikto, Nessus, custom scripts
- Test windows: ...
- Authenticated? (Yes/No) — credentials used (if any)

---

## Findings
### Finding 1 — <Short Title>
- **Severity:** High  
- **CVSS:** 9.1 (Base) — *[calculator]*  
- **CVE:** CVE-YYYY-NNNN (if any)  
- **Description:** ...
- **Steps to reproduce:** 1) ... 2) ...
- **Evidence:** (screenshot links, pcap, logs)
- **Remediation:** (clear, stepwise)
- **Notes / mitigation timeline:** (e.g., patch within 7 days)

---

### Finding 2 — <Short Title>
*(repeat format)*

---

## Risk Prioritization & Recommendation Roadmap
| Priority | Finding | Action | ETA |
|---:|---|---|---|
| 1 (Critical) | Finding 1 | Apply patch X.Y | 7 days |
| 2 (High) | Finding 2 | Disable service Z | 14 days |

---

## Appendix
- Full command output
- Raw PoC code (in a secure repo)
- Tool scan configs
```
---

## Recommended tools & templates

* **Authoring:** Markdown (GitHub), Google Docs / Confluence (for collaborative edits).
* **Evidence & PoC:** Screenshots, recorded terminal session, pcap files in a secured artifact store.
* **Prioritization:** FIRST CVSS calculator. ([first.org][5])
* **Vulnerability references:** CVE / NVD search for vendor advisories. ([cve.org][3])

---
