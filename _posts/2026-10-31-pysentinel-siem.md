---
title: "pysentinel-siem: Building a SIEM From Scratch in Python"
date: 2026-10-31 16:30:00 -0400
categories: [Projects, Detection Engineering]
tags: [siem, python, sysmon, windows, mitre-attack, blue-team]
pin: true
---

**Repo:** [github.com/rackvzz/pysentinel-siem](https://github.com/rackvzz/pysentinel-siem) · Python, Flask, SQLite, Sysmon · v1.1

## Why I built it

While studying for Security+, I kept reading about SIEM concepts like log normalization, correlation, and detection rules without ever seeing how they fit together. So I built a small but real SIEM that runs on a single Windows host, end to end: collection, storage, detection, correlation, alerting, and response.

It also matters for the offensive side. To write a good pentest report, you need to understand what defenders can see. Building the detections myself showed me exactly which attacker actions leave traces in Windows logs and which don't.

## How it works

```text
Windows Event Log (Security, System) + Sysmon
                |
        collector.py   (win32evtlog API, per-channel watermark)
                |
        normalize.py   (raw XML -> common schema)
                |
        storage.py     (SQLite)
                |
        engine.py      (runs each event through the rules)
                |
        alerts -> correlation -> dashboard / desktop app
```

- **Collection:** polls the Security, System, and Sysmon channels through the native Windows API. There's no third-party agent. Each channel keeps a watermark so the collector resumes safely after a restart.
- **Normalization:** every event, whatever its source, is converted into one schema and stored in SQLite.
- **Two interfaces:** a Flask browser dashboard and a native Tkinter desktop app, plus a standalone `.exe` that doesn't need Python.

## Detections

There are 10 rules, each mapped to MITRE ATT&CK:

| Rule | What it catches | ATT&CK |
|---|---|---|
| brute_force | Repeated failed logons (4625) from one source | T1110 |
| new_admin_account | New account (4720) or added to Administrators (4732) | T1136 / T1098 |
| afterhours_logon | Interactive/RDP logon outside business hours | T1078 |
| encoded_powershell | PowerShell launched with `-EncodedCommand` | T1059.001 |
| suspicious_parent_child | Office app spawning a shell or script interpreter | T1059 |
| powershell_scriptblock | Download cradles, offensive tooling, or encoded commands in script block logs (4104) | T1059.001 |
| credential_access | A process opening lsass.exe with memory-read access (Sysmon 10) | T1003 |
| persistence | New scheduled task (4698) or new service (7045) | T1053.005 / T1543.003 |
| port_scan_detection | Many blocked connections to different local ports from one IP (5157) | T1595 |
| threat_intel_match | Logon or outbound connection to an IP on the abuse.ch ThreatFox feed | TA0011 |

## Design decisions I'd point to

**Correlation over noise.** An after-hours logon alone usually means nothing. An after-hours logon, then a new admin account, then a brute-force burst from the same actor within 15 minutes is a much stronger signal. The correlation engine chains alerts like these into a single high-severity alert, so they don't get lost in the list.

**Human-in-the-loop response.** The tool never blocks anything on its own. "Block Source IP" adds a Windows Firewall rule only after explicit confirmation, and it refuses to block private, loopback, link-local, or reserved addresses, so you can't lock yourself out of your own network by mistake.

**Port scan detection with ambiguous docs.** Microsoft's documentation is inconsistent about which field in event 5157 is the local side and which is the remote side. Instead of guessing, the rule checks both fields against the machine's actual local IPs and treats whichever one isn't local as the scanner.

## Securing a security tool

A SIEM with a web UI and a firewall-blocking endpoint is itself an attack surface, so I treated it like one:

- **CSRF protection** on the write endpoints. A malicious page in another tab could otherwise send a forged POST to the localhost dashboard and trigger a block.
- **Security headers:** the server version banner is removed, plus `nosniff`, `X-Frame-Options: DENY` against clickjacking, and `no-referrer`.
- **Data minimization:** the API returns an explicit allowlist of fields, so raw event XML, which can contain full command lines, never leaves the backend.
- **File permissions:** the database and the API key file are restricted to the current user.
- **Content-Security-Policy:** scripts, styles, and API calls may only come from the dashboard itself, with no `unsafe-inline`. Even if event text like a username or command line ever slipped past output encoding, the browser would refuse to run injected script.
- **Input validation:** API parameters are clamped and validated, so one request can't pull the whole database into memory.
- **CI on every push:** 133 tests run on Windows and Ubuntu (Python 3.10 and 3.12), along with Ruff, Bandit, and pip-audit. Dependabot keeps dependencies current.

## Accessibility

A security dashboard is only useful if everyone on the team can use it, so the web UI targets **WCAG 2.2 AA**:

- **Contrast:** all text meets 4.5:1 in light and dark mode. The automated axe-core check went from 64 violations to 0, with no change to the layout.
- **Keyboard:** there's a skip link and a visible focus ring, and tables can be scrolled with the keyboard. Focus stays on your button through the 5-second auto-refresh.
- **Screen readers:**
  - charts describe their data in text
  - Block/Unblock buttons say which alert or IP they act on
  - new high-severity alerts are announced, even with reduced motion turned on
- **Never color alone:** severity always has a text label.

## Documentation

The repo includes a [security policy](https://github.com/rackvzz/pysentinel-siem/blob/master/SECURITY.md) with private vulnerability reporting, a [privacy page](https://github.com/rackvzz/pysentinel-siem/blob/master/PRIVACY.md) covering exactly what's collected and what (if anything) leaves the machine, [third-party license notices](https://github.com/rackvzz/pysentinel-siem/blob/master/THIRD_PARTY_NOTICES.md), and a [changelog](https://github.com/rackvzz/pysentinel-siem/blob/master/CHANGELOG.md).

## What's next

I plan to build an Active Directory lab, attack it with common techniques like Kerberoasting and pass-the-hash, and extend pysentinel-siem with detections for each one. Those write-ups will cover both the attack and the detection.
