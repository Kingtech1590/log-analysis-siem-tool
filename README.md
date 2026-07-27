# Log Analysis / Mini-SIEM Tool

A lightweight Python log analyzer that parses SSH auth logs and detects brute-force login attempts and successful logins that follow a burst of failures — a strong indicator of a compromised credential.

## Why this exists

Detection and monitoring are core Security+ domains. Full SIEM platforms (Splunk, Elastic, Wazuh) are overkill for demonstrating the underlying logic: this tool implements the detection rules themselves from raw log lines, in plain Python, so the reasoning is fully visible.

## Features
- Parses standard `sshd` auth log lines (`Failed password`, `Accepted password`)
- Detects brute-force bursts: N+ failures from one IP within a rolling time window
- Detects "success after failure burst" — a likely successful compromise following repeated failed attempts
- Configurable threshold and time window
- Zero dependencies — standard library only

## Usage

```bash
# Run against the bundled sample log
python log_analyzer.py sample_auth.log

# Tune sensitivity
python log_analyzer.py sample_auth.log --threshold 5 --window 300
```

## Sample output

```
Log Analysis / Mini-SIEM Report
============================================================
Events parsed: 11
Failed logins: 8   Successful logins: 3

[HIGH    ] BRUTE_FORCE               ip=203.0.113.45   — 6 failed logins within 300s starting 2026-07-20T09:12:01
[CRITICAL] SUCCESS_AFTER_BRUTE_FORCE ip=203.0.113.45   — Successful login for 'root' after 6 failed attempts at 2026-07-20T09:12:25
```

## Requirements
- Python 3.9+
- No third-party dependencies

## Notes
This is a detection-logic demonstration, not a production SIEM. It's meant to show an understanding of brute-force detection and log correlation, the kind of logic that underlies real SIEM alert rules.
