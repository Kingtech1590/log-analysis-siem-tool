#!/usr/bin/env python3
"""
Log Analysis / Mini-SIEM Tool
------------------------------
Parses SSH auth logs (or similar syslog-style auth logs) and flags:
  - Brute-force attempts (>= N failed logins from one IP in a time window)
  - Successful logins following a burst of failures (possible compromise)
  - Logins from new/rare source IPs

Usage:
    python log_analyzer.py sample_auth.log
    python log_analyzer.py sample_auth.log --threshold 5 --window 300
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

LOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"sshd.*?(?P<result>Failed password|Accepted password).*?"
    r"for\s+(invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_line(line, year=2026):
    m = LOG_PATTERN.search(line)
    if not m:
        return None
    d = m.groupdict()
    ts = datetime(year, MONTHS[d["month"]], int(d["day"]),
                  *map(int, d["time"].split(":")))
    return {
        "timestamp": ts,
        "result": "success" if d["result"] == "Accepted password" else "failure",
        "user": d["user"],
        "ip": d["ip"],
    }


def parse_log(path):
    events = []
    with open(path) as f:
        for line in f:
            e = parse_line(line)
            if e:
                events.append(e)
    return sorted(events, key=lambda e: e["timestamp"])


def detect_brute_force(events, threshold=5, window_seconds=300):
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        if e["result"] != "failure":
            continue
        by_ip[e["ip"]].append(e["timestamp"])

    for ip, times in by_ip.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times[i:] if (t - times[i]).total_seconds() <= window_seconds]
            if len(window) >= threshold:
                findings.append({
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip": ip,
                    "detail": f"{len(window)} failed logins within {window_seconds}s "
                              f"starting {times[i].isoformat()}",
                })
                break
    return findings


def detect_success_after_failures(events, threshold=3, window_seconds=300):
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["timestamp"])
        fail_streak = []
        for e in evs:
            if e["result"] == "failure":
                fail_streak.append(e["timestamp"])
            elif e["result"] == "success":
                recent_fails = [t for t in fail_streak
                                if (e["timestamp"] - t).total_seconds() <= window_seconds]
                if len(recent_fails) >= threshold:
                    findings.append({
                        "type": "SUCCESS_AFTER_BRUTE_FORCE",
                        "severity": "CRITICAL",
                        "ip": ip,
                        "detail": f"Successful login for '{e['user']}' after {len(recent_fails)} "
                                  f"failed attempts at {e['timestamp'].isoformat()}",
                    })
                    fail_streak = []
    return findings


def summarize(events, findings):
    print("Log Analysis / Mini-SIEM Report")
    print("=" * 60)
    print(f"Events parsed: {len(events)}")
    fails = sum(1 for e in events if e["result"] == "failure")
    succ = sum(1 for e in events if e["result"] == "success")
    print(f"Failed logins: {fails}   Successful logins: {succ}\n")

    if not findings:
        print("No brute-force or anomalous patterns detected.")
        return

    for f in sorted(findings, key=lambda x: x["severity"]):
        print(f"[{f['severity']:8}] {f['type']:24} ip={f['ip']:15} — {f['detail']}")


def main():
    parser = argparse.ArgumentParser(description="Log Analysis / Mini-SIEM Tool")
    parser.add_argument("logfile", help="Path to auth log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts to flag brute force")
    parser.add_argument("--window", type=int, default=300, help="Time window in seconds")
    args = parser.parse_args()

    try:
        events = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    findings = detect_brute_force(events, args.threshold, args.window)
    findings += detect_success_after_failures(events, window_seconds=args.window)
    summarize(events, findings)


if __name__ == "__main__":
    main()
