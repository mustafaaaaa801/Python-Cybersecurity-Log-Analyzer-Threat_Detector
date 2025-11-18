#!/usr/bin/env python3
import argparse
from utils.file_loader import load_file
from parsers.auth_parser import parse_auth_log
from parsers.apache_parser import parse_apache_log
from detectors.brute_force import detect_brute_force
from detectors.ti_checker import TIChecker
from reports.reporter import Reporter
from reports.dashboard import Dashboard
import datetime
import os
import sys
from utils.real_time_monitor import start_monitoring

# وظائف للمراقبة الحية
def process_auth_log(file_path, brute_detector, ti_checker):
    lines = load_file(file_path)
    events = parse_auth_log(lines)
    brute_detector(events)
    ti_checker([e['ip'] for e in events if e.get('ip')])

def process_apache_log(file_path, brute_detector, ti_checker):
    lines = load_file(file_path)
    events = parse_apache_log(lines)
    brute_detector(events)
    ti_checker([e['ip'] for e in events if e.get('ip')])

def main():
    parser = argparse.ArgumentParser(description="PCLATD - Log Analyzer & Threat Detector")
    parser.add_argument("--auth", help="Path to auth.log", required=False, default="sample_logs/auth.log")
    parser.add_argument("--apache", help="Path to access.log", required=False, default="sample_logs/access.log")
    parser.add_argument("--blocklist", help="Path to blocklist txt (one IP per line)", required=False, default="sample_logs/blocklist.txt")
    parser.add_argument("--out", help="Output folder", default="reports")
    parser.add_argument("--realtime", action="store_true", help="Enable real-time log monitoring")

    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # إعداد الكاشف و TI checker
    blocklist = load_file(args.blocklist)
    ti_checker = TIChecker(blocklist_ips=[ip.strip() for ip in blocklist if ip.strip()])
    
    def brute_detector(events):
        findings = detect_brute_force(events, window_seconds=120, threshold=10)
        if findings:
            print(f"[REAL-TIME] Detected {len(findings)} brute-force attack(s)")

    # الوضع الزمني الحقيقي
    if args.realtime:
        print("[*] Running in REAL-TIME mode")
        files = {
            args.auth: lambda f: process_auth_log(f, brute_detector, ti_checker),
            args.apache: lambda f: process_apache_log(f, brute_detector, ti_checker)
        }
        start_monitoring(files)
        sys.exit()

    # التحليل العادي (الافتراضي)
    auth_lines = load_file(args.auth)
    apache_lines = load_file(args.apache)

    auth_events = parse_auth_log(auth_lines)
    apache_events = parse_apache_log(apache_lines)

    brute_findings = detect_brute_force(auth_events, window_seconds=120, threshold=10)
    ti_matches = ti_checker.check_ips(set([e['ip'] for e in auth_events if e.get('ip')]) |
                                       set([e['ip'] for e in apache_events if e.get('ip')]))

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(args.out, f"report_{timestamp}.json")
    reporter = Reporter(report_path)
    reporter.save({
        "summary": {
            "auth_events": len(auth_events),
            "apache_events": len(apache_events),
            "brute_force_attacks": len(brute_findings),
            "ti_matches": list(ti_matches)
        },
        "brute_findings": brute_findings,
        "ti_matches": list(ti_matches),
        "sample_events": {
            "auth": auth_events[:10],
            "apache": apache_events[:10]
        }
    })

    dash_path = os.path.join(args.out, f"dashboard_{timestamp}.png")
    dashboard = Dashboard(dash_path)
    dashboard.plot_top_ips(auth_events + apache_events, top_n=10)

    print(f"Report saved: {report_path}")
    print(f"Dashboard saved: {dash_path}")
    print(f"Detected {len(brute_findings)} brute-force attack(s).")
    if ti_matches:
        print(f"Threat intelligence matches found for IPs: {', '.join(ti_matches)}")
    else:
        print("No TI matches found.")

if __name__ == "__main__":
    main()
