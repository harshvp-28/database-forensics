import sqlite3
import os
import sys
import json
from datetime import datetime

DB_PATH    = "sample_db/bank.db"
REPORT_TXT = "forensic_report.txt"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from audit.log_viewer           import get_audit_log
from integrity.hash_checker     import verify_chain
from recovery.page_parser       import scan_for_deleted_records
from detection.anomaly_detector import run_all_checks

def generate_report(db_path=DB_PATH, out_path=REPORT_TXT):
    conn = sqlite3.connect(db_path)
    lines = []
    sep = "=" * 65

    lines.append(sep)
    lines.append("  FORENSIC INVESTIGATION REPORT")
    lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Database  : {os.path.abspath(db_path)}")
    lines.append(sep)

    # Audit trail
    lines.append("\n[1] AUDIT TRAIL\n" + "-"*65)
    log = get_audit_log(conn)
    lines.append(f"  Total entries: {len(log)}\n")
    for e in log:
        line = f"  [{e['timestamp']}]  {e['action']:<8} {e['table_name']:<15} id={e['record_id']}  user={e['db_user']}"
        if e["old_value"]:
            try: line += f"\n           old -> {json.loads(e['old_value'])}"
            except: pass
        if e["new_value"]:
            try: line += f"\n           new -> {json.loads(e['new_value'])}"
            except: pass
        lines.append(line)

    # Integrity
    lines.append("\n\n[2] INTEGRITY CHECK\n" + "-"*65)
    integrity = verify_chain(conn)
    lines.append(f"  Rows checked : {integrity['total_rows_checked']}")
    if integrity["ok"]:
        lines.append("  Result : ALL HASHES MATCH")
    else:
        lines.append(f"  Result : TAMPERING DETECTED — {len(integrity['issues'])} issue(s)")
        for issue in integrity["issues"]:
            lines.append(f"    !! {issue}")

    # Recovery
    # Recovery
    lines.append("\n\n[3] DELETED RECORD RECOVERY\n" + "-"*65)
    fragments = scan_for_deleted_records(db_path, conn)   # <-- pass conn
    if not fragments:
        lines.append("  No recoverable data found.")
    else:
        lines.append(f"  {len(fragments)} page(s) with recoverable fragments:\n")
        for frag in fragments:                             # <-- frag not f
            lines.append(f"  Page {frag['page']} (offset {frag['offset_hex']}):")
            if frag["possible_names"]:
                lines.append(f"    Names    : {', '.join(frag['possible_names'])}")
            if frag["possible_emails"]:
                lines.append(f"    Emails   : {', '.join(frag['possible_emails'])}")
            if frag["possible_balances"]:
                lines.append(f"    Balances : {', '.join(frag['possible_balances'])}")
    # Anomalies
    lines.append("\n\n[4] ANOMALY DETECTION\n" + "-"*65)
    anomalies = run_all_checks(conn)
    lines.append(f"  Entries analysed : {anomalies['total_entries_analysed']}")
    lines.append(f"  Alerts raised    : {anomalies['alert_count']}\n")
    for alert in anomalies["alerts"]:
        lines.append(f"  [!] {alert}")
    if not anomalies["alerts"]:
        lines.append("  No anomalies detected.")

    # Summary
    lines.append("\n\n[5] SUMMARY\n" + "-"*65)
    if not integrity["ok"]:
        status = "CRITICAL — log tampering detected"
    elif anomalies["alert_count"] > 0:
        status = f"WARNING — {anomalies['alert_count']} anomalies detected"
    elif fragments:
        status = "INFO — deleted data fragments found"
    else:
        status = "CLEAN"
    lines.append(f"  Overall status : {status}")
    lines.append(f"  Integrity      : {'PASS' if integrity['ok'] else 'FAIL'}")
    lines.append(f"  Anomalies      : {anomalies['alert_count']}")
    lines.append(f"  Recovery hits  : {len(fragments)} page(s)")
    lines.append("\n" + sep)
    lines.append("  END OF REPORT")
    lines.append(sep)

    conn.close()
    report_text = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"\n[OK] Report saved: {os.path.abspath(out_path)}")
    return report_text

if __name__ == "__main__":
    generate_report()