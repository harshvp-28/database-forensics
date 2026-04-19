import argparse
import sqlite3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from audit.log_viewer           import print_audit_log
from integrity.hash_checker     import print_integrity_report
from recovery.page_parser       import print_recovery_report
from detection.anomaly_detector import print_anomaly_report
from report.report_gen          import generate_report

def main():
    parser = argparse.ArgumentParser(description="Database Forensic Analysis Tool")
    parser.add_argument("--db", default="sample_db/bank.db")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"[ERROR] Database not found: {args.db}")
        print("Run setup.py first.")
        sys.exit(1)

    print("\n" + "="*65)
    print("  DATABASE FORENSICS TOOL")
    print(f"  Analysing: {os.path.abspath(args.db)}")
    print("="*65)

    conn = sqlite3.connect(args.db)
    print_audit_log(conn)
    print_integrity_report(conn)
    print_recovery_report(args.db)
    print_anomaly_report(conn)
    conn.close()

    generate_report(db_path=args.db)
    print("\n[DONE] Full analysis complete. Check forensic_report.txt")

if __name__ == "__main__":
    main()