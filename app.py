"""
app.py — Flask Web Dashboard for Database Forensics Tool
Run with: python app.py
Then open: http://127.0.0.1:5000
"""

from flask import Flask, render_template, jsonify, request, send_file
import sqlite3
import sys
import os
import json
import subprocess
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from audit.log_viewer           import get_audit_log
from integrity.hash_checker     import verify_chain
from recovery.page_parser       import scan_for_deleted_records
from detection.anomaly_detector import run_all_checks
from report.report_gen          import generate_report
from detection.ml_detector      import get_ml_summary

from report.generate_pdf_report import generate_pdf
app = Flask(__name__)
DB_PATH = "sample_db/bank.db"


def get_conn():
    return sqlite3.connect(DB_PATH)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _generate_report_bg():
    try:
        # call whatever function you already use to build the PDF
        generate_pdf()  # replace with your actual function name
    except Exception:
        pass

@app.route("/api/generate-report", methods=["POST"])
def api_generate_report():
    t = threading.Thread(target=_generate_report_bg)
    t.daemon = True
    t.start()
    return {"status": "started"}

@app.route("/api/report-ready")
def api_report_ready():
    path = os.path.join(os.path.dirname(__file__), "forensic_report.pdf")
    return {"ready": os.path.exists(path)}


# ── Helper: db exists check ───────────────────────────────────────────────────
def db_exists():
    return os.path.exists(DB_PATH)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    db_ready = os.path.exists(DB_PATH)
    
    if not db_ready:
        return render_template('dashboard.html',
            db_ready=False,
            accounts=[],
            transactions=[],
            audit_count=0
        )
    
    # Only query if DB exists
    conn = get_db()
    accounts = conn.execute("SELECT * FROM accounts").fetchall()
    transactions = conn.execute("""
        SELECT t.id, a.name, t.amount, t.type, t.timestamp
        FROM transactions t LEFT JOIN accounts a ON t.account_id = a.id
        ORDER BY t.timestamp DESC LIMIT 20
    """).fetchall()
    audit_count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    conn.close()

    return render_template('dashboard.html',
        db_ready=True,
        accounts=accounts,
        transactions=transactions,
        audit_count=audit_count
    )


@app.route("/forensics")
def forensics():
    db_ready = os.path.exists(DB_PATH)

    if not db_ready:
        return render_template('forensics.html',
            db_ready=False,
            integrity={'ok': True, 'total_rows_checked': 0, 'issues': []},
            anomalies={'alert_count': 0},
            tagged_alerts=[],
            fragments=[],
            audit=[]
        )

    if not db_exists():
        return render_template("forensics.html", db_ready=False)

    conn      = get_conn()
    audit     = get_audit_log(conn)
    integrity = verify_chain(conn)
    anomalies = run_all_checks(conn)
    conn.close()
    fragments = scan_for_deleted_records(DB_PATH)

    pdf_path = os.path.join(os.path.dirname(__file__), "forensic_report.pdf")
    if os.path.exists(pdf_path):
        os.remove(pdf_path)

    

    # Severity badge for each anomaly
    def severity(alert):
        alert_upper = alert.upper()
        if any(k in alert_upper for k in ["TAMPER", "WIPE", "CRITICAL", "INJECTION"]):
            return "danger"
        if any(k in alert_upper for k in ["OFF-HOURS", "BULK", "LARGE", "SUSPICIOUS"]):
            return "warning"
        return "info"
    
    tagged_alerts = [(a, severity(a)) for a in anomalies["alerts"]]
    t = threading.Thread(target=_generate_report_bg)
    t.daemon = True
    t.start()


    return render_template("forensics.html",
                           db_ready=True,
                           audit=audit,
                           integrity=integrity,
                           anomalies=anomalies,
                           tagged_alerts=tagged_alerts,
                           fragments=fragments)

@app.route('/api/reset', methods=['POST'])
def api_reset():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    return jsonify({'output': 'Database removed. Fresh state restored.'})

@app.route("/report")
def report():
    if not db_exists():
        return render_template("report.html", db_ready=False, report_text="")
    generate_report()
    with open("forensic_report.txt", "r", encoding="utf-8") as f:
        report_text = f.read()
    return render_template("report.html", db_ready=True, report_text=report_text)


# ── API endpoints (called by buttons via fetch) ───────────────────────────────

@app.route("/api/setup", methods=["POST"])
def api_setup():
    try:
        result = subprocess.run(
            [sys.executable, "setup.py"],
            capture_output=True, text=True, timeout=30
        )
        return jsonify({"ok": True, "output": result.stdout + result.stderr})
    except Exception as e:
        return jsonify({"ok": False, "output": str(e)})


@app.route("/api/attack", methods=["POST"])
def api_attack():
    mode = request.json.get("mode", "advanced")  # 'fixed' or 'advanced'
    seed = request.json.get("seed", None)
    try:
        cmd = [sys.executable, "simulate_advanced.py"]
        if seed:
            cmd += ["--seed", str(seed)]
        if mode == "fixed":
            cmd = [sys.executable, "simulate_crime.py"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return jsonify({"ok": True, "output": result.stdout + result.stderr})
    except Exception as e:
        return jsonify({"ok": False, "output": str(e)})


@app.route("/api/forensics", methods=["POST"])
def api_forensics():
    if not db_exists():
        return jsonify({"ok": False, "output": "Database not found. Run Setup first."})
    try:
        conn      = get_conn()
        integrity = verify_chain(conn)
        anomalies = run_all_checks(conn)
        conn.close()
        fragments = scan_for_deleted_records(DB_PATH)
        return jsonify({
            "ok":            True,
            "integrity_ok":  integrity["ok"],
            "issues":        len(integrity["issues"]),
            "alerts":        anomalies["alert_count"],
            "recovery_hits": len(fragments),
        })
    except Exception as e:
        return jsonify({"ok": False, "output": str(e)})


@app.route("/api/db_status", methods=["GET"])
def api_db_status():
    if not db_exists():
        return jsonify({"exists": False})
    conn = get_conn()
    cur  = conn.cursor()
    accounts = cur.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    txns     = cur.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    audit    = cur.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    conn.close()
    return jsonify({"exists": True, "accounts": accounts,
                    "transactions": txns, "audit_entries": audit})

@app.route("/ml")
def ml_analysis():
    if not db_exists():
        return render_template("ml.html", db_ready=False, summary=None)
    conn    = get_conn()
    summary = get_ml_summary(conn)
    conn.close()
    return render_template("ml.html", db_ready=True, summary=summary)


@app.route("/download-report")
def download_report():
    pdf_path = generate_pdf()   # your function from file
    return send_file(pdf_path, as_attachment=True)

@app.route("/view-report")
def view_report():
    path = os.path.join(os.path.dirname(__file__), "forensic_report.pdf")
    if not os.path.exists(path):
        return "Report not yet generated. Run Forensic Analysis first.", 404
    return send_file(path, mimetype="application/pdf", as_attachment=False)
if __name__ == "__main__":
    app.run(debug=False)