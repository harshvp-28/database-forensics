import sqlite3
import json
from datetime import datetime
from collections import defaultdict

DB_PATH = "sample_db/bank.db"

def get_log_entries(conn):
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, action, table_name, record_id, old_value, new_value, timestamp, db_user "
        "FROM audit_log ORDER BY id"
    ).fetchall()
    keys = ["id","action","table_name","record_id","old_value","new_value","timestamp","db_user"]
    return [dict(zip(keys, r)) for r in rows]

def parse_ts(ts):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except: pass
    return datetime.min

def check_bulk_deletes(entries):
    alerts = []
    delete_events = [
        (parse_ts(e["timestamp"]), e["db_user"])
        for e in entries if e["action"] == "DELETE"
    ]
    delete_events.sort(key=lambda x: x[0])

    for i, (t, _) in enumerate(delete_events):
        window = [(dt, u) for dt, u in delete_events[i:] if (dt - t).total_seconds() <= 60]
        if len(window) >= 5:
            users = set(u for _, u in window)
            alerts.append(
                f"BULK DELETE: {len(window)} deletes within 60s at {t} "
                f"by user(s): {', '.join(users)}"
            )
            break
    return alerts

def check_off_hours(entries):
    alerts = []
    for e in entries:
        ts = parse_ts(e["timestamp"])
        if 0 <= ts.hour < 5:
            alerts.append(
                f"OFF-HOURS: {e['action']} on {e['table_name']} "
                f"id={e['record_id']} at {ts.strftime('%H:%M:%S')} by {e['db_user']}"
            )
    return alerts

def check_rapid_updates(entries):
    alerts = []
    by_record = defaultdict(list)
    for e in entries:
        if e["action"] == "UPDATE":
            by_record[(e["table_name"], e["record_id"])].append(parse_ts(e["timestamp"]))
    for (table, rid), times in by_record.items():
        times.sort()
        for i, t in enumerate(times):
            window = [dt for dt in times[i:] if (dt - t).total_seconds() <= 10]
            if len(window) >= 3:
                alerts.append(f"RAPID UPDATES: {table} id={rid} updated {len(window)}x in 10s")
                break
    return alerts

def check_balance_wipe(entries):
    alerts = []
    for e in entries:
        if e["action"] == "UPDATE" and e["table_name"] == "accounts" and e["new_value"]:
            try:
                new = json.loads(e["new_value"])
                if float(new.get("balance", 1)) <= 0:
                    old = json.loads(e["old_value"] or "{}") if e["old_value"] else {}
                    alerts.append(
                        f"BALANCE WIPE: account id={e['record_id']} "
                        f"{old.get('balance','?')} -> {new.get('balance')}"
                    )
            except: pass
    return alerts

def check_log_gaps(conn):
    cur = conn.cursor()
    ids = [r[0] for r in cur.execute("SELECT id FROM audit_log ORDER BY id").fetchall()]
    alerts = []
    for i in range(1, len(ids)):
        if ids[i] - ids[i-1] > 1:
            alerts.append(
                f"LOG GAP: IDs jump from {ids[i-1]} to {ids[i]} "
                f"({ids[i]-ids[i-1]-1} row(s) deleted)"
            )
    return alerts
def check_suspicious_accounts(conn):
    """Flag accounts created with unusually high starting balance."""
    cur = conn.cursor()
    alerts = []
    rows = cur.execute(
        "SELECT record_id, new_value, timestamp, db_user FROM audit_log "
        "WHERE action = 'INSERT' AND table_name = 'accounts'"
    ).fetchall()
    for record_id, new_value, timestamp, db_user in rows:
        try:
            data = json.loads(new_value)
            balance = float(data.get("balance", 0))
            if balance > 500000:
                alerts.append(
                    f"SUSPICIOUS ACCOUNT: id={record_id} created with "
                    f"balance {balance} at {timestamp} by {db_user}"
                )
        except:
            pass
    return alerts

def check_name_tampering(entries):
    """Flag any UPDATE that changes an account holder's name."""
    alerts = []
    for e in entries:
        if e["action"] == "UPDATE" and e["table_name"] == "accounts":
            try:
                old = json.loads(e["old_value"] or "{}")
                new = json.loads(e["new_value"] or "{}")
                if old.get("name") and new.get("name") and old["name"] != new["name"]:
                    alerts.append(
                        f"NAME TAMPER: account id={e['record_id']} "
                        f"'{old['name']}' → '{new['name']}' by {e['db_user']}"
                    )
            except:
                pass
    return alerts

def check_large_transactions(entries):
    """Flag any transaction above a suspicious threshold."""
    THRESHOLD = 100000
    alerts = []
    for e in entries:
        if e["action"] == "INSERT" and e["table_name"] == "transactions":
            try:
                data = json.loads(e["new_value"] or "{}")
                amount = float(data.get("amount", 0))
                if amount > THRESHOLD:
                    alerts.append(
                        f"LARGE TRANSACTION: id={data.get('id')} amount={amount} "
                        f"type={data.get('type')} at {e['timestamp']} by {e['db_user']}"
                    )
            except:
                pass
    return alerts
def run_all_checks(conn):
    entries = get_log_entries(conn)
    alerts = []
    alerts += check_bulk_deletes(entries)
    alerts += check_off_hours(entries)
    alerts += check_rapid_updates(entries)
    alerts += check_balance_wipe(entries)
    alerts += check_log_gaps(conn)
    alerts += check_suspicious_accounts(conn)   
    alerts += check_name_tampering(entries)   
    alerts += check_large_transactions(entries)  
    return {"total_entries_analysed": len(entries), "alert_count": len(alerts), "alerts": alerts}

def print_anomaly_report(conn):
    result = run_all_checks(conn)
    print("\n" + "="*65)
    print("  ANOMALY DETECTION")
    print("="*65)
    print(f"  Entries analysed : {result['total_entries_analysed']}")
    print(f"  Alerts raised    : {result['alert_count']}\n")
    for alert in result["alerts"]:
        print(f"  [!] {alert}")
    if not result["alerts"]:
        print("  No anomalies detected.")
    print("="*65)
    return result

if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    print_anomaly_report(conn)
    conn.close()