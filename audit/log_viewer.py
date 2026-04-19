import sqlite3
import json

DB_PATH = "sample_db/bank.db"

def get_audit_log(conn):
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, action, table_name, record_id, old_value, new_value, timestamp, db_user "
        "FROM audit_log ORDER BY id"
    ).fetchall()
    keys = ["id","action","table_name","record_id","old_value","new_value","timestamp","db_user"]
    return [dict(zip(keys, row)) for row in rows]

def print_audit_log(conn):
    entries = get_audit_log(conn)
    print("\n" + "="*80)
    print("  AUDIT TRAIL")
    print("="*80)
    print(f"  {'ID':<5} {'ACTION':<10} {'TABLE':<15} {'REC_ID':<8} {'TIMESTAMP':<22} USER")
    print("-"*80)
    for e in entries:
        print(f"  {e['id']:<5} {e['action']:<10} {e['table_name']:<15} "
              f"{str(e['record_id'] or ''):<8} {e['timestamp']:<22} {e['db_user']}")
        if e["old_value"]:
            try:
                print(f"         old -> {json.loads(e['old_value'])}")
            except: pass
        if e["new_value"]:
            try:
                print(f"         new -> {json.loads(e['new_value'])}")
            except: pass
    print("="*80)
    print(f"  Total entries: {len(entries)}")
    return entries

if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    print_audit_log(conn)
    conn.close()