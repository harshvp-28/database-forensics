"""
integrity/hash_checker.py — Hash chain tamper detection
Each audit_log row is hashed together with the previous row's hash (like a mini blockchain).
Any deletion or modification of a log row breaks the chain and gets flagged.
"""

import sqlite3
import hashlib
import json

DB_PATH = "sample_db/bank.db"


def _row_to_string(row: tuple) -> str:
    """Serialise an audit_log row to a stable string for hashing."""
    return json.dumps(row, sort_keys=True, default=str)


def compute_and_store_hashes(conn: sqlite3.Connection):
    """
    Build (or rebuild) the hash chain for all existing audit_log rows.
    Called once during setup; also callable to resync after legitimate changes.
    """
    cur = conn.cursor()
    cur.execute("DELETE FROM log_hashes")

    rows = cur.execute(
        "SELECT id, action, table_name, record_id, old_value, new_value, timestamp, db_user "
        "FROM audit_log ORDER BY id"
    ).fetchall()

    prev_hash = "GENESIS"
    for row in rows:
        content = _row_to_string(row) + prev_hash
        row_hash = hashlib.sha256(content.encode()).hexdigest()
        cur.execute(
            "INSERT INTO log_hashes (log_id, row_hash) VALUES (?, ?)",
            (row[0], row_hash)
        )
        prev_hash = row_hash

    conn.commit()


def verify_chain(conn: sqlite3.Connection) -> dict:
    """
    Re-compute the hash chain and compare against stored hashes.
    Returns a report dict: {ok: bool, issues: list[str], details: list[dict]}
    """
    cur = conn.cursor()

    stored = {
        row[0]: row[1]
        for row in cur.execute("SELECT log_id, row_hash FROM log_hashes ORDER BY log_id").fetchall()
    }

    rows = cur.execute(
        "SELECT id, action, table_name, record_id, old_value, new_value, timestamp, db_user "
        "FROM audit_log ORDER BY id"
    ).fetchall()

    issues = []
    details = []
    prev_hash = "GENESIS"
    live_ids = set()

    for row in rows:
        log_id = row[0]
        live_ids.add(log_id)
        content = _row_to_string(row) + prev_hash
        expected_hash = hashlib.sha256(content.encode()).hexdigest()

        if log_id not in stored:
            msg = f"Row {log_id} exists in audit_log but has NO stored hash → possible injection"
            issues.append(msg)
            details.append({"log_id": log_id, "status": "MISSING_HASH", "message": msg})
        elif stored[log_id] != expected_hash:
            msg = f"Row {log_id} hash MISMATCH → row was modified after logging"
            issues.append(msg)
            details.append({"log_id": log_id, "status": "MISMATCH", "message": msg})
        else:
            details.append({"log_id": log_id, "status": "OK"})

        prev_hash = expected_hash  # continue chain even on mismatch to catch downstream breaks

    # Check for gaps (rows deleted from audit_log but still in log_hashes)
    ghost_ids = set(stored.keys()) - live_ids
    for gid in sorted(ghost_ids):
        msg = f"Row {gid} is in log_hashes but MISSING from audit_log → row was deleted"
        issues.append(msg)
        details.append({"log_id": gid, "status": "DELETED", "message": msg})

    return {
        "ok": len(issues) == 0,
        "total_rows_checked": len(rows),
        "issues": issues,
        "details": details,
    }


def print_integrity_report(conn: sqlite3.Connection):
    result = verify_chain(conn)
    print("\n" + "=" * 55)
    print("  INTEGRITY CHECK")
    print("=" * 55)
    print(f"  Rows checked : {result['total_rows_checked']}")
    if result["ok"]:
        print("  Status       : ✓ ALL HASHES MATCH — no tampering detected")
    else:
        print(f"  Status       : ✗ TAMPERING DETECTED — {len(result['issues'])} issue(s)")
        for issue in result["issues"]:
            print(f"    !! {issue}")
    print("=" * 55)
    return result


if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    print_integrity_report(conn)
    conn.close()