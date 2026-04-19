"""
simulate_crime.py — Database Forensics Project
Simulates an attacker performing malicious actions on bank.db.

Crimes committed (each maps to a forensic detection):
  1. Balance wipe       → Alice Sharma's balance set to 0.0
  2. Bulk delete        → Grace Nair (id=7) + Hemal Joshi (id=8) deleted rapidly
  3. Fraudulent txns    → Large withdrawals inserted for attacker's benefit
  4. Audit log erasure  → 3 audit_log rows deleted to cover tracks
  5. All actions stamped as user='attacker' at 2AM

Run AFTER setup.py, BEFORE forensic_tool.py.
"""

import sqlite3
import time

DB_PATH = "sample_db/bank.db"

CRIME_TIMESTAMP = "2026-03-31 02:13:00"  # 2AM — off-hours flag


def _ts(offset_seconds: int = 0) -> str:
    """Return a fake 2AM timestamp with an offset (to simulate rapid actions)."""
    from datetime import datetime, timedelta
    base = datetime.strptime(CRIME_TIMESTAMP, "%Y-%m-%d %H:%M:%S")
    return (base + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%d %H:%M:%S")


def run_crimes():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    print("=" * 55)
    print("  SIMULATING ATTACKER ACTIONS")
    print("=" * 55)

    # ── Crime 1: Wipe Alice Sharma's balance ──────────────────────────────
    # Detected by: anomaly_detector (balance_wipe rule)
    cur.execute("""
        UPDATE accounts
        SET balance = 0.0
        WHERE id = 1
    """)
    # Stamp the audit_log row with attacker + fake timestamp
    cur.execute("""
        UPDATE audit_log
        SET db_user   = 'attacker',
            timestamp = ?
        WHERE id = (SELECT MAX(id) FROM audit_log)
    """, (_ts(0),))
    print(f"[CRIME 1] Balance wiped  → Alice Sharma (id=1) balance set to 0.0")

    # ── Crime 2: Fraudulent large withdrawal on Carol's account ───────────
    # Detected by: audit trail (INSERT by attacker) + anomaly (large amount)
    cur.execute("""
        INSERT INTO transactions (account_id, amount, type, timestamp)
        VALUES (3, 99000.0, 'withdrawal', ?)
    """, (_ts(2),))
    cur.execute("""
        UPDATE audit_log
        SET db_user   = 'attacker',
            timestamp = ?
        WHERE id = (SELECT MAX(id) FROM audit_log)
    """, (_ts(2),))
    print(f"[CRIME 2] Fraudulent txn → ₹99000 withdrawal on Carol Singh (id=3)")

    # ── Crime 3: Rapid bulk delete of accounts ────────────────────────────
    # Grace Nair (id=7) and Hemal Joshi (id=8) deleted 4 seconds apart
    # Detected by: anomaly_detector (bulk_delete rule) + page_parser (recovery)
    for offset, acc_id, name in [(5, 7, "Grace Nair"), (7, 8, "Hemal Joshi")]:
        cur.execute("DELETE FROM accounts WHERE id = ?", (acc_id,))
        cur.execute("""
            UPDATE audit_log
            SET db_user   = 'attacker',
                timestamp = ?
            WHERE id = (SELECT MAX(id) FROM audit_log)
        """, (_ts(offset),))
        print(f"[CRIME 3] Account deleted → {name} (id={acc_id}) at {_ts(offset)}")

    # Also delete their transactions to deepen the cover-up
    for acc_id in (7, 8):
        cur.execute("DELETE FROM transactions WHERE account_id = ?", (acc_id,))
        # stamp each resulting audit row
        cur.execute("""
            UPDATE audit_log
            SET db_user   = 'attacker',
                timestamp = ?
            WHERE id = (SELECT MAX(id) FROM audit_log)
        """, (_ts(10),))
    print(f"[CRIME 3] Transactions deleted for accounts 7 and 8")

    conn.commit()

    # ── Crime 4: Erase audit log rows to cover tracks ─────────────────────
    # Attacker deletes 3 specific audit_log rows (the DELETE entries for id=7,8)
    # Detected by: hash_checker (DELETED status — ghost IDs in log_hashes)
    #              anomaly_detector (ID gap rule)
    rows_to_erase = cur.execute("""
        SELECT id FROM audit_log
        WHERE db_user = 'attacker'
          AND action  = 'DELETE'
          AND table_name = 'accounts'
        ORDER BY id
        LIMIT 3
    """).fetchall()

    erased_ids = []
    for (row_id,) in rows_to_erase:
        cur.execute("DELETE FROM audit_log WHERE id = ?", (row_id,))
        erased_ids.append(row_id)

    conn.commit()
    print(f"[CRIME 4] Audit log rows erased → ids {erased_ids}")

    # ── Summary ───────────────────────────────────────────────────────────
    remaining_accounts = cur.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    audit_count        = cur.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    hash_count         = cur.execute("SELECT COUNT(*) FROM log_hashes").fetchone()[0]

    print()
    print("=" * 55)
    print("  POST-CRIME STATE")
    print("=" * 55)
    unhashed   = audit_count - hash_count   # new rows added after setup (no hash yet)
    ghost_rows = len(erased_ids)            # rows deleted from audit_log (hash exists, row gone)

    print(f"  Accounts remaining : {remaining_accounts}  (was 8)")
    print(f"  audit_log rows     : {audit_count}  |  log_hashes rows: {hash_count}")
    print(f"  Unhashed new rows  : {unhashed}  ← flagged as MISSING_HASH by checker")
    print(f"  Erased audit rows  : {ghost_rows}  ← flagged as DELETED by checker")
    print("=" * 55)
    print()
    print("  Run forensic_tool.py to investigate.")
    print()

    conn.close()


if __name__ == "__main__":
    run_crimes()