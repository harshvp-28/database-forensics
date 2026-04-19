"""
simulate_advanced.py — Advanced Dynamic Attack Simulator
Every run selects a RANDOM combination of attack types, random target accounts,
random timestamps, and random attacker usernames.

This makes the forensic tool prove it works on ANY attack scenario —
not just one hardcoded crime scene.

Run AFTER setup.py (re-run setup.py first to get a clean database).
"""

import sqlite3
import time
import random
import json
from datetime import datetime, timedelta

DB_PATH = "sample_db/bank.db"

# ── Attack config pools ───────────────────────────────────────────────────────
ATTACKER_NAMES = ["root", "attacker", "admin", "sys_user", "db_admin", "unknown"]
ATTACK_HOURS   = [0, 1, 2, 3, 4]          # off-hours window (midnight to 4AM)

def random_offhours_ts(days_ago=1):
    """Generate a timestamp at a random off-hours time."""
    base = datetime.now() - timedelta(days=days_ago)
    base = base.replace(
        hour=random.choice(ATTACK_HOURS),
        minute=random.randint(0, 59),
        second=random.randint(0, 59)
    )
    return base.strftime("%Y-%m-%d %H:%M:%S")


def get_existing_accounts(cur):
    return cur.execute("SELECT id, name, balance FROM accounts").fetchall()


def get_existing_transactions(cur):
    return cur.execute("SELECT id, account_id FROM transactions").fetchall()


# ── Individual attack functions ───────────────────────────────────────────────

def attack_balance_wipe(cur, conn, attacker):
    """Zero out a randomly chosen account balance."""
    accounts = get_existing_accounts(cur)
    if not accounts:
        return None
    target = random.choice(accounts)
    acc_id, name, old_balance = target
    cur.execute("UPDATE accounts SET balance = 0.0 WHERE id = ?", (acc_id,))
    conn.commit()
    return f"[ATTACK] BALANCE WIPE — {name} (id={acc_id}) balance {old_balance} → 0.0"


def attack_balance_inflate(cur, conn, attacker):
    """Inflate a random account balance to a suspiciously high amount."""
    accounts = get_existing_accounts(cur)
    if not accounts:
        return None
    target = random.choice(accounts)
    acc_id, name, old_balance = target
    fake_balance = round(random.uniform(900000, 9999999), 2)
    cur.execute("UPDATE accounts SET balance = ? WHERE id = ?", (fake_balance, acc_id))
    conn.commit()
    return f"[ATTACK] BALANCE INFLATE — {name} (id={acc_id}) balance {old_balance} → {fake_balance}"


def attack_rapid_updates(cur, conn, attacker):
    """Rapidly update the same account multiple times in quick succession."""
    accounts = get_existing_accounts(cur)
    if not accounts:
        return None
    target = random.choice(accounts)
    acc_id, name, _ = target
    count = random.randint(3, 6)
    for _ in range(count):
        val = round(random.uniform(100, 50000), 2)
        cur.execute("UPDATE accounts SET balance = ? WHERE id = ?", (val, acc_id))
        conn.commit()
        time.sleep(0.03)
    return f"[ATTACK] RAPID UPDATES — {name} (id={acc_id}) updated {count}x rapidly"


def attack_bulk_delete_accounts(cur, conn, attacker):
    """Delete multiple accounts in quick succession."""
    accounts = get_existing_accounts(cur)
    if len(accounts) < 3:
        return None
    count = random.randint(2, min(4, len(accounts)))
    targets = random.sample(accounts, count)
    deleted = []
    for acc_id, name, _ in targets:
        cur.execute("DELETE FROM accounts WHERE id = ?", (acc_id,))
        conn.commit()
        deleted.append(name)
        time.sleep(0.05)
    return f"[ATTACK] BULK DELETE ACCOUNTS — deleted {count} accounts: {', '.join(deleted)}"


def attack_bulk_delete_transactions(cur, conn, attacker):
    """Delete multiple transactions in quick succession."""
    txns = get_existing_transactions(cur)
    if len(txns) < 4:
        return None
    count = random.randint(4, min(8, len(txns)))
    targets = random.sample(txns, count)
    for txn_id, _ in targets:
        cur.execute("DELETE FROM transactions WHERE id = ?", (txn_id,))
        conn.commit()
        time.sleep(0.04)
    return f"[ATTACK] BULK DELETE TRANSACTIONS — deleted {count} transactions"


def attack_fake_transaction(cur, conn, attacker):
    """Insert a suspicious large transaction with a backdated off-hours timestamp."""
    accounts = get_existing_accounts(cur)
    if not accounts:
        return None
    target = random.choice(accounts)
    acc_id, name, _ = target
    amount = round(random.uniform(50000, 999999), 2)
    ts = random_offhours_ts(days_ago=random.randint(1, 3))
    txn_type = random.choice(["withdrawal", "transfer"])

    # Insert directly (bypasses trigger timestamp to simulate backdated entry)
    cur.execute(
        "INSERT INTO transactions (account_id, amount, type, timestamp) VALUES (?, ?, ?, ?)",
        (acc_id, amount, txn_type, ts)
    )
    conn.commit()
    return f"[ATTACK] FAKE TRANSACTION — {txn_type} of {amount} from {name} at {ts}"


def attack_data_exfil_marker(cur, conn, attacker):
    """
    Simulate data exfiltration by mass-reading all account data.
    Leaves a marker in audit_log with an off-hours timestamp — attacker forgot to clean it.
    """
    ts = random_offhours_ts()
    cur.execute(
        "INSERT INTO audit_log (action, table_name, record_id, new_value, timestamp, db_user) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("SELECT", "accounts", 0,
         json.dumps({"query": "SELECT * FROM accounts", "rows_returned": 8}),
         ts, attacker)
    )
    conn.commit()
    return f"[ATTACK] EXFIL MARKER — mass SELECT logged at {ts} by {attacker}"


def attack_privilege_escalation(cur, conn, attacker):
    """
    Simulate a privilege escalation attempt by inserting a new account
    with a suspiciously high balance at an off-hours timestamp.
    """
    ts = random_offhours_ts()
    fake_name = random.choice(["Ghost User", "Test Admin", "Sys Account", "Backup User"])
    fake_email = f"{fake_name.lower().replace(' ', '')}@bank.com"
    balance = round(random.uniform(200000, 999999), 2)
    cur.execute(
        "INSERT INTO accounts (name, email, balance, created_at) VALUES (?, ?, ?, ?)",
        (fake_name, fake_email, balance, ts)
    )
    conn.commit()
    return f"[ATTACK] PRIV ESCALATION — ghost account '{fake_name}' created with balance {balance} at {ts}"


def attack_log_deletion(cur, conn, attacker):
    """Delete random rows from audit_log to cover tracks — creates detectable gaps."""
    ids = [r[0] for r in cur.execute("SELECT id FROM audit_log ORDER BY id").fetchall()]
    if len(ids) < 6:
        return None
    # Delete 2-4 random non-consecutive rows
    count = random.randint(2, min(4, len(ids) - 2))
    to_delete = random.sample(ids[2:-2], count)   # avoid first and last rows
    for log_id in to_delete:
        cur.execute("DELETE FROM audit_log WHERE id = ?", (log_id,))
    conn.commit()
    return f"[ATTACK] LOG DELETION — deleted {count} audit_log rows {sorted(to_delete)} to cover tracks"


def attack_name_tampering(cur, conn, attacker):
    """Modify an account holder's name — could indicate identity fraud."""
    accounts = get_existing_accounts(cur)
    if not accounts:
        return None
    target = random.choice(accounts)
    acc_id, name, _ = target
    fake_names = ["John Doe", "Test User", "Unknown Person", "Deleted User", "NULL"]
    new_name = random.choice(fake_names)
    cur.execute("UPDATE accounts SET name = ? WHERE id = ?", (new_name, acc_id))
    conn.commit()
    return f"[ATTACK] NAME TAMPER — account id={acc_id} renamed '{name}' → '{new_name}'"


# ── Attack registry ───────────────────────────────────────────────────────────
ALL_ATTACKS = [
    ("Balance Wipe",           attack_balance_wipe),
    ("Balance Inflate",        attack_balance_inflate),
    ("Rapid Updates",          attack_rapid_updates),
    ("Bulk Delete Accounts",   attack_bulk_delete_accounts),
    ("Bulk Delete Txns",       attack_bulk_delete_transactions),
    ("Fake Transaction",       attack_fake_transaction),
    ("Data Exfil Marker",      attack_data_exfil_marker),
    ("Privilege Escalation",   attack_privilege_escalation),
    ("Log Deletion",           attack_log_deletion),
    ("Name Tampering",         attack_name_tampering),
]


# ── Main simulator ────────────────────────────────────────────────────────────
def simulate_advanced(db_path=DB_PATH, num_attacks=None, seed=None):
    """
    Run a random combination of attacks.

    Args:
        num_attacks: How many attacks to run (default: random 3-6)
        seed: Set a random seed for reproducible runs (useful for demos)
    """
    if seed is not None:
        random.seed(seed)
        print(f"[INFO] Random seed set to {seed} — run is reproducible")

    conn = sqlite3.connect(db_path)
    cur  = conn.cursor()

    attacker = random.choice(ATTACKER_NAMES)
    if num_attacks is None:
        num_attacks = random.randint(3, 6)

    # Pick random attacks without repetition
    chosen = random.sample(ALL_ATTACKS, min(num_attacks, len(ALL_ATTACKS)))

    print("\n" + "="*60)
    print(f"  ADVANCED ATTACK SIMULATION")
    print(f"  Attacker identity : {attacker}")
    print(f"  Number of attacks : {num_attacks}")
    print(f"  Attacks selected  : {', '.join(name for name, _ in chosen)}")
    print("="*60 + "\n")

    results = []
    for attack_name, attack_fn in chosen:
        try:
            result = attack_fn(cur, conn, attacker)
            if result:
                print(result)
                results.append(result)
            else:
                print(f"[SKIP] {attack_name} — not enough data")
        except Exception as e:
            print(f"[ERROR] {attack_name} failed: {e}")
        time.sleep(0.1)

    conn.close()

    print("\n" + "="*60)
    print(f"  {len(results)} attack(s) executed successfully.")
    print(f"  Now run: python forensic_tool.py")
    print("="*60)
    return results


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Advanced dynamic attack simulator")
    parser.add_argument("--attacks", type=int, default=None,
                        help="Number of attacks to run (default: random 3-6)")
    parser.add_argument("--seed",    type=int, default=None,
                        help="Random seed for reproducible runs")
    parser.add_argument("--list",    action="store_true",
                        help="List all available attack types and exit")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable attack types:")
        for i, (name, _) in enumerate(ALL_ATTACKS, 1):
            print(f"  {i:2}. {name}")
        print()
    else:
        simulate_advanced(num_attacks=args.attacks, seed=args.seed)