"""
setup.py — Database Forensics Project
Creates the sample banking database, audit log table, triggers, and seeds realistic data.
Run this FIRST before anything else.
"""

import sqlite3
import os
import hashlib
import json
from datetime import datetime, timedelta
import random

DB_PATH = "sample_db/bank.db"

def create_database():
    os.makedirs("sample_db", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ── Main tables ──────────────────────────────────────────────────────────
    cur.executescript("""
        DROP TABLE IF EXISTS accounts;
        DROP TABLE IF EXISTS transactions;
        DROP TABLE IF EXISTS audit_log;
        DROP TABLE IF EXISTS log_hashes;

        CREATE TABLE accounts (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            name    TEXT    NOT NULL,
            email   TEXT    UNIQUE,
            balance REAL    NOT NULL DEFAULT 0.0,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE transactions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            amount     REAL    NOT NULL,
            type       TEXT    NOT NULL,   -- 'deposit' | 'withdrawal' | 'transfer'
            timestamp  TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        -- Audit log: every INSERT/UPDATE/DELETE on accounts and transactions
        CREATE TABLE audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action      TEXT NOT NULL,         -- INSERT | UPDATE | DELETE
            table_name  TEXT NOT NULL,
            record_id   INTEGER,
            old_value   TEXT,                  -- JSON snapshot of old row
            new_value   TEXT,                  -- JSON snapshot of new row
            timestamp   TEXT DEFAULT (datetime('now')),
            db_user     TEXT DEFAULT 'system'
        );

        -- Hash chain table for tamper detection
        CREATE TABLE log_hashes (
            log_id   INTEGER PRIMARY KEY,
            row_hash TEXT NOT NULL
        );
    """)

    # ── Triggers ─────────────────────────────────────────────────────────────
    # accounts — INSERT
    cur.execute("""
        CREATE TRIGGER audit_accounts_insert
        AFTER INSERT ON accounts
        BEGIN
            INSERT INTO audit_log (action, table_name, record_id, new_value, db_user)
            VALUES ('INSERT', 'accounts', NEW.id,
                json_object('id', NEW.id, 'name', NEW.name, 'email', NEW.email,
                            'balance', NEW.balance),
                'system');
        END;
    """)

    # accounts — UPDATE
    cur.execute("""
        CREATE TRIGGER audit_accounts_update
        AFTER UPDATE ON accounts
        BEGIN
            INSERT INTO audit_log (action, table_name, record_id, old_value, new_value, db_user)
            VALUES ('UPDATE', 'accounts', NEW.id,
                json_object('id', OLD.id, 'name', OLD.name, 'balance', OLD.balance),
                json_object('id', NEW.id, 'name', NEW.name, 'balance', NEW.balance),
                'system');
        END;
    """)

    # accounts — DELETE
    cur.execute("""
        CREATE TRIGGER audit_accounts_delete
        AFTER DELETE ON accounts
        BEGIN
            INSERT INTO audit_log (action, table_name, record_id, old_value, db_user)
            VALUES ('DELETE', 'accounts', OLD.id,
                json_object('id', OLD.id, 'name', OLD.name, 'email', OLD.email,
                            'balance', OLD.balance),
                'system');
        END;
    """)

    # transactions — INSERT
    cur.execute("""
        CREATE TRIGGER audit_transactions_insert
        AFTER INSERT ON transactions
        BEGIN
            INSERT INTO audit_log (action, table_name, record_id, new_value, db_user)
            VALUES ('INSERT', 'transactions', NEW.id,
                json_object('id', NEW.id, 'account_id', NEW.account_id,
                            'amount', NEW.amount, 'type', NEW.type),
                'system');
        END;
    """)

    # transactions — DELETE
    cur.execute("""
        CREATE TRIGGER audit_transactions_delete
        AFTER DELETE ON transactions
        BEGIN
            INSERT INTO audit_log (action, table_name, record_id, old_value, db_user)
            VALUES ('DELETE', 'transactions', OLD.id,
                json_object('id', OLD.id, 'account_id', OLD.account_id,
                            'amount', OLD.amount, 'type', OLD.type),
                'system');
        END;
    """)

    conn.commit()

    # ── Seed data ─────────────────────────────────────────────────────────────
    accounts = [
        ("Alice Sharma",   "alice@bank.com",   95000.00),
        ("Bob Verma",      "bob@bank.com",      42000.00),
        ("Carol Singh",    "carol@bank.com",   120000.00),
        ("David Mehta",    "david@bank.com",    18500.00),
        ("Eve Patel",      "eve@bank.com",      67000.00),
        ("Frank D'souza",  "frank@bank.com",    53000.00),
        ("Grace Nair",     "grace@bank.com",    84000.00),
        ("Hemal Joshi",    "hemal@bank.com",    31000.00),
    ]
    cur.executemany(
        "INSERT INTO accounts (name, email, balance) VALUES (?, ?, ?)",
        accounts
    )

    # Seed a few normal transactions
    txn_types = ["deposit", "withdrawal", "transfer"]
    for acc_id in range(1, 9):
        for _ in range(3):
            amount = round(random.uniform(500, 5000), 2)
            cur.execute(
                "INSERT INTO transactions (account_id, amount, type) VALUES (?, ?, ?)",
                (acc_id, amount, random.choice(txn_types))
            )

    conn.commit()

    # ── Build initial hash chain ───────────────────────────────────────────
    from integrity.hash_checker import compute_and_store_hashes
    compute_and_store_hashes(conn)

    conn.commit()
    conn.close()
    print(f"[✓] Database created at {DB_PATH}")
    print(f"[✓] Accounts: 8  |  Transactions: 24  |  Triggers: 5")
    print(f"[✓] Hash chain initialised")


if __name__ == "__main__":
    create_database()