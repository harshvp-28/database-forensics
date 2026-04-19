import sqlite3

conn = sqlite3.connect("sample_db/bank.db")
cur = conn.cursor()

cur.execute("ALTER TABLE audit_log ADD COLUMN row_hash TEXT")

conn.commit()
conn.close()

print("✅ column added")