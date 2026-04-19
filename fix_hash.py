import sqlite3
import hashlib

conn = sqlite3.connect("sample_db/bank.db")
cur = conn.cursor()

cur.execute("""
SELECT id, timestamp, action, table_name, record_id, old_value, new_value, db_user
FROM audit_log
""")

rows = cur.fetchall()

for r in rows:
    rid, ts, action, tbl, rec_id, old_v, new_v, user = r
    
    raw = f"{ts}{action}{tbl}{rec_id}{old_v}{new_v}{user}"
    hash_val = hashlib.sha256(raw.encode()).hexdigest()
    
    cur.execute("UPDATE audit_log SET row_hash=? WHERE id=?", (hash_val, rid))

conn.commit()
conn.close()

print("✅ hashes added")