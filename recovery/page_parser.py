import re
import struct
import os

DB_PATH = "sample_db/bank.db"
PAGE_SIZE = 4096
def deduplicate_fragments(fragments):
    seen = set()
    unique = []
    for f in fragments:
        key = frozenset(f["possible_emails"])
        if key and key not in seen:
            seen.add(key)
            unique.append(f)
        elif not key:
            unique.append(f)  # keep email-less pages (balance-only fragments)
    return unique

def read_pages(db_path):
    with open(db_path, "rb") as f:
        data = f.read()
    if len(data) >= 18:
        ps = struct.unpack(">H", data[16:18])[0]
        page_size = ps if ps in (512,1024,2048,4096,8192,16384,32768,65536) else PAGE_SIZE
    else:
        page_size = PAGE_SIZE
    return [data[i:i+page_size] for i in range(0, len(data), page_size)]

def extract_strings(data, min_len=4):
    pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'
    return [s.decode("ascii") for s in re.findall(pattern, data)]
def clean_name(n):
    words = n.split()
    cleaned = []
    for w in words:
        # Handle apostrophes like D'souza → D'Souza → stops at lowercase blob
        m = re.match(r"([A-Z][a-z']*(?:[A-Z][a-z']*)?)", w)
        cleaned.append(m.group(1) if m else w)
    return " ".join(cleaned)

def scan_for_deleted_records(db_path,conn=None):
    pages = read_pages(db_path)
    recovered = []
    email_re   = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    name_re    = re.compile(r'[A-Z][a-z]+(?: [A-Z][a-z\']+)+')
    balance_re = re.compile(r'\b\d{4,6}\.\d{2}\b')

    for page_num, page_data in enumerate(pages):
        strings = extract_strings(page_data)
        page_text = " ".join(strings)
        # After finding names and emails, filter them
        emails = [e for e in email_re.findall(page_text) if e.endswith("@bank.com")]
        names = [
            clean_name(n)
            for n in name_re.findall(page_text)
            if len(n.split()) >= 2 and len(n) <= 40
        ]
        names = list({n for n in names if len(n.split()) >= 2})
        balances = balance_re.findall(page_text)

        if emails or (names and balances):
            recovered.append({
                "page": page_num,
                "offset_hex": hex(page_num * PAGE_SIZE),
                "possible_names":    list(set(names)),
                "possible_emails":   list(set(emails)),
                "possible_balances": list(set(balances)),
            })

    
    if conn:
        cur = conn.cursor()
        live_emails = {r[0] for r in cur.execute("SELECT email FROM accounts").fetchall()}
        for fragment in recovered:
            fragment["possible_emails"] = [
                e for e in fragment["possible_emails"] if e not in live_emails
            ]
        # Remove pages where nothing forensically interesting remains
        recovered = [f for f in recovered if f["possible_emails"] or 
                    (f["possible_names"] and f["possible_balances"])]
        
    recovered = deduplicate_fragments(recovered)
    return recovered


def print_recovery_report(db_path=DB_PATH, conn=None):
    print("\n" + "="*60)
    print("  DELETED RECORD RECOVERY")
    print("="*60)
    if not os.path.exists(db_path):
        print("  Database not found.")
        return []
    fragments = scan_for_deleted_records(db_path, conn)
    if not fragments:
        print("  No recoverable data found.")
    else:
        print(f"  Found {len(fragments)} page(s) with recoverable fragments:\n")
        for f in fragments:
            print(f"  Page {f['page']} (offset {f['offset_hex']}):")
            if f["possible_names"]:
                print(f"    Names    : {', '.join(f['possible_names'])}")
            if f["possible_emails"]:
                print(f"    Emails   : {', '.join(f['possible_emails'])}")
            if f["possible_balances"]:
                print(f"    Balances : {', '.join(f['possible_balances'])}")
    print("="*60)
    return fragments

if __name__ == "__main__":
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    print_recovery_report(db_path=DB_PATH, conn=conn)
    conn.close()