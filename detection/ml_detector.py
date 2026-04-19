"""
detection/ml_detector.py — ML-based Anomaly Detection using Isolation Forest
Uses unsupervised learning to score each audit log entry for suspiciousness.
Works alongside the rule-based detector — catches patterns rules might miss.
"""

import sqlite3
import json
import numpy as np
from datetime import datetime

DB_PATH = "sample_db/bank.db"

# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(entries):
    """
    Convert each audit log entry into a numeric feature vector.
    Features:
      0 — hour of day (0-23)
      1 — action type encoded (INSERT=0, UPDATE=1, DELETE=2, other=3)
      2 — is weekend (0/1)
      3 — amount (from new_value/old_value JSON, 0 if not applicable)
      4 — balance_after (from new_value, 0 if not applicable)
      5 — is_non_system_user (0=system, 1=other)
      6 — record_id (numeric — high IDs can indicate injected rows)
    """
    ACTION_MAP = {"INSERT": 0, "UPDATE": 1, "DELETE": 2, "SELECT": 3}

    vectors = []
    for e in entries:
        try:
            ts   = _parse_ts(e["timestamp"])
            hour = ts.hour
            dow  = ts.weekday()  # 0=Mon, 6=Sun
        except:
            hour, dow = 12, 0

        action_code = ACTION_MAP.get(e["action"], 3)
        is_weekend  = 1 if dow >= 5 else 0
        is_offhours = 1 if (0 <= hour < 5) else 0
        is_non_sys  = 0 if e["db_user"] == "system" else 1
        record_id   = int(e["record_id"]) if e["record_id"] else 0

        # Extract amount and balance from JSON
        amount  = 0.0
        balance = 0.0
        for field in ["new_value", "old_value"]:
            try:
                data = json.loads(e[field] or "{}")
                if "amount"  in data: amount  = float(data["amount"])
                if "balance" in data: balance = float(data["balance"])
            except:
                pass

        vectors.append([
            hour,
            action_code,
            is_weekend,
            is_offhours,
            amount,
            balance,
            is_non_sys,
            record_id,
        ])

    return np.array(vectors, dtype=float)


def _parse_ts(ts_str):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt)
        except:
            pass
    return datetime.min


# ── Isolation Forest ──────────────────────────────────────────────────────────

def run_isolation_forest(entries, contamination=0.15):
    """
    Train Isolation Forest on audit log entries and return anomaly scores.

    contamination: expected fraction of outliers (0.15 = 15% flagged)

    Returns list of dicts with:
      - entry: original audit log entry
      - score: raw anomaly score (-1 to 0, lower = more anomalous)
      - risk:  normalised risk 0-100 (100 = most suspicious)
      - label: ANOMALY or NORMAL
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    if len(entries) < 5:
        return []  # not enough data to train

    X = extract_features(entries)

    # Normalise features so large amounts don't dominate
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42
    )
    model.fit(X_scaled)

    raw_scores = model.decision_function(X_scaled)  # negative = anomalous
    predictions = model.predict(X_scaled)           # -1=anomaly, 1=normal

    # Normalise scores to 0-100 risk scale (100 = most suspicious)
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s != min_s:
        risk_scores = 100 * (1 - (raw_scores - min_s) / (max_s - min_s))
    else:
        risk_scores = np.zeros(len(raw_scores))

    results = []
    for i, entry in enumerate(entries):
        results.append({
            "entry":  entry,
            "score":  round(float(raw_scores[i]), 4),
            "risk":   round(float(risk_scores[i]), 1),
            "label":  "ANOMALY" if predictions[i] == -1 else "NORMAL",
        })

    # Sort by risk descending
    results.sort(key=lambda x: x["risk"], reverse=True)
    return results


def get_ml_summary(conn):
    """
    Run ML detection and return a clean summary for the dashboard.
    """
    cur     = conn.cursor()
    rows    = cur.execute(
        "SELECT id, action, table_name, record_id, old_value, new_value, timestamp, db_user "
        "FROM audit_log ORDER BY id"
    ).fetchall()
    keys    = ["id","action","table_name","record_id","old_value","new_value","timestamp","db_user"]
    entries = [dict(zip(keys, r)) for r in rows]

    if len(entries) < 5:
        return {
            "available": False,
            "reason": "Not enough audit entries to train model (need at least 5)",
            "results": [],
            "top_anomalies": [],
            "anomaly_count": 0,
        }

    results = run_isolation_forest(entries)
    anomalies = [r for r in results if r["label"] == "ANOMALY"]

    return {
        "available":     True,
        "total_scored":  len(results),
        "anomaly_count": len(anomalies),
        "top_anomalies": results[:10],   # top 10 riskiest entries
        "results":       results,
    }


def print_ml_report(conn):
    summary = get_ml_summary(conn)
    print("\n" + "="*65)
    print("  ML ANOMALY DETECTION  (Isolation Forest)")
    print("="*65)
    if not summary["available"]:
        print(f"  {summary['reason']}")
        return

    print(f"  Entries scored   : {summary['total_scored']}")
    print(f"  Anomalies found  : {summary['anomaly_count']}")
    print(f"\n  Top 10 riskiest entries:")
    print(f"  {'ID':<5} {'RISK':>6}  {'LABEL':<10} {'ACTION':<8} {'TABLE':<15} TIMESTAMP")
    print("  " + "-"*65)
    for r in summary["top_anomalies"]:
        e = r["entry"]
        print(
            f"  {e['id']:<5} {r['risk']:>5.1f}%  {r['label']:<10} "
            f"{e['action']:<8} {e['table_name']:<15} {e['timestamp']}"
        )
    print("="*65)


if __name__ == "__main__":
    conn = sqlite3.connect(DB_PATH)
    print_ml_report(conn)
    conn.close()