import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH
from feeds.reputation_loader import get_ip_reputation

WINDOW_MINUTES = 2
THRESHOLD = 10  # default

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("SELECT MAX(timestamp) FROM logs")
latest_ts = cursor.fetchone()[0]

if not latest_ts:
    print("[INFO] No logs found for anomaly detection.")
    conn.close()
    exit()

latest_dt = datetime.strptime(latest_ts, "%Y-%m-%d %H:%M:%S")
window_start = latest_dt - timedelta(minutes=WINDOW_MINUTES)

# Fetch all IP event counts
cursor.execute("""
SELECT source_ip, COUNT(*)
FROM logs
WHERE timestamp >= ?
GROUP BY source_ip
""", (
    window_start.strftime("%Y-%m-%d %H:%M:%S"),
))

results = cursor.fetchall()

for ip, count in results:
    rep = get_ip_reputation(ip)
    ip_tag = rep["tag"] if rep else "unknown"
    ip_risk = rep["risk"] if rep else "unknown"

    # Dynamic threshold override
    dynamic_threshold = THRESHOLD
    if ip_risk in ("high", "critical"):
        dynamic_threshold = 5  # trigger faster for known bad IPs

    if count < dynamic_threshold:
        continue

    # Dedup
    cursor.execute("""
    SELECT COUNT(*) FROM alerts
    WHERE alert_type = 'Anomalous Activity'
    AND source_ip = ?
    AND detected_at >= ?
    """, (
        ip,
        window_start.strftime("%Y-%m-%d %H:%M:%S")
    ))

    if cursor.fetchone()[0] > 0:
        continue

    cursor.execute("""
    INSERT INTO alerts (
        alert_type, source_ip, event_count,
        time_window, severity, mitre_id, detected_at, ip_tag, ip_risk
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "Anomalous Activity",
        ip,
        count,
        f"{WINDOW_MINUTES} minutes",
        "Medium",
        "T1499",
        latest_dt.strftime("%Y-%m-%d %H:%M:%S"),
        ip_tag,
        ip_risk
    ))

    print(f"[ALERT] Anomalous activity from {ip} (count={count}, threshold={dynamic_threshold}, risk={ip_risk})")

conn.commit()
conn.close()
