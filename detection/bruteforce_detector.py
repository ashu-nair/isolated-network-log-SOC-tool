import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH
from feeds.reputation_loader import get_ip_reputation


THRESHOLD = 5
WINDOW_MINUTES = 2

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Use latest log timestamp instead of system time
cursor.execute("SELECT MAX(timestamp) FROM logs")
latest_ts = cursor.fetchone()[0]

if not latest_ts:
    print("[INFO] No logs found for brute force detection.")
    conn.close()
    exit()

latest_dt = datetime.strptime(latest_ts, "%Y-%m-%d %H:%M:%S")
window_start = latest_dt - timedelta(minutes=WINDOW_MINUTES)

cursor.execute("""
SELECT source_ip, COUNT(*) 
FROM logs
WHERE event_type IN ('AUTH_FAIL', 'AUTH_FAIL_INVALID_USER')
AND timestamp >= ?
GROUP BY source_ip
""", (
    window_start.strftime("%Y-%m-%d %H:%M:%S"),
))


results = cursor.fetchall()

for ip, count in results:
    rep = get_ip_reputation(ip)

    dynamic_threshold = THRESHOLD
    if rep and rep.get("risk") in ("high", "critical"):
        dynamic_threshold = 1

    if count < dynamic_threshold:
        continue

    rep = get_ip_reputation(ip)
    ip_tag = rep["tag"] if rep else "unknown"
    ip_risk = rep["risk"] if rep else "unknown"
    cursor.execute("""
    SELECT MAX(timestamp)
    FROM logs
    WHERE source_ip = ?
    AND timestamp >= ?
    AND event_type IN ('AUTH_FAIL', 'AUTH_FAIL_INVALID_USER')
    """, (ip, window_start.strftime("%Y-%m-%d %H:%M:%S")))

    ip_latest_ts = cursor.fetchone()[0]
    detected_at = ip_latest_ts if ip_latest_ts else latest_dt.strftime("%Y-%m-%d %H:%M:%S")


    cursor.execute("""
    SELECT COUNT(*) FROM alerts
    WHERE alert_type = 'Brute Force Attack'
    AND source_ip = ?
    AND detected_at >= ?
    """, (
        ip,
        window_start.strftime("%Y-%m-%d %H:%M:%S")
    ))

    already_exists = cursor.fetchone()[0]

    if already_exists == 0:
        cursor.execute("""
        INSERT INTO alerts (
            alert_type, source_ip, event_count,
            time_window, severity, mitre_id, detected_at, ip_tag, ip_risk
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "Brute Force Attack",
            ip,
            count,
            f"{WINDOW_MINUTES} minutes",
            "High",
            "T1110",
            detected_at,
            ip_tag,
            ip_risk
        ))

        print(f"[ALERT] Brute Force detected from {ip}")

conn.commit()
conn.close()
