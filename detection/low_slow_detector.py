import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH
from feeds.reputation_loader import get_ip_reputation

WINDOW_HOURS = 24
THRESHOLD = 10   # total failures in 24 hours


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Use latest timestamp in logs as reference
cursor.execute("SELECT MAX(timestamp) FROM logs")
latest_ts = cursor.fetchone()[0]

if not latest_ts:
    print("[INFO] No logs found for low & slow detection.")
    conn.close()
    exit()

latest_dt = datetime.strptime(latest_ts, "%Y-%m-%d %H:%M:%S")
window_start = latest_dt - timedelta(hours=WINDOW_HOURS)

cursor.execute("""
SELECT source_ip, COUNT(*)
FROM logs
WHERE event_type IN ('AUTH_FAIL', 'AUTH_FAIL_INVALID_USER')
AND timestamp >= ?
GROUP BY source_ip
""", (window_start.strftime("%Y-%m-%d %H:%M:%S"),))

results = cursor.fetchall()

for ip, count in results:
    if count < THRESHOLD:
        continue

    rep = get_ip_reputation(ip)
    ip_tag = rep["tag"] if rep else "unknown"
    ip_risk = rep["risk"] if rep else "unknown"

    # Dedup: do not repeat same alert for same window
    cursor.execute("""
    SELECT COUNT(*) FROM alerts
    WHERE alert_type = 'Targeted Password Spray (Low & Slow)'
    AND source_ip = ?
    AND detected_at >= ?
    """, (
        ip,
        window_start.strftime("%Y-%m-%d %H:%M:%S")
    ))

    if cursor.fetchone()[0] > 0:
        continue

    # Severity based on risk + volume
    severity = "Medium"
    if count >= 20:
        severity = "High"
    if ip_risk in ("high", "critical"):
        severity = "High"

    cursor.execute("""
    INSERT INTO alerts (
        alert_type, source_ip, event_count,
        time_window, severity, mitre_id, detected_at,
        ip_tag, ip_risk
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "Targeted Password Spray (Low & Slow)",
        ip,
        count,
        f"{WINDOW_HOURS} hours",
        severity,
        "T1110",
        latest_dt.strftime("%Y-%m-%d %H:%M:%S"),
        ip_tag,
        ip_risk
    ))

    print(f"[ALERT] Low & slow password spray detected from {ip} (count={count} in {WINDOW_HOURS}h)")

conn.commit()
conn.close()
