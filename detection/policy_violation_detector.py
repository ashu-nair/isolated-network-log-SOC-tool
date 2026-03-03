import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH
from feeds.reputation_loader import get_ip_reputation

OFF_HOURS_START = 22
OFF_HOURS_END = 6
WINDOW_MINUTES = 60  # one alert per hour per user/IP

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Use latest log timestamp instead of system time
cursor.execute("SELECT MAX(timestamp) FROM logs")
latest_ts = cursor.fetchone()[0]

if not latest_ts:
    print("[INFO] No logs found for policy violation detection.")
    conn.close()
    exit()

latest_dt = datetime.strptime(latest_ts, "%Y-%m-%d %H:%M:%S")
window_start = latest_dt - timedelta(minutes=WINDOW_MINUTES)

cursor.execute("""
SELECT DISTINCT source_ip, username
FROM logs
WHERE username IN ('admin', 'root')
AND timestamp >= ?
""", (window_start.strftime("%Y-%m-%d %H:%M:%S"),))

pairs = cursor.fetchall()

for ip, user in pairs:
    rep = get_ip_reputation(ip)
    ip_tag = rep["tag"] if rep else "unknown"
    ip_risk = rep["risk"] if rep else "unknown"

    # Pull only timestamps inside the window
    cursor.execute("""
    SELECT timestamp
    FROM logs
    WHERE source_ip = ?
    AND username = ?
    AND timestamp >= ?
    ORDER BY timestamp ASC
    """, (ip, user, window_start.strftime("%Y-%m-%d %H:%M:%S")))

    timestamps = cursor.fetchall()

    violation_ts = None

    for (ts,) in timestamps:
        hour = int(ts.split(" ")[1].split(":")[0])
        if hour >= OFF_HOURS_START or hour <= OFF_HOURS_END:
            violation_ts = ts
            break

    if not violation_ts:
        continue

    detected_at = violation_ts  # ✅ real event time

    # Deduplication check (same alert for same IP at same detected time)
    cursor.execute("""
    SELECT COUNT(*)
    FROM alerts
    WHERE alert_type = 'Policy Violation: Off-Hours Privileged Access'
    AND source_ip = ?
    AND detected_at = ?
    """, (ip, detected_at))

    if cursor.fetchone()[0] > 0:
        continue

    cursor.execute("""
    INSERT INTO alerts (
        alert_type, source_ip, event_count,
        time_window, severity, mitre_id,
        detected_at, ip_tag, ip_risk
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "Policy Violation: Off-Hours Privileged Access",
        ip,
        len(timestamps),
        "Off-hours",
        "Medium",
        "T1078",
        detected_at,
        ip_tag,
        ip_risk
    ))

    print(f"[ALERT] Policy violation by {user} from {ip}")

conn.commit()
conn.close()
