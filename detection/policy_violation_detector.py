import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH


OFF_HOURS_START = 22
OFF_HOURS_END = 6
WINDOW_MINUTES = 60  # one alert per hour per user/IP

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

now = datetime.now()
window_start = now - timedelta(minutes=WINDOW_MINUTES)

cursor.execute("""
SELECT DISTINCT source_ip, username
FROM logs
WHERE username IN ('admin', 'root')
AND timestamp >= ?
""", (window_start.strftime("%Y-%m-%d %H:%M:%S"),))

for ip, user in cursor.fetchall():
    # Check time condition separately
    cursor.execute("""
    SELECT timestamp FROM logs
    WHERE source_ip = ? AND username = ?
    """, (ip, user))

    timestamps = cursor.fetchall()
    violation = False

    for (ts,) in timestamps:
        hour = int(ts.split(" ")[1].split(":")[0])
        if hour >= OFF_HOURS_START or hour <= OFF_HOURS_END:
            violation = True
            break

    if not violation:
        continue

    # Deduplication check
    cursor.execute("""
    SELECT COUNT(*) FROM alerts
    WHERE alert_type = 'Policy Violation: Off-Hours Privileged Access'
    AND source_ip = ?
    AND detected_at >= ?
    """, (
        ip,
        window_start.strftime("%Y-%m-%d %H:%M:%S")
    ))

    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO alerts (
            alert_type, source_ip, event_count,
            time_window, severity, mitre_id, detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "Policy Violation: Off-Hours Privileged Access",
            ip,
            len(timestamps),
            "Off-hours",
            "Medium",
            "T1078",
            now.strftime("%Y-%m-%d %H:%M:%S")
        ))

        print(f"[ALERT] Policy violation by {user} from {ip}")

conn.commit()
conn.close()
