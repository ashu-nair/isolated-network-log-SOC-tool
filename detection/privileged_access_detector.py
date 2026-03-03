import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH
from feeds.reputation_loader import get_ip_reputation

WINDOW_MINUTES = 60
PRIV_USERS = ("root", "admin")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Use latest log timestamp instead of system time
cursor.execute("SELECT MAX(timestamp) FROM logs")
latest_ts = cursor.fetchone()[0]

if not latest_ts:
    print("[INFO] No logs found for privileged access detection.")
    conn.close()
    exit()

latest_dt = datetime.strptime(latest_ts, "%Y-%m-%d %H:%M:%S")
window_start = latest_dt - timedelta(minutes=WINDOW_MINUTES)

# Count failed attempts against privileged usernames in the window
cursor.execute("""
SELECT source_ip, username, COUNT(*)
FROM logs
WHERE username IN ('root', 'admin')
AND event_type IN ('AUTH_FAIL', 'AUTH_FAIL_INVALID_USER')
AND timestamp >= ?
GROUP BY source_ip, username
""", (window_start.strftime("%Y-%m-%d %H:%M:%S"),))

results = cursor.fetchall()

for ip, user, count in results:

    # Real event timestamp = latest failed attempt inside the window
    cursor.execute("""
    SELECT MAX(timestamp)
    FROM logs
    WHERE source_ip = ?
    AND username = ?
    AND event_type IN ('AUTH_FAIL', 'AUTH_FAIL_INVALID_USER')
    AND timestamp >= ?
    """, (ip, user, window_start.strftime("%Y-%m-%d %H:%M:%S")))

    detected_at = cursor.fetchone()[0]

    if not detected_at:
        continue

    # Dedup
    cursor.execute("""
    SELECT COUNT(*) FROM alerts
    WHERE alert_type = 'Privileged Account Access Attempt'
    AND source_ip = ?
    AND detected_at = ?
    """, (ip, detected_at))

    if cursor.fetchone()[0] > 0:
        continue

    rep = get_ip_reputation(ip)
    ip_tag = rep["tag"] if rep else "unknown"
    ip_risk = rep["risk"] if rep else "unknown"

    cursor.execute("""
    INSERT INTO alerts (
        alert_type, source_ip, event_count,
        time_window, severity, mitre_id,
        detected_at, ip_tag, ip_risk
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "Privileged Account Access Attempt",
        ip,
        count,
        f"{WINDOW_MINUTES} minutes",
        "Medium",
        "T1078",
        detected_at,
        ip_tag,
        ip_risk
    ))

    print(f"[ALERT] Privileged access attempt on {user} from {ip}")

conn.commit()
conn.close()
