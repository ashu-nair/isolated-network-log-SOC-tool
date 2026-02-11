import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH
from feeds.reputation_loader import get_ip_reputation


WINDOW_MINUTES = 60

SUSPICIOUS_KEYWORDS = [
    "/etc/shadow",
    "find / -perm -4000",
    "python3 -c",
    "python -c",
    "os.setuid",
    "/bin/bash",
    "bash -i",
    "nc -e",
    "curl | bash",
    "wget | bash"
]

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
SELECT source_ip, username, raw_log, timestamp
FROM logs
WHERE event_type = 'PRIV_ACCESS'
AND timestamp >= ?
""", (window_start.strftime("%Y-%m-%d %H:%M:%S"),))

rows = cursor.fetchall()

for ip, user, raw, ts in rows:
    raw_lower = raw.lower()
    rep = get_ip_reputation(ip)
    ip_tag = rep["tag"] if rep else "unknown"
    ip_risk = rep["risk"] if rep else "unknown"

    if any(k.lower() in raw_lower for k in SUSPICIOUS_KEYWORDS):
        # Dedup: avoid spamming same alert repeatedly
        cursor.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE alert_type = 'Suspicious Privileged Command Execution'
        AND source_ip = ?
        AND detected_at >= ?
        """, (ip, window_start.strftime("%Y-%m-%d %H:%M:%S")))

        if cursor.fetchone()[0] > 0:
            continue

        cursor.execute("""
        INSERT INTO alerts (
            alert_type, source_ip, event_count,
            time_window, severity, mitre_id, detected_at , ip_tag, ip_risk
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "Suspicious Privileged Command Execution",
            ip,
            1,
            f"{WINDOW_MINUTES} minutes",
            "High",
            "T1059",
            latest_dt.strftime("%Y-%m-%d %H:%M:%S"),
            ip_tag,
            ip_risk
        ))

        print(f"[ALERT] Suspicious sudo command by {user} from {ip}")
        break

conn.commit()
conn.close()
