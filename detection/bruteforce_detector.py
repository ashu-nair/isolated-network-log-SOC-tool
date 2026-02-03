import sqlite3
from datetime import datetime, timedelta

DB_PATH = "storage/portsoc.db"

THRESHOLD = 5
WINDOW_MINUTES = 2

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

now = datetime.now()
window_start = now - timedelta(minutes=WINDOW_MINUTES)

# Step 1: Find suspicious IPs
cursor.execute("""
SELECT source_ip, COUNT(*) 
FROM logs
WHERE event_type = 'AUTH_FAIL'
AND timestamp >= ?
GROUP BY source_ip
HAVING COUNT(*) >= ?
""", (
    window_start.strftime("%Y-%m-%d %H:%M:%S"),
    THRESHOLD
))

results = cursor.fetchall()

# Step 2: For each IP, check if alert already exists
for ip, count in results:

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
            time_window, severity, mitre_id, detected_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "Brute Force Attack",
            ip,
            count,
            f"{WINDOW_MINUTES} minutes",
            "High",
            "T1110",
            now.strftime("%Y-%m-%d %H:%M:%S")
        ))

        print(f"[ALERT] Brute Force detected from {ip}")

    else:
        print(f"[INFO] Brute Force alert already exists for {ip}")

conn.commit()
conn.close()
