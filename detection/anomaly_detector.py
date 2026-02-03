import sqlite3
from datetime import datetime, timedelta

DB_PATH = "storage/portsoc.db"

THRESHOLD = 20
WINDOW_MINUTES = 1

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

window_start = datetime.now() - timedelta(minutes=WINDOW_MINUTES)

cursor.execute("""
SELECT source_ip, COUNT(*)
FROM logs
WHERE timestamp >= ?
GROUP BY source_ip
HAVING COUNT(*) >= ?
""", (window_start.strftime("%Y-%m-%d %H:%M:%S"), THRESHOLD))

for ip, count in cursor.fetchall():
    cursor.execute("""
    INSERT INTO alerts (alert_type, source_ip, event_count, time_window, severity, mitre_id, detected_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        "Anomalous Activity Detected",
        ip,
        count,
        f"{WINDOW_MINUTES} minutes",
        "Medium",
        "T1046",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    print(f"[ALERT] Anomalous activity from {ip}")

conn.commit()
conn.close()
