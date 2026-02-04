import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH


USER_THRESHOLD = 5
WINDOW_MINUTES = 10

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

now = datetime.now()
window_start = now - timedelta(minutes=WINDOW_MINUTES)

cursor.execute("""
SELECT source_ip, COUNT(DISTINCT username)
FROM logs
WHERE event_type = 'AUTH_FAIL'
AND timestamp >= ?
GROUP BY source_ip
HAVING COUNT(DISTINCT username) >= ?
""", (
    window_start.strftime("%Y-%m-%d %H:%M:%S"),
    USER_THRESHOLD
))

results = cursor.fetchall()

for ip, user_count in results:
    cursor.execute("""
    INSERT INTO alerts (
        alert_type, source_ip, event_count,
        time_window, severity, mitre_id, detected_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        "Password Spraying / Identity Abuse",
        ip,
        user_count,
        f"{WINDOW_MINUTES} minutes",
        "High",
        "T1110.003",
        now.strftime("%Y-%m-%d %H:%M:%S")
    ))

    print(f"[ALERT] Identity abuse detected from {ip}")

conn.commit()
conn.close()
