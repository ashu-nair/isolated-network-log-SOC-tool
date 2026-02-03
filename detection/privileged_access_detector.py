import sqlite3
from datetime import datetime

DB_PATH = "storage/portsoc.db"
PRIV_USERS = ("root", "admin")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
SELECT source_ip, username, COUNT(*)
FROM logs
WHERE username IN ('root', 'admin')
AND event_type = 'AUTH_FAIL'
GROUP BY source_ip, username
""")

for ip, user, count in cursor.fetchall():
    cursor.execute("""
    INSERT INTO alerts (alert_type, source_ip, event_count, time_window, severity, mitre_id, detected_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        "Privileged Account Access Attempt",
        ip,
        count,
        "N/A",
        "Medium",
        "T1078",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    print(f"[ALERT] Privileged access attempt on {user} from {ip}")

conn.commit()
conn.close()
