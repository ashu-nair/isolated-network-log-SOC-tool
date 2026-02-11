import sqlite3
from datetime import datetime
from config.settings import DB_PATH
from feeds.reputation_loader import get_ip_reputation


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
    rep = get_ip_reputation(ip)
    ip_tag = rep["tag"] if rep else "unknown"
    ip_risk = rep["risk"] if rep else "unknown"

    cursor.execute("""
    INSERT INTO alerts (alert_type, source_ip, event_count, time_window, severity, mitre_id, detected_at, ip_tag, ip_risk)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "Privileged Account Access Attempt",
        ip,
        count,
        "N/A",
        "Medium",
        "T1078",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip_tag,
        ip_risk
    ))

    print(f"[ALERT] Privileged access attempt on {user} from {ip}")

conn.commit()
conn.close()
