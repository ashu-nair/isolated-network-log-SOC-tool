import sqlite3
from datetime import datetime
from config.settings import DB_PATH
from feeds.reputation_loader import get_ip_reputation


KEYWORDS = [
    "firewall disabled",
    "antivirus stopped",
    "audit logs cleared",
    "logging service stopped",
    "security service terminated"
]

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
SELECT DISTINCT source_ip
FROM logs
WHERE LOWER(raw_log) LIKE ?
""", ('%' + '%'.join(KEYWORDS) + '%',))

results = cursor.fetchall()

for (ip,) in results:
    rep = get_ip_reputation(ip)
    ip_tag = rep["tag"] if rep else "unknown"
    ip_risk = rep["risk"] if rep else "unknown"

    cursor.execute("""
    INSERT INTO alerts (
        alert_type, source_ip, event_count,
        time_window, severity, mitre_id, detected_at , ip_tag, ip_risk
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "Security Control Tampering",
        ip,
        1,
        "N/A",
        "High",
        "T1562",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip_tag,
        ip_risk
    ))

    print(f"[ALERT] Security control tampering detected from {ip}")

conn.commit()
conn.close()
