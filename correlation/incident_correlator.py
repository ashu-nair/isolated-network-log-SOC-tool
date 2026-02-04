import sqlite3
from datetime import datetime, timedelta

DB_PATH = "storage/portsoc.db"
WINDOW_MINUTES = 60

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

now = datetime.now()
window_start = now - timedelta(minutes=WINDOW_MINUTES)

# Get recent alerts
cursor.execute("""
SELECT source_ip, alert_type, mitre_id, severity, detected_at
FROM alerts
WHERE detected_at >= ?
ORDER BY detected_at ASC
""", (window_start.strftime("%Y-%m-%d %H:%M:%S"),))

alerts = cursor.fetchall()

if not alerts:
    print("[+] No alerts to correlate")
    conn.close()
    exit()

grouped = {}

for ip, alert, mitre, severity, ts in alerts:
    grouped.setdefault(ip, []).append((alert, mitre, severity, ts))

for ip, items in grouped.items():
    if len(items) < 2:
        continue  # single alert ≠ incident

    techniques = sorted(set(i[1] for i in items))
    severities = [i[2] for i in items]

    incident_severity = "High" if "High" in severities else "Medium"

    start_time = items[0][3]
    end_time = items[-1][3]

    cursor.execute("""
    INSERT INTO incidents (
        incident_type, source_ip, techniques,
        severity, alert_count,
        start_time, end_time, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "Correlated Security Incident",
        ip,
        ", ".join(techniques),
        incident_severity,
        len(items),
        start_time,
        end_time,
        now.strftime("%Y-%m-%d %H:%M:%S")
    ))

    print(f"[INCIDENT] Correlated incident created for {ip}")

conn.commit()
conn.close()
