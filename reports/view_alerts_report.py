import sqlite3

DB_PATH = "storage/portsoc.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print("\n========== PORT-SOC ALERT REPORT ==========\n")

rows = cursor.execute("""
SELECT detected_at, alert_type, source_ip, severity, mitre_id, event_count, time_window
FROM alerts
ORDER BY detected_at DESC
""").fetchall()

if not rows:
    print("No alerts found.")
else:
    for r in rows:
        print(f"""
Time       : {r[0]}
Attack     : {r[1]}
Source IP  : {r[2]}
Severity   : {r[3]}
MITRE ID   : {r[4]}
Count      : {r[5]}
Window     : {r[6]}
-------------------------------------------
""")

conn.close()
