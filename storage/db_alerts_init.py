import sqlite3

conn = sqlite3.connect("storage/portsoc.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT,
    source_ip TEXT,
    event_count INTEGER,
    time_window TEXT,
    severity TEXT,
    mitre_id TEXT,
    detected_at TEXT
)
""")

conn.commit()
conn.close()

print("[+] Alerts table initialized")
