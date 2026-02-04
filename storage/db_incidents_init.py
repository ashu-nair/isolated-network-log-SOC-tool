import sqlite3

conn = sqlite3.connect("storage/portsoc.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_type TEXT,
    source_ip TEXT,
    techniques TEXT,
    severity TEXT,
    alert_count INTEGER,
    start_time TEXT,
    end_time TEXT,
    created_at TEXT
)
""")

conn.commit()
conn.close()

print("[+] Incidents table initialized")
