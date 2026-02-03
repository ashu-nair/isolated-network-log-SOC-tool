import sqlite3

conn = sqlite3.connect("storage/portsoc.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    event_type TEXT,
    username TEXT,
    raw_log TEXT
)
""")

conn.commit()
conn.close()

print("[+] Database initialized successfully")
