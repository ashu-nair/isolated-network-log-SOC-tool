import sqlite3
from config.settings import DB_PATH

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("DELETE FROM logs")
cur.execute("DELETE FROM alerts")
cur.execute("DELETE FROM incidents")

conn.commit()
conn.close()

print("[+] Database tables cleared (logs, alerts, incidents).")
