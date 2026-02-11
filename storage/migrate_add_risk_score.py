import sqlite3
from config.settings import DB_PATH

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

def add_column(table, col, coltype):
    try:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}")
        print(f"[+] Added {col} to {table}")
    except Exception:
        print(f"[i] Column {col} already exists in {table}")

add_column("incidents", "risk_score", "INTEGER")
add_column("incidents", "severity", "TEXT")

conn.commit()
conn.close()

print("[+] Migration done")
