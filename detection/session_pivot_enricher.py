import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH

WINDOW_MINUTES = 30

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("SELECT MAX(timestamp) FROM logs")
latest_ts = cursor.fetchone()[0]

if not latest_ts:
    print("[INFO] No logs found for session pivot.")
    conn.close()
    exit()

latest_dt = datetime.strptime(latest_ts, "%Y-%m-%d %H:%M:%S")
window_start = latest_dt - timedelta(minutes=WINDOW_MINUTES)

# Step 1: Build mapping of username -> last known login IP
cursor.execute("""
SELECT username, source_ip, timestamp
FROM logs
WHERE event_type = 'AUTH_SUCCESS'
AND timestamp >= ?
ORDER BY timestamp DESC
""", (window_start.strftime("%Y-%m-%d %H:%M:%S"),))

rows = cursor.fetchall()

user_to_ip = {}
for user, ip, ts in rows:
    if user and user != "UNKNOWN" and ip not in ("LOCAL_HOST", "UNKNOWN"):
        if user not in user_to_ip:
            user_to_ip[user] = ip

if not user_to_ip:
    print("[INFO] No AUTH_SUCCESS logs found for session pivot.")
    conn.close()
    exit()

# Step 2: Update LOCAL_HOST logs based on username
updated = 0

for user, ip in user_to_ip.items():
    cursor.execute("""
    UPDATE logs
    SET source_ip = ?
    WHERE source_ip = 'LOCAL_HOST'
    AND username = ?
    AND timestamp >= ?
    """, (
        ip,
        user,
        window_start.strftime("%Y-%m-%d %H:%M:%S")
    ))
    updated += cursor.rowcount

conn.commit()
conn.close()

print(f"[+] Session pivot enrichment done. Updated {updated} LOCAL_HOST log rows.")
