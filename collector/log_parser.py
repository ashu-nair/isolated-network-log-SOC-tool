import re
import sqlite3

DB_PATH = "storage/portsoc.db"

def parse_log(line):
    """
    Input format:
    timestamp | source_ip | log_type | message
    """

    try:
        parts = line.strip().split(" | ")
        timestamp, source_ip, log_type, message = parts

        username = None
        ip_match = re.search(r'from ([0-9.]+)', message)
        user_match = re.search(r'for (\w+)', message)

        if user_match:
            username = user_match.group(1)

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "event_type": log_type,
            "username": username,
            "raw_log": message
        }

    except Exception:
        return None

def store_log(event):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO logs (timestamp, source_ip, event_type, username, raw_log)
        VALUES (?, ?, ?, ?, ?)
    """, (
        event["timestamp"],
        event["source_ip"],
        event["event_type"],
        event["username"],
        event["raw_log"]
    ))

    conn.commit()
    conn.close()
