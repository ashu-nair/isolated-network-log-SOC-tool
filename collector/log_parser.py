import re
import sqlite3
from datetime import datetime
from config.settings import DB_PATH


# ----------------------------
# Helpers
# ----------------------------

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def extract_ip(text):
    # Prefer IP after "from X"
    m = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", text)
    if m:
        return m.group(1)

    # Fallback: any IPv4
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
    if m:
        return m.group(1)

    # Note: sudo logs often don't have IP
    return "LOCAL_HOST"



def parse_syslog_timestamp(raw_log):
    # Supports: "Feb 04 22:10:17 ..."
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+", raw_log)
    if not m:
        return None

    month, day, time_part = m.groups()
    year = datetime.now().year
    try:
        dt = datetime.strptime(f"{year} {month} {day} {time_part}", "%Y %b %d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return None


# ----------------------------
# Specific Parsers (plugins)
# ----------------------------

def parse_linux_ssh(raw_log):
    low = raw_log.lower()

    # Accept multiple SSH indicators (real-world tolerant)
    ssh_indicators = ["sshd", "openssh", "pam_unix(sshd"]
    if not any(x in low for x in ssh_indicators):
        # Still allow matching if log contains classic SSH phrases
        if "failed password" not in low and "accepted password" not in low and "invalid user" not in low:
            return None

    # Failed password (invalid user)
    if "failed password" in low and "invalid user" in low:
        user_match = re.search(r"failed password for invalid user (\w+)", raw_log, re.IGNORECASE)
        user = user_match.group(1) if user_match else "UNKNOWN"
        return ("AUTH_FAIL_INVALID_USER", user)

    # Invalid user (sometimes comes without "Failed password")
    if "invalid user" in low:
        user_match = re.search(r"invalid user (\w+)", raw_log, re.IGNORECASE)
        user = user_match.group(1) if user_match else "UNKNOWN"
        return ("AUTH_FAIL_INVALID_USER", user)

    # Failed password (valid user)
    if "failed password" in low:
        user_match = re.search(r"failed password for (\w+)", raw_log, re.IGNORECASE)
        user = user_match.group(1) if user_match else "UNKNOWN"
        return ("AUTH_FAIL", user)

    # Accepted password
    if "accepted password" in low:
        user_match = re.search(r"accepted password for (\w+)", raw_log, re.IGNORECASE)
        user = user_match.group(1) if user_match else "UNKNOWN"
        return ("AUTH_SUCCESS", user)

    return None

def parse_linux_sudo(raw_log):
    if "sudo:" not in raw_log:
        return None

    # Example:
    # sudo: jdoe : ... USER=root ; COMMAND=/usr/bin/cat /etc/shadow
    if "USER=root" in raw_log:
        user_match = re.search(r"sudo:\s+(\w+)\s+:", raw_log)
        user = user_match.group(1) if user_match else "UNKNOWN"
        return ("PRIV_ACCESS", user)

    # sudo auth failure
    if "authentication failure" in raw_log.lower():
        user_match = re.search(r"user=(\w+)", raw_log)
        user = user_match.group(1) if user_match else "UNKNOWN"
        return ("AUTH_FAIL", user)

    return None


def parse_security_tampering(raw_log):
    low = raw_log.lower()
    keywords = [
        "firewall disabled",
        "antivirus stopped",
        "audit logs cleared",
        "logging service stopped",
        "windows defender disabled",
        "security service terminated"
    ]

    if any(k in low for k in keywords):
        return ("SEC_TAMPER", "SYSTEM")

    return None


# ----------------------------
# Master Normalizer
# ----------------------------

def parse_log(raw_log: str):
    raw_log = raw_log.strip()
    if not raw_log:
        return None

    event = {
        "timestamp": now_ts(),
        "source_ip": extract_ip(raw_log),
        "event_type": "OTHER",
        "username": "UNKNOWN",
        "raw_log": raw_log
    }

    # Try to parse syslog timestamp if present
    ts = parse_syslog_timestamp(raw_log)
    if ts:
        event["timestamp"] = ts

    # Apply parsers in priority order
    for parser in (parse_security_tampering, parse_linux_sudo, parse_linux_ssh):
        result = parser(raw_log)
        if result:
            event_type, username = result
            event["event_type"] = event_type
            event["username"] = username
            return event

    # Fallback: keep OTHER, but still store IP + timestamp + raw_log
    return event


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
def store_logs_batch(events):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.executemany("""
        INSERT INTO logs (timestamp, source_ip, event_type, username, raw_log)
        VALUES (?, ?, ?, ?, ?)
    """, [
        (
            e["timestamp"],
            e["source_ip"],
            e["event_type"],
            e["username"],
            e["raw_log"]
        )
        for e in events
    ])

    conn.commit()
    conn.close()
