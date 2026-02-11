import csv
import os

FEED_PATH = "feeds/ip_reputation.csv"

def load_ip_reputation():
    reputation = {}

    if not os.path.exists(FEED_PATH):
        return reputation

    with open(FEED_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("ip", "").strip()
            if not ip:
                continue

            reputation[ip] = {
                "tag": row.get("tag", "unknown").strip(),
                "risk": row.get("risk", "unknown").strip(),
                "notes": row.get("notes", "").strip()
            }

    return reputation


def get_ip_reputation(ip: str):
    rep = load_ip_reputation()
    return rep.get(ip, None)
