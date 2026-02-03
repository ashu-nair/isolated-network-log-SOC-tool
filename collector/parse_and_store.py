from log_parser import parse_log, store_log

LOG_FILE = "storage/raw_logs.log"

with open(LOG_FILE, "r") as f:
    for line in f:
        event = parse_log(line)
        if event:
            store_log(event)

print("[+] Logs parsed and stored successfully")
