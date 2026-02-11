import os
from collector.log_parser import parse_log, store_logs_batch
from config.settings import RAW_LOG_FILE, OFFSET_FILE

LOG_FILE = RAW_LOG_FILE


def parse_new_logs():
    if not os.path.exists(LOG_FILE):
        print("[INFO] Raw log file not found yet.")
        return

    # read last offset
    offset = 0
    if os.path.exists(OFFSET_FILE):
        try:
            with open(OFFSET_FILE, "r") as f:
                offset = int(f.read().strip() or 0)
        except:
            offset = 0

    events = []
    processed = 0

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(offset)

        for line in f:
            line = line.strip()
            if not line:
                continue

            processed += 1
            parsed = parse_log(line)
            if parsed:
                events.append(parsed)

        new_offset = f.tell()

    # Save offset
    with open(OFFSET_FILE, "w") as f:
        f.write(str(new_offset))

    if events:
        store_logs_batch(events)

    print(f"[+] Parsed {processed} new raw lines")
    print(f"[+] Stored {len(events)} structured logs")


if __name__ == "__main__":
    parse_new_logs()
