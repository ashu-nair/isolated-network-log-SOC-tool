import os
from config.settings import RAW_LOG_FILE

# Ubuntu log sources
LOG_SOURCES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/ufw.log",
]

OFFSET_DIR = "storage/local_offsets"

# On first run, only take last N lines (avoid huge backfill)
FIRST_RUN_TAIL_LINES = 2000


def tail_lines(path, n=2000):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            return lines[-n:]
    except Exception:
        return []


def collect_from_file(path):
    os.makedirs(OFFSET_DIR, exist_ok=True)

    safe_name = path.replace("/", "_").replace("\\", "_")
    offset_file = os.path.join(OFFSET_DIR, safe_name + ".offset")

    if not os.path.exists(path):
        return 0, 0

    # If first run, do tail import
    if not os.path.exists(offset_file):
        lines = tail_lines(path, FIRST_RUN_TAIL_LINES)

        with open(RAW_LOG_FILE, "a", encoding="utf-8") as out:
            for line in lines:
                line = line.strip()
                if line:
                    out.write(line + "\n")

        # set offset to EOF
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            eof = f.tell()

        with open(offset_file, "w") as off:
            off.write(str(eof))

        return len(lines), len(lines)

    # Normal mode: read only new lines
    try:
        with open(offset_file, "r") as off:
            offset = int(off.read().strip() or 0)
    except:
        offset = 0

    processed = 0
    stored = 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(offset)

        new_lines = f.readlines()
        new_offset = f.tell()

    with open(offset_file, "w") as off:
        off.write(str(new_offset))

    if not new_lines:
        return 0, 0

    with open(RAW_LOG_FILE, "a", encoding="utf-8") as out:
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            processed += 1
            out.write(line + "\n")
            stored += 1

    return processed, stored


def run_local_collection():
    print("[+] Local Ubuntu Log Collector started\n")

    total_processed = 0
    total_stored = 0

    for src in LOG_SOURCES:
        p, s = collect_from_file(src)
        if p > 0:
            print(f"[+] Collected from {src}: {s} new lines")
        total_processed += p
        total_stored += s

    print(f"\n[+] Local collection complete. Stored {total_stored} lines into raw_logs.log")


if __name__ == "__main__":
    run_local_collection()
