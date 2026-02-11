import os
from collector.log_parser import parse_log, store_logs_batch

IMPORT_FOLDER = "storage/import"


def import_logs_from_folder():
    if not os.path.exists(IMPORT_FOLDER):
        print(f"[!] Import folder not found: {IMPORT_FOLDER}")
        os.makedirs(IMPORT_FOLDER)
        print("[+] Import folder created. Add logs and rerun.")
        return

    files = [f for f in os.listdir(IMPORT_FOLDER) if f.endswith((".log", ".txt"))]

    if not files:
        print("[+] No log files found in storage/import/")
        return

    total = 0
    stored = 0

    print(f"[+] Importing logs from {IMPORT_FOLDER}\n")

    for file in files:
        path = os.path.join(IMPORT_FOLDER, file)
        print(f"[+] Processing {file}")

        events = []

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    total += 1
                    parsed = parse_log(line)

                    if parsed:
                        events.append(parsed)

            if events:
                store_logs_batch(events)
                stored += len(events)

        except Exception as e:
            print(f"[!] Error reading {file}: {e}")

    print("\n[+] Offline import complete")
    print(f"[+] Lines processed: {total}")
    print(f"[+] Logs stored: {stored}")


if __name__ == "__main__":
    import_logs_from_folder()
