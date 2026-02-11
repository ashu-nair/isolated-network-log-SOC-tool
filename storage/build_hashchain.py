import hashlib
import os
from config.settings import RAW_LOG_FILE, RAW_LOG_HASH_FILE


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def build_hashchain():
    if not os.path.exists(RAW_LOG_FILE):
        print("[INFO] Raw log file not found.")
        return

    prev_hash = "0" * 64
    count = 0

    with open(RAW_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f_in, \
         open(RAW_LOG_HASH_FILE, "w", encoding="utf-8") as f_out:

        for line in f_in:
            line = line.strip()
            if not line:
                continue

            current_hash = sha256(prev_hash + line)
            f_out.write(current_hash + "\n")

            prev_hash = current_hash
            count += 1

    print(f"[+] Hashchain generated for {count} raw log lines.")
    print(f"[+] Saved to: {RAW_LOG_HASH_FILE}")


if __name__ == "__main__":
    build_hashchain()
