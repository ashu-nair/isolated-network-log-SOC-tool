import hashlib
import os
from config.settings import RAW_LOG_FILE, RAW_LOG_HASH_FILE


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def verify_hashchain():
    if not os.path.exists(RAW_LOG_FILE):
        print("[INFO] Raw log file not found.")
        return

    if not os.path.exists(RAW_LOG_HASH_FILE):
        print("[INFO] Hashchain file not found. Build it first.")
        return

    prev_hash = "0" * 64
    line_num = 0

    with open(RAW_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f_logs, \
         open(RAW_LOG_HASH_FILE, "r", encoding="utf-8", errors="ignore") as f_hash:

        for log_line, stored_hash in zip(f_logs, f_hash):
            log_line = log_line.strip()
            stored_hash = stored_hash.strip()

            if not log_line:
                continue

            expected = sha256(prev_hash + log_line)
            line_num += 1

            if expected != stored_hash:
                print(f"[FAIL] Integrity check failed at line {line_num}")
                print(f"Expected: {expected}")
                print(f"Stored:   {stored_hash}")
                return

            prev_hash = expected

    print(f"[PASS] Raw log integrity verified ({line_num} lines).")


if __name__ == "__main__":
    verify_hashchain()
