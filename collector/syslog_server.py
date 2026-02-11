import socket
import os
from config.settings import RAW_LOG_FILE

SYSLOG_IP = "0.0.0.0"
SYSLOG_PORT = 5514
LOG_FILE = RAW_LOG_FILE

os.makedirs("storage", exist_ok=True)

def start_syslog_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SYSLOG_IP, SYSLOG_PORT))

    print(f"[+] PORT-SOC Syslog Server listening on UDP {SYSLOG_PORT}")
    print(f"[+] Writing raw logs to: {LOG_FILE}")

    while True:
        data, addr = sock.recvfrom(8192)

        message = data.decode(errors="ignore").strip()
        if not message:
            continue

        # Store raw message exactly (do NOT reformat)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(message + "\n")

        print(f"[SYSLOG] {addr[0]} -> {message}")

if __name__ == "__main__":
    start_syslog_server()
