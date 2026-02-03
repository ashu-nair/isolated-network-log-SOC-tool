import socket
import datetime
import os

SYSLOG_IP = "0.0.0.0"
SYSLOG_PORT = 5514   # Windows-safe syslog port
LOG_FILE = "storage/raw_logs.log"

os.makedirs("storage", exist_ok=True)

def classify_log(message):
    msg = message.lower()
    if "failed password" in msg:
        return "AUTH_FAIL"
    elif "accepted password" in msg:
        return "AUTH_SUCCESS"
    elif "ssh" in msg:
        return "SSH"
    elif "firewall" in msg:
        return "FIREWALL"
    else:
        return "GENERAL"

def start_syslog_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SYSLOG_IP, SYSLOG_PORT))

    print(f"[+] PORT-SOC Syslog Server listening on UDP {SYSLOG_PORT}")

    while True:
        data, addr = sock.recvfrom(4096)
        message = data.decode(errors="ignore").strip()

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        source_ip = addr[0]
        log_type = classify_log(message)

        log_entry = f"{timestamp} | {source_ip} | {log_type} | {message}\n"

        with open(LOG_FILE, "a") as f:
            f.write(log_entry)

        print(log_entry.strip())

if __name__ == "__main__":
    start_syslog_server()
