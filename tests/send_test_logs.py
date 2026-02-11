import socket
import time

SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 5514

TEST_LOGS = [
    # --- Brute force + identity abuse ---
    "Failed password for invalid user admin from 10.0.0.5 port 111 ssh2",
    "Failed password for invalid user support from 10.0.0.5 port 111 ssh2",
    "Failed password for invalid user guest from 10.0.0.5 port 111 ssh2",
    "Failed password for root from 192.168.1.105 port 111 ssh2",
    "Failed password for root from 192.168.1.105 port 111 ssh2",
    "Failed password for root from 192.168.1.105 port 111 ssh2",
    "Failed password for root from 192.168.1.105 port 111 ssh2",

    # --- Privileged access ---
    "sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/apt-get update",

    # --- Suspicious sudo ---
    "sudo: jdoe : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/python3 -c import os; os.setuid(0); os.system('/bin/bash')",

    # --- Security tampering ---
    "Firewall disabled by administrator from 192.168.1.200",

    # --- Policy violation ---
    "Policy violation: root accessed restricted file /etc/shadow from 192.168.1.105",
]

# Add anomaly spam (same IP many times)
for _ in range(15):
    TEST_LOGS.append("Random activity from 10.0.0.5")


def send_logs():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for log in TEST_LOGS:
        s.sendto(log.encode(), (SYSLOG_HOST, SYSLOG_PORT))
        time.sleep(0.05)

    print(f"[+] Sent {len(TEST_LOGS)} logs to syslog server")


if __name__ == "__main__":
    send_logs()
