import sys
import subprocess
import time

PYTHON = sys.executable

print("\n[+] PORT-SOC Analysis Pipeline Started\n")

steps = [
    ("Parsing logs", [PYTHON, "-m", "collector.parse_and_store"]),
    ("Session pivot enrichment", [PYTHON, "-m", "detection.session_pivot_enricher"]),
    ("Brute force detection", [PYTHON, "-m", "detection.bruteforce_detector"]),
    ("Identity abuse detection", [PYTHON, "-m", "detection.identity_abuse_detector"]),
    ("Low & slow detection", [PYTHON, "-m", "detection.low_slow_detector"]),
    ("Privileged access detection", [PYTHON, "-m", "detection.privileged_access_detector"]),
    ("Suspicious sudo command detection", [PYTHON, "-m", "detection.suspicious_sudo_detector"]),
    ("Security tampering detection", [PYTHON, "-m", "detection.security_tampering_detector"]),
    ("Policy violation detection", [PYTHON, "-m", "detection.policy_violation_detector"]),
    ("Anomaly detection", [PYTHON, "-m", "detection.anomaly_detector"]),
    ("Incident correlation", [PYTHON, "-m", "correlation.incident_correlator"]),
    ("Building raw log integrity hashchain", [PYTHON, "-m", "storage.build_hashchain"]),
]

for name, cmd in steps:
    print(f"[+] {name}...")
    subprocess.run(cmd, check=False)
    time.sleep(0.2)

print("\n[+] Pipeline completed. Alerts updated.\n")
