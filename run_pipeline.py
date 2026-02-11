import os
import time

print("\n[+] PORT-SOC Analysis Pipeline Started\n")

steps = [
    ("Parsing logs", "python -m collector.parse_and_store"),
    ("Session pivot enrichment", "python -m detection.session_pivot_enricher"),
    ("Brute force detection", "python -m detection.bruteforce_detector"),
    ("Identity abuse detection", "python -m detection.identity_abuse_detector"),
    ("Low & slow detection", "python -m detection.low_slow_detector"),
    ("Privileged access detection", "python -m detection.privileged_access_detector"),
    ("Suspicious sudo command detection", "python -m detection.suspicious_sudo_detector"), 
    ("Security tampering detection", "python -m detection.security_tampering_detector"),
    ("Policy violation detection", "python -m detection.policy_violation_detector"),
     ("Anomaly detection", "python -m detection.anomaly_detector"),
    ("Incident correlation", "python -m correlation.incident_correlator"),
    ("Building raw log integrity hashchain", "python storage/build_hashchain.py"),


    

]

for name, cmd in steps:
    print(f"[+] {name}...")
    os.system(cmd)
    time.sleep(1)

print("\n[+] Pipeline completed. Alerts updated.\n")
