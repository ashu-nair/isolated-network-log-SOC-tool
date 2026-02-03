import os
import time

print("\n[+] PORT-SOC Analysis Pipeline Started\n")

steps = [
    ("Parsing logs", "python collector/parse_and_store.py"),
    ("Brute force detection", "python detection/bruteforce_detector.py"),
    ("Privileged access detection", "python detection/privileged_access_detector.py"),
    ("Anomaly detection", "python detection/anomaly_detector.py"),
]

# Optional: threat intel
if os.path.exists("detection/threat_intel_detector.py"):
    steps.append(("Threat intelligence detection", "python detection/threat_intel_detector.py"))

for name, cmd in steps:
    print(f"[+] {name}...")
    os.system(cmd)
    time.sleep(1)

print("\n[+] Pipeline completed. Alerts updated.\n")
