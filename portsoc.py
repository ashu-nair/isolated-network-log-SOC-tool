
import sys
import subprocess
import os
import time
PYTHON = sys.executable

BANNER = r"""
██████╗  ██████╗ ██████╗ ████████╗      ███████╗ ██████╗  ██████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝      ██╔════╝██╔═══██╗██╔════╝
██████╔╝██║   ██║██████╔╝   ██║         ███████╗██║   ██║██║     
██╔═══╝ ██║   ██║██╔══██╗   ██║         ╚════██║██║   ██║██║     
██║     ╚██████╔╝██║  ██║   ██║         ███████║╚██████╔╝╚██████╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝         ╚══════╝ ╚═════╝  ╚═════╝

Portable Offline SOC for Isolated Networks
"""


# ----------------------------
# Helpers
# ----------------------------

def run(cmd):
    subprocess.run(cmd, check=False)


def trim_raw_logs(max_lines=10000):
    """
    Keeps only last max_lines from storage/raw_logs.log
    Prevents storage explosion in live mode.
    """
    path = "storage/raw_logs.log"
    if not os.path.exists(path):
        return

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        if len(lines) <= max_lines:
            return

        lines = lines[-max_lines:]

        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        print(f"[+] Raw log trimmed to last {max_lines} lines")

    except Exception as e:
        print(f"[WARN] Could not trim raw logs: {e}")


def banner():
    print(BANNER)


def usage():
    print("Usage:")
    print("  python portsoc.py start      -> One-command launcher (recommended)")
    print("  python portsoc.py live       -> Start syslog server (real-time collection)")
    print("  python portsoc.py local      -> Import local Ubuntu logs (/var/log/*)")
    print("  python portsoc.py import     -> Import offline logs from storage/import")
    print("  python portsoc.py pipeline   -> Run full analysis pipeline once")
    print("  python portsoc.py ui         -> Start Flask dashboard")
    print("  python portsoc.py reset      -> Reset DB + raw logs + offsets\n")


def reset_all():
    # reset db
    run([PYTHON, "-m", "storage.reset_db"])

    # clear raw log file
    if os.path.exists("storage/raw_logs.log"):
        open("storage/raw_logs.log", "w").close()

    # clear offsets
    if os.path.exists("storage/offset.txt"):
        os.remove("storage/offset.txt")

    # clear hashchain
    if os.path.exists("storage/raw_logs.hashchain"):
        os.remove("storage/raw_logs.hashchain")

    # clear ubuntu offsets (if you use local collector)
    if os.path.exists("storage/local_offsets"):
        # keep folder but remove files
        for f in os.listdir("storage/local_offsets"):
            try:
                os.remove(os.path.join("storage/local_offsets", f))
            except:
                pass

    print("[+] Reset complete.")


def setup_db():
    """
    Runs full DB schema setup + migrations.
    """
    run([PYTHON, "-m", "storage.setup_db"])


# ----------------------------
# Start launcher
# ----------------------------

def start_launcher():
    print("\n[PORT-SOC] Welcome\n")

    fresh = input("Do you want a fresh start (wipe old data)? (y/n): ").strip().lower()
    if fresh == "y":
        reset_all()
        setup_db()

    print("\nSelect operation mode:")
    print("  1) Live Syslog SOC (real-time)")
    print("  2) Import local Ubuntu logs (/var/log/auth.log, /var/log/syslog)")
    print("  3) Offline import from storage/import folder")

    choice = input("\nEnter choice (1/2/3): ").strip()

    if choice == "1":
        # Live SOC mode
        print("\n[+] Starting live SOC mode")
        print("[+] Terminal will keep running. Press CTRL+C to stop.\n")

        # Start syslog server in a separate process
        syslog_proc = subprocess.Popen([PYTHON, "-m", "collector.syslog_server"])

        # Start UI in separate process
        ui_proc = subprocess.Popen([PYTHON, "ui/app.py"])

        # Loop pipeline
        interval = 10
        print(f"[+] Running pipeline every {interval} seconds...\n")

        try:
            while True:
                subprocess.run([PYTHON, "run_pipeline.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                trim_raw_logs(max_lines=10000)
                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n[+] Stopping PORT-SOC live mode...")

        finally:
            try:
                syslog_proc.terminate()
            except:
                pass
            try:
                ui_proc.terminate()
            except:
                pass

            print("[+] Live mode stopped.")

    elif choice == "2":
        # Local Ubuntu logs import
        print("\n[+] Importing local Ubuntu logs...")
        run([PYTHON, "-m", "collector.local_log_collector"])
        print("[+] Running pipeline...")
        run([PYTHON, "run_pipeline.py"])
        print("[+] Starting UI...")
        run([PYTHON, "ui/app.py"])

    elif choice == "3":
        # Offline import folder
        print("\n[+] Importing offline logs from storage/import...")
        run([PYTHON, "-m", "collector.import_folder_parser"])
        print("[+] Running pipeline...")
        run([PYTHON, "run_pipeline.py"])
        print("[+] Starting UI...")
        run([PYTHON, "ui/app.py"])

    else:
        print("[!] Invalid choice. Exiting.")


# ----------------------------
# Main
# ----------------------------

if __name__ == "__main__":
    banner()

    if len(sys.argv) < 2:
        usage()
        sys.exit(0)

    mode = sys.argv[1].lower()

    if mode == "start":
        start_launcher()

    elif mode == "live":
        print("[+] Starting syslog server...")
        run([PYTHON, "-m", "collector.syslog_server"])

    elif mode == "import":
        print("[+] Importing offline logs...")
        run([PYTHON, "-m", "collector.import_folder_parser"])
        print("[+] Running pipeline...")
        run([PYTHON, "run_pipeline.py"])

    elif mode == "pipeline":
        print("[+] Running pipeline...")
        run([PYTHON, "run_pipeline.py"])

    elif mode == "ui":
        print("[+] Starting dashboard...")
        run([PYTHON, "ui/app.py"])

    elif mode == "local":
        print("[+] Collecting local Ubuntu logs...")
        run([PYTHON, "-m", "collector.local_log_collector"])
        print("[+] Running pipeline...")
        run([PYTHON, "run_pipeline.py"])

    elif mode == "reset":
        reset_all()

    else:
        usage()
