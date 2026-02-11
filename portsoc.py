import sys
import subprocess
import os


def run(cmd):
    subprocess.run(cmd, check=False)


def banner():
    print("\n=== PORT-SOC (Offline Log Analysis & Detection) ===\n")


def usage():
    print("Usage:")
    print("  python portsoc.py live       -> Start syslog server (real-time collection)")
    print("  python portsoc.py import     -> Import logs from storage/import")
    print("  python portsoc.py pipeline   -> Run full analysis pipeline once")
    print("  python portsoc.py ui         -> Start Flask dashboard")
    print("  python portsoc.py reset      -> Reset DB + raw logs + offsets\n")


def reset_all():
    # reset db
    run(["python", "-m", "storage.reset_db"])

    # clear raw log file
    if os.path.exists("storage/raw_logs.log"):
        open("storage/raw_logs.log", "w").close()

    # clear offsets
    if os.path.exists("storage/offset.txt"):
        os.remove("storage/offset.txt")

    # clear hashchain
    if os.path.exists("storage/raw_logs.hashchain"):
        os.remove("storage/raw_logs.hashchain")

    print("[+] Reset complete.")


if __name__ == "__main__":
    banner()

    if len(sys.argv) < 2:
        usage()
        sys.exit(0)

    mode = sys.argv[1].lower()

    if mode == "live":
        print("[+] Starting syslog server...")
        run(["python", "-m", "collector.syslog_server"])

    elif mode == "import":
        print("[+] Importing offline logs...")
        run(["python", "-m", "collector.import_folder_parser"])
        print("[+] Running pipeline...")
        run(["python", "run_pipeline.py"])

    elif mode == "pipeline":
        print("[+] Running pipeline...")
        run(["python", "run_pipeline.py"])

    elif mode == "ui":
        print("[+] Starting dashboard...")
        run(["python", "ui/app.py"])

    elif mode == "local":
        print("[+] Collecting local Ubuntu logs...")
        run(["python", "-m", "collector.local_log_collector"])
        print("[+] Running pipeline...")
        run(["python", "run_pipeline.py"])


    elif mode == "reset":
        reset_all()

    else:
        usage()
