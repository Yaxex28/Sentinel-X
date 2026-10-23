import sys
import threading
sys.path.insert(0, "src")

from core.config import Config
from storage.database import init_db
from collectors.process_monitor import run_process_monitor
from collectors.file_monitor import run_file_monitor
from collectors.usb_monitor import run_usb_monitor
from collectors.login_monitor import run_login_monitor
from collectors.network_monitor import run_network_monitor

config = Config("config/default.yaml")

DB_PATH = "data/sentinel.db"
HOST = "DESKTOP-01"
WATCHED_PATHS = config.get("monitoring.file_integrity.watched_paths")
IGNORE_LIST = config.get("monitoring.process.ignore_list")
POLL_INTERVAL = config.get("monitoring.process.poll_interval_seconds")
NET_POLL = config.get("monitoring.network.poll_interval_seconds", 5)
NET_PORTS = config.get("monitoring.network.suspicious_ports", [])
NET_IGNORE = config.get("monitoring.network.ignore_processes", [])


def start_process_monitor():
    conn = init_db(DB_PATH)
    run_process_monitor(conn=conn, host=HOST, ignore_list=IGNORE_LIST, poll_interval_seconds=POLL_INTERVAL)


def start_usb_monitor():
    conn = init_db(DB_PATH)
    run_usb_monitor(conn=conn, host=HOST, poll_interval_seconds=POLL_INTERVAL)


def start_login_monitor():
    try:
        conn = init_db(DB_PATH)
        run_login_monitor(conn=conn, host=HOST, poll_interval_seconds=POLL_INTERVAL)
    except Exception as err:
        print("[!] Login monitor stopped: " + str(err) + " (run as Administrator?)")


def start_network_monitor():
    try:
        conn = init_db(DB_PATH)
        run_network_monitor(conn=conn, host=HOST, poll_interval_seconds=NET_POLL,
                            suspicious_ports=NET_PORTS, ignore_processes=NET_IGNORE)
    except Exception as err:
        print("[!] Network monitor stopped: " + str(err))


for target in (start_process_monitor, start_usb_monitor, start_login_monitor, start_network_monitor):
    threading.Thread(target=target, daemon=True).start()

print("All monitors running. Press Ctrl+C to stop.")
print(f"(File monitor runs on the main thread, watching {WATCHED_PATHS})")

try:
    run_file_monitor(db_path=DB_PATH, host=HOST, watched_paths=WATCHED_PATHS)
except KeyboardInterrupt:
    print("\nStopping Sentinel-X... goodbye.")