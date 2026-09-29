import sys
import threading
sys.path.insert(0, "src")

from storage.database import init_db
from collectors.process_monitor import run_process_monitor
from collectors.file_monitor import run_file_monitor
from collectors.usb_monitor import run_usb_monitor
from collectors.login_monitor import run_login_monitor

DB_PATH = "data/sentinel.db"
HOST = "DESKTOP-01"


def start_process_monitor():
    conn = init_db(DB_PATH)
    run_process_monitor(conn=conn, host=HOST, ignore_list=["svchost.exe", "explorer.exe", "dllhost.exe", "RuntimeBroker.exe", "conhost.exe"], poll_interval_seconds=5)


def start_usb_monitor():
    conn = init_db(DB_PATH)
    run_usb_monitor(conn=conn, host=HOST, poll_interval_seconds=5)


def start_login_monitor():
    conn = init_db(DB_PATH)
    run_login_monitor(conn=conn, host=HOST, poll_interval_seconds=5)


process_thread = threading.Thread(target=start_process_monitor, daemon=True)
usb_thread = threading.Thread(target=start_usb_monitor, daemon=True)
login_thread = threading.Thread(target=start_login_monitor, daemon=True)

process_thread.start()
usb_thread.start()
login_thread.start()

print("All monitors running. Press Ctrl+C to stop.")
print("(File monitor runs on the main thread, watching 'watch_test/')")


try:
    run_file_monitor(db_path=DB_PATH, host=HOST, watched_paths=["watch_test"])
except KeyboardInterrupt:
    print("\nStopping Sentinel-X... goodbye.")