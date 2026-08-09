import time
import hashlib
from watchdog.events import FileSystemEventHandler
from core.models import Event
from storage.repository import insert_event
from storage.database import init_db

last_seen = {}
def should_record(path, debounce_seconds = 2):
    now = time.time()
    last = last_seen.get(path)
    if last is not None and (now - last) < debounce_seconds:
        return False
    last_seen[path] = now
    return True

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, db_path: str, host: str):
        self.db_path = db_path
        self.host = host
        self.conn = None

    def _get_conn(self):
        if self.conn is None:
            self.conn = init_db(self.db_path)
        return self.conn

    def on_modified(self, event):
        if event.is_directory:
            return
        if not should_record(event.src_path):
            return
        if not content_really_changed(event.src_path):
            return

        file_event = Event(
            host=self.host,
            source="file_monitor",
            event_type="file_modified",
            severity="low",
            description=f"File modified: {event.src_path}",
            raw_data={"path": event.src_path}
        )
        insert_event(self._get_conn(), file_event)
        print(f"[+] {file_event.description}")

    def on_created(self, event):
        if event.is_directory:
            return
        if not should_record(event.src_path):
            return
        file_hashes[event.src_path] = hash_file(event.src_path)


        file_event = Event(
            host=self.host,
            source="file_monitor",
            event_type="file_created",
            severity="low",
            description=f"File created: {event.src_path}",
            raw_data={"path": event.src_path}
        )
        insert_event(self._get_conn(), file_event)
        print(f"[+] {file_event.description}")

    def on_deleted(self, event):
        if event.is_directory:
            return
        if not should_record(event.src_path):
            return

        file_event = Event(
            host=self.host,
            source="file_monitor",
            event_type="file_deleted",
            severity="low",
            description=f"File deleted: {event.src_path}",
            raw_data={"path": event.src_path}
        )
        insert_event(self._get_conn(), file_event)
        print(f"[+] {file_event.description}")

file_hashes = {}
def hash_file(path:str) -> str:
    """conpute the sha-256 hash of file's contents."""
    with open(path, "rb") as f:
        content = f.read()
    return hashlib.sha256(content).hexdigest()

def content_really_changed(path:str) -> bool:
    """check if a file content actually changes since we last saw it."""
    try:
        current_hash = hash_file(path)
    except(FileNotFoundError,PermissionError):
        return False

    previous_hash = file_hashes.get(path)
    file_hashes[path] = current_hash

    if previous_hash is None:
        return True
    return current_hash != previous_hash