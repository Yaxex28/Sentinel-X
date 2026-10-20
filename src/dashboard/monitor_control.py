import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class MonitorController:
    """Starts and stops the monitoring runner as a child process."""

    def __init__(self, command=None, cwd=None, log_path=None):
        self._command = command or [sys.executable, "-u", str(ROOT / "run_all.py")]
        self._cwd = str(cwd or ROOT)
        self._log_path = Path(log_path or ROOT / "logs" / "monitors.log")
        self._proc = None
        self._log = None
        self._lock = threading.Lock()

    def _running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _close_log(self):
        if self._log is not None:
            self._log.close()
            self._log = None

    def start(self) -> None:
        with self._lock:
            if self._running():
                return
            self._close_log()
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log = open(self._log_path, "ab")
            self._proc = subprocess.Popen(
                self._command, cwd=self._cwd, stdout=self._log, stderr=subprocess.STDOUT
            )

    def stop(self) -> None:
        with self._lock:
            if self._running():
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait()
            self._proc = None
            self._close_log()

    def status(self) -> dict:
        with self._lock:
            running = self._running()
            exit_code = None
            if self._proc is not None and not running:
                exit_code = self._proc.returncode  # the runner died on its own
            return {
                "running": running,
                "pid": self._proc.pid if running else None,
                "exit_code": exit_code,
                "is_admin": is_admin(),
            }