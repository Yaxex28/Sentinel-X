import sys

from dashboard.monitor_control import MonitorController


def _controller(tmp_path):
    return MonitorController(
        command=[sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=tmp_path, log_path=tmp_path / "m.log",
    )


def test_start_then_stop(tmp_path):
    c = _controller(tmp_path)
    try:
        c.start()
        assert c.status()["running"] is True
        c.stop()
        assert c.status()["running"] is False
    finally:
        c.stop()


def test_second_start_does_not_spawn_another_process(tmp_path):
    c = _controller(tmp_path)
    try:
        c.start()
        pid = c.status()["pid"]
        c.start()
        assert c.status()["pid"] == pid
    finally:
        c.stop()