import http.client
import threading

from dashboard.server import create_server


class FakeController:
    def __init__(self):
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def status(self):
        return {"running": self.running, "pid": 1 if self.running else None,
                "exit_code": None, "is_admin": True}


def _serve(tmp_path):
    fake = FakeController()
    server = create_server(str(tmp_path / "t.db"), port=0, controller=fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, fake


def _status(server, method, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
    conn.request(method, path, headers=headers or {})
    code = conn.getresponse().status
    conn.close()
    return code


def _good_headers(server):
    return {"Origin": "http://127.0.0.1:" + str(server.server_address[1]), "X-Sentinel-Action": "1"}


def test_post_without_origin_and_action_header_is_rejected(tmp_path):
    server, fake = _serve(tmp_path)
    try:
        assert _status(server, "POST", "/api/monitor/start") == 403
        assert fake.running is False
    finally:
        server.shutdown()
        server.server_close()


def test_post_with_correct_headers_starts_monitoring(tmp_path):
    server, fake = _serve(tmp_path)
    try:
        assert _status(server, "POST", "/api/monitor/start", _good_headers(server)) == 200
        assert fake.running is True
    finally:
        server.shutdown()
        server.server_close()


def test_get_cannot_start_monitoring(tmp_path):
    server, fake = _serve(tmp_path)
    try:
        assert _status(server, "GET", "/api/monitor/start") == 404
        assert fake.running is False
    finally:
        server.shutdown()
        server.server_close()


def test_wrong_host_header_is_rejected(tmp_path):
    server, _ = _serve(tmp_path)
    try:
        assert _status(server, "GET", "/api/report", {"Host": "evil.example:8765"}) == 403
    finally:
        server.shutdown()
        server.server_close()