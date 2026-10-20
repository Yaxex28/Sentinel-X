import json
import threading
import urllib.error
import urllib.request

from dashboard.server import create_server


def _start(tmp_path):
    server = create_server(str(tmp_path / "t.db"), port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _stop(server):
    server.shutdown()
    server.server_close()


def test_api_report_returns_json(tmp_path):
    server = _start(tmp_path)
    try:
        url = "http://127.0.0.1:" + str(server.server_address[1]) + "/api/report"
        with urllib.request.urlopen(url) as response:
            assert response.headers["Content-Type"] == "application/json"
            data = json.loads(response.read())
        assert data["total"] == 0
    finally:
        _stop(server)


def test_unknown_path_is_404_and_server_is_loopback_only(tmp_path):
    server = _start(tmp_path)
    try:
        assert server.server_address[0] == "127.0.0.1"
        url = "http://127.0.0.1:" + str(server.server_address[1]) + "/../secrets"
        try:
            urllib.request.urlopen(url)
            assert False, "expected a 404"
        except urllib.error.HTTPError as err:
            assert err.code == 404
    finally:
        _stop(server)


def test_page_is_served_with_a_content_security_policy(tmp_path):
    server = _start(tmp_path)
    try:
        url = "http://127.0.0.1:" + str(server.server_address[1]) + "/"
        with urllib.request.urlopen(url) as response:
            assert "default-src 'self'" in response.headers["Content-Security-Policy"]
            assert b"Sentinel-X Dashboard" in response.read()
    finally:
        _stop(server)