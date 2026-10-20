import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from storage.database import init_db
from reporting.report_data import build_report_data
from ai.explainer import explain
from dashboard.monitor_control import MonitorController

HERE = Path(__file__).parent
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
CSP = "default-src 'self'"
ACTION_HEADER = "X-Sentinel-Action"


def make_handler(db_path: str, controller):
    class Handler(BaseHTTPRequestHandler):
        def _host_ok(self) -> bool:
            port = str(self.server.server_address[1])
            return self.headers.get("Host", "") in ("127.0.0.1:" + port, "localhost:" + port)

        def _post_ok(self) -> bool:
            host = self.headers.get("Host", "")
            return (self.headers.get("Origin", "") == "http://" + host
                    and self.headers.get(ACTION_HEADER) == "1")

        def do_GET(self):
            if not self._host_ok():
                self._send(403, "text/plain; charset=utf-8", b"forbidden")
                return
            path = self.path.split("?", 1)[0]
            if path in STATIC:
                filename, content_type = STATIC[path]
                self._send(200, content_type, (HERE / filename).read_bytes())
            elif path == "/api/report":
                self._json(200, self._report())
            elif path == "/api/monitor":
                self._json(200, controller.status())
            else:
                self._send(404, "text/plain; charset=utf-8", b"not found")

        def do_POST(self):
            if not (self._host_ok() and self._post_ok()):
                self._send(403, "text/plain; charset=utf-8", b"forbidden")
                return
            path = self.path.split("?", 1)[0]
            if path not in ("/api/monitor/start", "/api/monitor/stop"):
                self._send(404, "text/plain; charset=utf-8", b"not found")
                return
            try:
                if path.endswith("/start"):
                    controller.start()
                else:
                    controller.stop()
            except OSError as err:
                self._json(500, {"error": str(err)})
                return
            self._json(200, controller.status())

        def _report(self) -> dict:
            conn = init_db(db_path)  # one connection per request: runs in its own thread
            try:
                data = build_report_data(conn)
            finally:
                conn.close()
            for cluster in data["clusters"]:
                cluster["explanation"] = explain(cluster) if cluster["flagged"] else None
            return data

        def _json(self, code: int, obj):
            self._send(code, "application/json", json.dumps(obj).encode("utf-8"))

        def _send(self, code: int, content_type: str, body: bytes):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass  # keep the terminal quiet

    return Handler


def create_server(db_path: str = "data/sentinel.db", port: int = 8765, controller=None):
    if controller is None:
        controller = MonitorController()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(db_path, controller))
    server.controller = controller
    return server


def serve(db_path: str = "data/sentinel.db", port: int = 8765):
    server = create_server(db_path, port)
    print("Sentinel-X dashboard: http://127.0.0.1:" + str(server.server_address[1]) + "  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.controller.stop()  # never leave the monitors running unattended
        server.server_close()