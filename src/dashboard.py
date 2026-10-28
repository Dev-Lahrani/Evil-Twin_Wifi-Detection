import json
import secrets
import ssl
import threading
import time
from collections import deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


DASHBOARD_HTML = Path(__file__).with_name("dashboard.html")
REPORT_HTML = Path(__file__).with_name("report.html")
MAX_BODY_BYTES = 64 * 1024
SESSION_SECONDS = 8 * 60 * 60


class DashboardServer:
    def __init__(self, host, port, password, status_provider, history_provider,
                 start_scanner, stop_scanner, update_config, certfile=None, keyfile=None):
        self.password = password or ""
        self.status_provider = status_provider
        self.history_provider = history_provider
        self.start_scanner = start_scanner
        self.stop_scanner = stop_scanner
        self.update_config = update_config
        self.certfile = certfile
        self.keyfile = keyfile
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self.login_attempts = {}
        self.login_lock = threading.Lock()
        self.server_thread = None
        ThreadingHTTPServer.allow_reuse_address = True
        self.server = ThreadingHTTPServer((host, port), self._make_handler())
        if bool(certfile) != bool(keyfile):
            self.server.server_close()
            raise ValueError("Provide both a TLS certificate and private key.")
        if password and not certfile:
            self.server.server_close()
            raise ValueError("A dashboard password requires HTTPS; provide a TLS certificate and key.")
        if certfile:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile, keyfile)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.server.daemon_threads = True

    def _make_handler(self):
        dashboard = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "EvilTwinDashboard"
            sys_version = ""

            def log_message(self, fmt, *args):
                return

            def end_headers(self):
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
                    "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
                )
                if dashboard.certfile:
                    self.send_header("Strict-Transport-Security", "max-age=31536000")
                super().end_headers()

            def _send(self, status, body, content_type="application/json; charset=utf-8", headers=()):
                encoded = body if isinstance(body, bytes) else body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("Cache-Control", "no-store")
                for key, value in headers:
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(encoded)

            def _json(self, status, payload, headers=()):
                self._send(status, json.dumps(payload, ensure_ascii=False), headers=headers)

            def _read_json(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    return None
                if not 0 < length <= MAX_BODY_BYTES:
                    return None
                try:
                    value = json.loads(self.rfile.read(length))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return None
                return value if isinstance(value, dict) else None

            def _is_secure(self):
                return isinstance(self.connection, ssl.SSLSocket)

            def _origin_ok(self):
                origin = self.headers.get("Origin")
                if not origin:
                    return True
                parsed = urlsplit(origin)
                scheme = "https" if dashboard.certfile else "http"
                return parsed.scheme == scheme and parsed.netloc.lower() == self.headers.get("Host", "").lower()

            def _session(self):
                cookie = SimpleCookie()
                try:
                    cookie.load(self.headers.get("Cookie", ""))
                except Exception:
                    return None
                morsel = cookie.get("eviltwin_session")
                token = morsel.value if morsel else ""
                now = time.monotonic()
                with dashboard.sessions_lock:
                    session = dashboard.sessions.get(token)
                if session and session["expires"] > now:
                    session["expires"] = now + SESSION_SECONDS
                    return token, dict(session)
                    dashboard.sessions.pop(token, None)
                return None

            def _require_admin(self):
                session = self._session()
                csrf = self.headers.get("X-CSRF-Token", "")
                if not session or not secrets.compare_digest(csrf, session[1]["csrf"]):
                    self._json(403, {"error": "Sign in again to use administrator controls."})
                    return None
                return session

            def do_GET(self):
                if self.path in ("/", "/report"):
                    page_path = REPORT_HTML if self.path == "/report" else DASHBOARD_HTML
                    unavailable = "Report page is unavailable." if self.path == "/report" else "Dashboard page is unavailable."
                    try:
                        page = page_path.read_bytes()
                    except OSError:
                        self._send(500, unavailable, "text/plain; charset=utf-8")
                        return
                    self._send(200, page, "text/html; charset=utf-8")
                    return
                if self.path == "/api/status":
                    status = dashboard.status_provider()
                    session = self._session()
                    status["dashboard_secure"] = self._is_secure()
                    status["admin_enabled"] = bool(dashboard.password)
                    status["authenticated"] = session is not None
                    status["csrf_token"] = session[1]["csrf"] if session else ""
                    if not session:
                        status.pop("trusted_networks", None)
                    self._json(200, status)
                elif self.path == "/api/history":
                    self._json(200, {"events": dashboard.history_provider()})
                else:
                    self._json(404, {"error": "Not found"})

            def do_POST(self):
                if self.path not in ("/api/login", "/api/logout", "/api/admin/scan", "/api/admin/config"):
                    self._json(404, {"error": "Not found"})
                    return
                if not self._origin_ok():
                    self._json(403, {"error": "Cross-origin requests are not accepted."})
                    return
                if self.path == "/api/login":
                    if not dashboard.password:
                        self._json(503, {"error": "Administrator controls are disabled."})
                        return
                    if not self._is_secure():
                        self._json(400, {"error": "Administrator sign-in is accepted only over HTTPS."})
                        return
                payload = self._read_json()
                if payload is None:
                    self._json(400, {"error": "Expected a valid JSON object no larger than 64 KiB."})
                    return
                if self.path == "/api/login":
                    self._login(payload)
                    return
                if self.path == "/api/logout":
                    session = self._require_admin()
                    if session:
                        with dashboard.sessions_lock:
                            dashboard.sessions.pop(session[0], None)
                        self._json(200, {"ok": True}, (("Set-Cookie", "eviltwin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"),))
                    return
                if self.path not in ("/api/admin/scan", "/api/admin/config"):
                    self._json(404, {"error": "Not found"})
                    return
                if not dashboard.password:
                    self._json(503, {"error": "Administrator controls are disabled."})
                    return
                if not self._is_secure():
                    self._json(400, {"error": "Administrator controls require HTTPS."})
                    return
                if not self._require_admin():
                    return
                if self.path == "/api/admin/scan":
                    self._scan(payload)
                else:
                    self._config(payload)

            def _login(self, payload):
                client = self.client_address[0]
                now = time.monotonic()
                with dashboard.login_lock:
                    attempts = dashboard.login_attempts.setdefault(client, deque())
                    while attempts and attempts[0] < now - 300:
                        attempts.popleft()
                    if len(attempts) >= 5:
                        self._json(429, {"error": "Too many sign-in attempts. Wait five minutes."})
                        return
                    attempts.append(now)
                if not self._is_secure():
                    self._json(400, {"error": "Administrator sign-in is accepted only over HTTPS."})
                    return
                supplied = payload.get("password")
                if not isinstance(supplied, str) or not secrets.compare_digest(supplied, dashboard.password):
                    self._json(401, {"error": "Password not accepted."})
                    return
                token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
                with dashboard.sessions_lock:
                    dashboard.sessions[token] = {"csrf": csrf, "expires": now + SESSION_SECONDS}
                self._json(200, {"ok": True, "csrf_token": csrf}, ((
                    "Set-Cookie", f"eviltwin_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"
                ),))

            def _scan(self, payload):
                action = payload.get("action")
                try:
                    if action == "start":
                        dashboard.start_scanner()
                    elif action == "stop":
                        dashboard.stop_scanner()
                    else:
                        self._json(400, {"error": "Action must be start or stop."})
                        return
                except (ValueError, RuntimeError) as error:
                    self._json(409, {"error": str(error)})
                    return
                self._json(200, {"ok": True, "status": dashboard.status_provider()})

            def _config(self, payload):
                try:
                    result = dashboard.update_config(payload.get("trusted_networks"), payload.get("scan_interval"))
                except (TypeError, ValueError, OSError) as error:
                    self._json(400, {"error": str(error)})
                    return
                self._json(200, {"ok": True, "config": result})

        return Handler

    @property
    def address(self):
        return self.server.server_address[:2]

    def start(self):
        self.server_thread = threading.Thread(target=self.server.serve_forever, name="dashboard-http", daemon=True)

        self.server_thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        if self.server_thread:
            self.server_thread.join(timeout=2)
