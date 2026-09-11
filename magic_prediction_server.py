from __future__ import annotations

import json
import os
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
GUEST_HTML = ROOT / "tools" / "magic_prediction_guest.html"
ADMIN_HTML = ROOT / "tools" / "magic_prediction_admin.html"
PASSWORD = os.environ.get("MAGIC_ADMIN_PASSWORD", "northmagic-local")
SESSIONS: dict[str, dict] = {}
LOCK = threading.Lock()


def json_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "NorthMagicPrediction/1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_body(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, value: dict) -> None:
        self.send_body(status, json_bytes(value), "application/json; charset=utf-8")

    def redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def read_json(self) -> dict:
        length = min(int(self.headers.get("Content-Length", "0")), 20_000)
        value = json.loads(self.rfile.read(length) or b"{}")
        return value if isinstance(value, dict) else {}

    def authorized(self) -> bool:
        return self.headers.get("X-Magic-Admin") == self.server.admin_token

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/guest"}:
            if parsed.path == "/guest" and not parse_qs(parsed.query).get("code", [""])[0]:
                code = secrets.token_hex(2).upper()
                with LOCK:
                    SESSIONS[code] = {"created": time.time(), "published": False}
                self.redirect(f"/guest?code={code}")
                return
            self.send_body(200, GUEST_HTML.read_bytes(), "text/html; charset=utf-8")
            return
        if parsed.path == "/admin":
            self.send_body(200, ADMIN_HTML.read_bytes(), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/session":
            code = parse_qs(parsed.query).get("code", [""])[0].upper()
            with LOCK:
                session = SESSIONS.get(code)
                payload = {"exists": bool(session), "published": bool(session and session.get("published"))}
                if session and session.get("published"):
                    payload["reveal"] = session.get("reveal", {})
            self.send_json(200, payload)
            return
        if parsed.path == "/api/guest-session":
            code = secrets.token_hex(2).upper()
            with LOCK:
                SESSIONS[code] = {"created": time.time(), "published": False}
            self.send_json(200, {"ok": True, "code": code})
            return
        if parsed.path == "/api/sessions" and self.authorized():
            with LOCK:
                items = [{"code": code, "published": bool(value.get("published")), "created": value.get("created", 0)} for code, value in SESSIONS.items()]
            items.sort(key=lambda item: item["created"], reverse=True)
            self.send_json(200, {"sessions": items[:20]})
            return
        self.send_json(404, {"error": "NOT_FOUND"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            body = self.read_json()
        except Exception:
            self.send_json(400, {"error": "INVALID_JSON"})
            return
        if parsed.path == "/api/login":
            if secrets.compare_digest(str(body.get("password", "")), PASSWORD):
                self.server.admin_token = secrets.token_urlsafe(24)
                self.send_json(200, {"ok": True, "token": self.server.admin_token})
            else:
                self.send_json(401, {"error": "密码不正确"})
            return
        if not self.authorized():
            self.send_json(401, {"error": "请先登录后台"})
            return
        if parsed.path == "/api/create":
            code = secrets.token_hex(2).upper()
            with LOCK:
                SESSIONS[code] = {"created": time.time(), "published": False}
            self.send_json(200, {"ok": True, "code": code})
            return
        if parsed.path == "/api/publish":
            code = str(body.get("code", "")).upper().strip()
            reveal = {
                "date": str(body.get("date", "")).strip(),
                "color": str(body.get("color", "")).strip(),
                "cocktail": str(body.get("cocktail", "")).strip(),
                "number": str(body.get("number", "")).strip(),
                "card": str(body.get("card", "")).strip(),
                "copy": str(body.get("copy", "")).strip(),
            }
            if not code or not reveal["color"] or not reveal["cocktail"] or not reveal["number"] or not reveal["card"]:
                self.send_json(400, {"error": "请填写衣服颜色、鸡尾酒、数字和牌面"})
                return
            with LOCK:
                if code not in SESSIONS:
                    self.send_json(404, {"error": "体验编号不存在"})
                    return
                SESSIONS[code].update({"reveal": reveal, "published": True})
            self.send_json(200, {"ok": True})
            return
        self.send_json(404, {"error": "NOT_FOUND"})


class Server(ThreadingHTTPServer):
    admin_token = ""


def main() -> None:
    port = int(os.environ.get("PORT", os.environ.get("MAGIC_PORT", "8787")))
    host = os.environ.get("MAGIC_HOST", "0.0.0.0" if "PORT" in os.environ else "127.0.0.1")
    server = Server((host, port), Handler)
    public_host = "127.0.0.1" if host == "127.0.0.1" else "0.0.0.0"
    print(f"顾客页：http://{public_host}:{port}/guest")
    print(f"后台页：http://{public_host}:{port}/admin")
    print("默认后台密码：northmagic-local；上线前请设置 MAGIC_ADMIN_PASSWORD")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
