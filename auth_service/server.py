"""HTTP front end (stdlib http.server, threaded).

Endpoints:
  POST /login             {"username", "password"}                -> {"token"}
  POST /change_password   {"username", "old_password", "new_password"}
  POST /admin/reset       header X-Admin-Token; {"username", "new_password"}
  POST /session/validate  {"token"}                               -> {"valid", "username"}
  GET  /health

Passwords arrive as JSON strings and are encoded to raw UTF-8 bytes with
no trimming / case folding / normalization.  Passwords and session tokens
are never logged.
"""

import argparse
import hmac
import json
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import core
from .config import load_config
from .hooks import Hooks, HookError


class _Handler(BaseHTTPRequestHandler):
    server_version = "AuthSvc/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Request lines only; bodies (passwords/tokens) are never logged.
        sys.stderr.write("[http] %s %s\n" % (self.address_string(), fmt % args))

    # -- helpers ---------------------------------------------------------
    def _send(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        cfg = self.server.cfg
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise core.AuthError("bad_request", 400)
        if length <= 0 or length > cfg.body_max_bytes:
            raise core.AuthError("bad_request", 400)
        raw = self.rfile.read(length)
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise core.AuthError("bad_request", 400)
        if not isinstance(obj, dict):
            raise core.AuthError("bad_request", 400)
        return obj

    def _req_hooks(self):
        if not self.server.cfg.enable_test_hooks:
            return None
        raw = self.headers.get("X-Test-Hooks")
        if not raw:
            return None
        try:
            obj = json.loads(raw)
        except ValueError:
            return None
        return obj if isinstance(obj, dict) else None

    @staticmethod
    def _pw(obj, key):
        v = obj.get(key)
        if not isinstance(v, str):
            raise core.AuthError("bad_request", 400)
        return v.encode("utf-8")

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        try:
            self._route()
        except core.AuthError as e:
            self._send(e.status, {"error": e.code})
        except HookError:
            self._send(500, {"error": "hook_error"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()
            try:
                self._send(500, {"error": "internal"})
            except Exception:
                pass

    def _route(self):
        srv = self.server
        cfg, hooks, db = srv.cfg, srv.hooks, srv.db_path
        obj = self._body()
        rh = self._req_hooks()

        if self.path == "/login":
            token = core.login(db, cfg, hooks, obj.get("username"),
                               self._pw(obj, "password"), rh)
            self._send(200, {"token": token})
        elif self.path == "/change_password":
            core.change_password(db, cfg, hooks, obj.get("username"),
                                 self._pw(obj, "old_password"),
                                 self._pw(obj, "new_password"), rh)
            self._send(200, {"ok": True})
        elif self.path == "/admin/reset":
            token = self.headers.get("X-Admin-Token") or ""
            if not hmac.compare_digest(token.encode("utf-8"),
                                       cfg.admin_token.encode("utf-8")):
                raise core.AuthError("forbidden", 403)
            core.admin_reset(db, cfg, hooks, obj.get("username"),
                             self._pw(obj, "new_password"), rh)
            self._send(200, {"ok": True})
        elif self.path == "/session/validate":
            t = obj.get("token")
            valid, username = core.validate_session(
                db, cfg, t if isinstance(t, str) else "")
            self._send(200, {"valid": valid,
                             "username": username if valid else None})
        else:
            self._send(404, {"error": "not_found"})


def main(argv=None):
    parser = argparse.ArgumentParser(description="local password auth service")
    parser.add_argument("--config", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0,
                        help="0 = pick a free port (printed on the READY line)")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    hooks = Hooks(cfg.enable_test_hooks, cfg.hook_dir or None)
    srv = ThreadingHTTPServer((args.host, args.port), _Handler)
    srv.daemon_threads = True
    srv.cfg = cfg
    srv.hooks = hooks
    srv.db_path = args.db
    port = srv.server_address[1]
    print(f"READY {port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
