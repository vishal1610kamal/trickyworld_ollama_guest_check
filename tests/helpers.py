"""A stand-in Ollama server and a fake host tree for the tests.

The stand-in answers the read-only endpoints the checker uses with the shapes Ollama 0.40.18's
source code produces (server/routes.go, api/types.go): /api/me returns the ollama.com account
(id, email, name, plan...) or 401 {"error": "unauthorized", "signin_url": ...}; /api/status returns
{"cloud": {"disabled", "source"}}; with cloud off, /api/usage and /api/balance return 403
"ollama cloud is disabled: ...". It also refuses anything that would change state, so a test fails
if the checker ever tries.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")


def load_fixture(name: str):
    with open(os.path.join(FIXTURES, name)) as fh:
        return json.load(fh)


SIGNED_IN_USER = {"id": "6f1c2d3e-0000-4000-8000-000000000001", "email": "alice@example.com",
                  "name": "alice", "firstname": "Alice", "lastname": "Example", "plan": "pro"}
SIGNIN_URL = "https://ollama.com/connect?name=gpu-box-01&key=c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUZha2U"


class StandIn:
    def __init__(self, version="0.40.18", models=None, me=(200, SIGNED_IN_USER), cloud_disabled=False,
                 status=True, running=None, usage=None, balance=None):
        self.version = version
        self.models = models if models is not None else []
        self.me = me
        self.cloud_disabled = cloud_disabled
        self.status = status
        self.running = running or []
        self.usage = usage
        self.balance = balance
        self.requests: list[tuple[str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                body = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.requests.append(("GET", self.path))
                path = self.path.split("?")[0]
                if path == "/api/version":
                    return self._send(200, {"version": outer.version})
                if path == "/api/tags":
                    return self._send(200, {"models": outer.models})
                if path == "/api/ps":
                    return self._send(200, {"models": [{"name": n, "model": n} for n in outer.running]})
                if path == "/api/status" and outer.status:
                    src = "env" if outer.cloud_disabled else "none"
                    return self._send(200, {"cloud": {"disabled": outer.cloud_disabled, "source": src}})
                if path in ("/api/usage", "/api/balance"):
                    if outer.cloud_disabled:
                        what = "usage" if path == "/api/usage" else "balance"
                        return self._send(403, {"error": f"ollama cloud is disabled: {what} is unavailable"})
                    if outer.me[0] != 200:
                        return self._send(401, {"error": "unauthorized", "signin_url": SIGNIN_URL})
                    return self._send(200, outer.usage if path == "/api/usage" else outer.balance)
                return self._send(404, None)

            def do_POST(self):
                outer.requests.append(("POST", self.path))
                if self.path == "/api/me":
                    code, body = outer.me
                    return self._send(code, body)
                return self._send(405, {"error": "the checker must not call this"})

            def do_DELETE(self):
                outer.requests.append(("DELETE", self.path))
                return self._send(405, {"error": "the checker must not call this"})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def build_host_root(root: str, bind_all=True, secret=True, key_mode=0o644) -> str:
    """A small copy of a Linux server's files: /proc/net, the systemd unit with an override,
    an EnvironmentFile and the service user's ~/.ollama. Secret-looking values are assembled here
    at run time so none sits in the repository."""
    def w(rel, text, mode=None):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(path, mode)
        return path

    local = "00000000" if bind_all else "0100007F"
    w("proc/net/tcp",
      "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
      f"   0: {local}:2CAA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 41001 1\n"
      "   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 41002 1\n"
      "   2: 0A7100CB:2CAA 646433C6:D431 01 00000000:00000000 00:00000000 00000000   999        0 41003 1\n")
    w("proc/net/tcp6",
      "  sl  local_address                         remote_address                        st tx_queue rx_queue\n"
      "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000\n")
    w("proc/net/fib_trie",
      "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n"
      "     +-- 127.0.0.0/8 2 0 2\n        |-- 127.0.0.1\n           /32 host LOCAL\n"
      "     |-- 203.0.113.10\n        /32 host LOCAL\n")
    w("proc/net/if_inet6",
      "00000000000000000000000000000001 01 80 10 80       lo\n"
      "20010db8000000000000000000000010 02 40 00 80     eth0\n")
    w("etc/systemd/system/ollama.service",
      "[Unit]\nDescription=Ollama Service\nAfter=network-online.target\n\n[Service]\n"
      "ExecStart=/usr/local/bin/ollama serve\nUser=ollama\nGroup=ollama\nRestart=always\n"
      'Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"\n\n'
      "[Install]\nWantedBy=default.target\n", 0o644)
    override = "[Service]\n"
    if bind_all:
        override += 'Environment="OLLAMA_HOST=0.0.0.0:11434"\n'
    if secret:
        override += 'Environment="OPENAI_API_KEY=not-a-real-key-' + "0" * 12 + '" "OLLAMA_KEEP_ALIVE=24h"\n'
        override += "EnvironmentFile=-/etc/ollama/ollama.env\n"
        w("etc/ollama/ollama.env", "# tokens for model downloads\nHF_TOKEN=hf_" + "A" * 24 + "\n", 0o640)
    w("etc/systemd/system/ollama.service.d/override.conf", override, 0o644)
    w("usr/share/ollama/.ollama/id_ed25519", "placeholder, not a key\n", key_mode)
    return root
