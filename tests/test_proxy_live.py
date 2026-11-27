"""Opt-in: run the proxy configs in proxy/ for real. GUESTCHECK_LIVE=1 python3 -m unittest tests.test_proxy_live

Apache: needs apache2 (or httpd), htpasswd and openssl. The test starts Apache as your user on two
local ports, with proxy/apache-ollama.conf changed only where it names paths and ports, in front of
a stand-in that applies Ollama's own rule for local servers (it refuses a Host header that isn't
local). nginx: only `nginx -t` on proxy/nginx-ollama.conf, skipped when nginx isn't installed.
"""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PROXY = os.path.join(os.path.dirname(HERE), "proxy")
LIVE = os.environ.get("GUESTCHECK_LIVE") == "1"
APACHE = shutil.which("apache2") or shutil.which("httpd")
NGINX = shutil.which("nginx")
MODULES = os.environ.get("GUESTCHECK_APACHE_MODULES", "/usr/lib/apache2/modules")
BLOCKED = [("POST", "/api/pull"), ("POST", "/api/push"), ("POST", "/api/create"), ("POST", "/api/copy"),
           ("DELETE", "/api/delete"), ("POST", "/api/blobs/sha256:00"), ("POST", "/api/me"),
           ("POST", "/api/signout"), ("DELETE", "/api/user/keys/abc"), ("GET", "/api/balance"),
           ("GET", "/api/usage?range=30d"), ("POST", "/api/experimental/web_search"),
           ("POST", "/api/codex/v1/responses")]


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def ollama_accepts_host(host_header: str) -> bool:
    """Ollama's check for a server bound to 127.0.0.1 (allowedHostsMiddleware in server/routes.go)."""
    host = host_header.rsplit(":", 1)[0].strip("[]") if host_header.count(":") <= 1 or host_header.startswith("[") \
        else host_header
    if host in ("", "localhost") or host.endswith((".localhost", ".local", ".internal")):
        return True
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        return False
    return a.is_loopback or a.is_private or a.is_unspecified


class Backend:
    def __init__(self):
        self.seen: list[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _record(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                outer.seen.append({"method": self.command, "path": self.path, "host": self.headers.get("Host"),
                                   "xff": self.headers.get("X-Forwarded-For"),
                                   "xri": self.headers.get("X-Real-IP")})
                return outer.seen[-1]

            def _json(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _any(self):
                rec = self._record()
                if not ollama_accepts_host(rec["host"] or ""):
                    return self._json(403, {"error": "host not allowed"})
                if self.path == "/api/generate":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ndjson")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    for i, pause in ((0, 1.5), (1, 0)):
                        line = json.dumps({"response": f"token{i}", "done": i == 1}).encode() + b"\n"
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(line), line))
                        self.wfile.flush()
                        time.sleep(pause)
                    self.wfile.write(b"0\r\n\r\n")
                    return
                return self._json(200, {"reached": self.path})

            do_GET = do_POST = do_DELETE = _any

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def make_cert(tmp: str) -> tuple[str, str]:
    cert, key = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)
    return cert, key


def wait_for(port: int, seconds: float = 15) -> None:
    end = time.time() + seconds
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on {port}")


def swap(text: str, old: str, new: str) -> str:
    assert old in text, f"the shipped config no longer contains {old!r}"
    return text.replace(old, new)


@unittest.skipUnless(LIVE and APACHE and shutil.which("htpasswd") and shutil.which("openssl"),
                     "set GUESTCHECK_LIVE=1; needs apache2, htpasswd and openssl")
class ApacheProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tmp.name
        cls.backend = Backend()
        cls.port, cls.port80 = free_port(), free_port()
        cert, key = make_cert(t)
        cls.password = secrets.token_urlsafe(18)
        htpasswd = os.path.join(t, "ollama.htpasswd")
        subprocess.run(["htpasswd", "-c", "-b", "-B", htpasswd, "tester", cls.password], check=True,
                       capture_output=True)
        with open(os.path.join(PROXY, "apache-ollama.conf")) as fh:
            site = fh.read()
        site = swap(site, "<VirtualHost *:443>", f"<VirtualHost 127.0.0.1:{cls.port}>")
        site = swap(site, "<VirtualHost *:80>", f"<VirtualHost 127.0.0.1:{cls.port80}>")
        site = swap(site, "/etc/letsencrypt/live/ollama.example.com/fullchain.pem", cert)
        site = swap(site, "/etc/letsencrypt/live/ollama.example.com/privkey.pem", key)
        site = swap(site, "/etc/apache2/ollama.htpasswd", htpasswd)
        site = swap(site, "http://127.0.0.1:11434/", f"http://127.0.0.1:{cls.backend.port}/")
        with open(os.path.join(t, "ollama.conf"), "w") as fh:
            fh.write(site)
        mods = ["mpm_event", "authz_core", "authn_core", "authn_file", "auth_basic", "authz_user", "headers",
                "proxy", "proxy_http", "ssl", "socache_shmcb", "alias"]
        main = [f'ServerRoot "{t}"', f"Listen 127.0.0.1:{cls.port}", f"Listen 127.0.0.1:{cls.port80}",
                f'PidFile "{t}/httpd.pid"', f'ErrorLog "{t}/error.log"', "LogLevel warn",
                f'DefaultRuntimeDir "{t}"', f"Mutex file:{t} default", "ServerName localhost",
                f'SSLSessionCache "shmcb:{t}/ssl_scache(512000)"']
        main += [f"LoadModule {m}_module {MODULES}/mod_{m}.so" for m in mods]
        main += ["<Directory />", "    AllowOverride None", "    Require all denied", "</Directory>",
                 f'Include "{t}/ollama.conf"']
        cls.conf = os.path.join(t, "httpd.conf")
        with open(cls.conf, "w") as fh:
            fh.write("\n".join(main) + "\n")
        test = subprocess.run([APACHE, "-t", "-f", cls.conf], capture_output=True, text=True)
        assert test.returncode == 0, test.stderr
        cls.proc = subprocess.Popen([APACHE, "-f", cls.conf, "-DFOREGROUND"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for(cls.port)
        wait_for(cls.port80)
        cls.ctx = ssl.create_default_context(cafile=cert)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.backend.close()
        cls.tmp.cleanup()

    def request(self, method, path, auth=True, password=None, headers=None):
        h = dict(headers or {})
        if auth:
            token = base64.b64encode(f"tester:{password or self.password}".encode()).decode()
            h["Authorization"] = "Basic " + token
        c = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.ctx, timeout=20)
        c.request(method, path, body=b"{}" if method == "POST" else None, headers=h)
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, body

    def test_no_password_no_answer(self):
        before = len(self.backend.seen)
        self.assertEqual(self.request("GET", "/api/tags", auth=False)[0], 401)
        self.assertEqual(self.request("GET", "/api/tags", password="wrong-password")[0], 401)
        self.assertEqual(len(self.backend.seen), before)

    def test_password_gets_through_with_a_local_host_and_the_real_address(self):
        status, body = self.request("GET", "/api/tags", headers={"X-Forwarded-For": "203.0.113.99",
                                                                  "X-Real-IP": "203.0.113.98"})
        self.assertEqual(status, 200, body)
        seen = self.backend.seen[-1]
        self.assertTrue(ollama_accepts_host(seen["host"]), seen["host"])
        self.assertEqual(seen["xff"], "127.0.0.1")       # the client's forged value is gone
        self.assertIsNone(seen["xri"])

    def test_management_and_account_paths_are_refused(self):
        before = len(self.backend.seen)
        for method, path in BLOCKED:
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path)[0], 403)
        self.assertEqual(len(self.backend.seen), before)

    def test_similar_paths_are_not_caught(self):
        for path in ("/api/meta", "/api/pulls", "/api/chat", "/v1/chat/completions"):
            with self.subTest(path=path):
                self.assertEqual(self.request("POST", path)[0], 200)

    def test_tokens_stream(self):
        token = base64.b64encode(f"tester:{self.password}".encode()).decode()
        c = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.ctx, timeout=20)
        start = time.time()
        c.request("POST", "/api/generate", body=b"{}", headers={"Authorization": "Basic " + token})
        r = c.getresponse()
        first = r.readline()
        first_at = time.time() - start
        rest = r.read()
        total = time.time() - start
        c.close()
        self.assertIn(b"token0", first)
        self.assertIn(b"token1", rest)
        self.assertLess(first_at, 1.2, "the first token waited for the whole response")
        self.assertGreater(total, 1.4)

    def test_plain_http_redirects(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port80, timeout=10)
        c.request("GET", "/api/tags")
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.status, 301)
        self.assertEqual(r.getheader("Location"), "https://ollama.example.com/api/tags")


@unittest.skipUnless(LIVE and NGINX, "set GUESTCHECK_LIVE=1; needs nginx")
class NginxSyntax(unittest.TestCase):
    def test_config_parses(self):
        with tempfile.TemporaryDirectory() as t:
            cert, key = make_cert(t)
            with open(os.path.join(PROXY, "nginx-ollama.conf")) as fh:
                site = fh.read()
            site = swap(site, "/etc/letsencrypt/live/ollama.example.com/fullchain.pem", cert)
            site = swap(site, "/etc/letsencrypt/live/ollama.example.com/privkey.pem", key)
            site = swap(site, "/etc/nginx/ollama.htpasswd", os.path.join(t, "htpasswd"))
            site = swap(site, "listen 443 ssl;", f"listen 127.0.0.1:{free_port()} ssl;")
            site = swap(site, "listen 80;", f"listen 127.0.0.1:{free_port()};")
            with open(os.path.join(t, "ollama.conf"), "w") as fh:
                fh.write(site)
            main = (f"error_log {t}/error.log;\npid {t}/nginx.pid;\nevents {{}}\nhttp {{\n"
                    f"  access_log off;\n  client_body_temp_path {t}/body;\n  proxy_temp_path {t}/proxy;\n"
                    f"  fastcgi_temp_path {t}/fcgi;\n  uwsgi_temp_path {t}/uwsgi;\n  scgi_temp_path {t}/scgi;\n"
                    f"  include {t}/ollama.conf;\n}}\n")
            conf = os.path.join(t, "nginx.conf")
            with open(conf, "w") as fh:
                fh.write(main)
            r = subprocess.run([NGINX, "-t", "-p", t, "-c", conf], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
