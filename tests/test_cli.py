import contextlib
import io
import re
import json
import os
import tempfile
import unittest
from unittest import mock

from guestcheck import cli
from tests.helpers import SIGNIN_URL, StandIn, build_host_root, load_fixture
from tests.test_logs import SAMPLE


def run(argv):
    """Exit code and output, with line wrapping undone so phrases can be searched for."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli.main(argv)
    return code, re.sub(r"\n {11}(- )?", lambda m: "\n           - " if m.group(1) else " ", buf.getvalue())


class Urls(unittest.TestCase):
    def test_default_and_normalize(self):
        self.assertEqual(cli.default_url(""), "http://127.0.0.1:11434")
        self.assertEqual(cli.default_url("0.0.0.0:11434"), "http://127.0.0.1:11434")
        self.assertEqual(cli.default_url("0.0.0.0"), "http://127.0.0.1:11434")
        self.assertEqual(cli.normalize_url("10.0.0.5"), "http://10.0.0.5:11434")
        self.assertEqual(cli.normalize_url("https://ollama.example.com"), "https://ollama.example.com:443")
        self.assertEqual(cli.normalize_url("http://[::1]:11500"), "http://[::1]:11500")


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = build_host_root(os.path.join(self.tmp.name, "root"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_visited_server_exits_2(self):
        with StandIn(models=load_fixture("rapid7_sample.json")["models"]) as s:
            code, out = run(["--url", s.url, "--root", self.root, "--listen-port", "11434"])
        self.assertEqual(code, 2)
        self.assertIn("read the account's email, user name, first name, last name, plan and account ID", out)
        self.assertIn("OPENAI_API_KEY in /etc/systemd/system/ollama.service.d/override.conf", out)
        self.assertIn("Strangers have used this server", out)
        self.assertIn("0.0.0.0:11434: reachable from other machines", out)
        self.assertIn("signed in as a***@example.com, plan pro", out)
        self.assertIn("OPENAI_API_KEY", out)
        self.assertNotIn("not-a-real-key", out)
        self.assertIn("/etc/shadow (credentials and keys)", out)
        self.assertIn("this server's own IP address (203.0.113.10)", out)
        self.assertIn("28 listed: 10 left by strangers, 2 to check, 5 run on Ollama's cloud", out)

    def test_json(self):
        with StandIn(models=load_fixture("rapid7_sample.json")["models"]) as s:
            code, out = run(["--url", s.url, "--root", self.root, "--json", "--listen-port", "11434"])
        data = json.loads(out)
        self.assertEqual(code, 2)
        self.assertEqual(data["assessment"]["verdict"], "strangers")
        self.assertTrue(data["assessment"]["exposed"])
        self.assertEqual(len(data["models"]), 28)
        self.assertEqual(data["models"][0]["level"], "stranger")
        self.assertNotIn("models", data["server"])

    def test_clean_local_server_exits_0(self):
        clean = build_host_root(os.path.join(self.tmp.name, "clean"), bind_all=False, secret=False,
                                key_mode=0o600)
        models = [{"name": "llama3.1:8b", "digest": "a" * 64}, {"name": "nomic-embed-text:latest"}]
        with StandIn(models=models, me=(401, {"error": "unauthorized", "signin_url": SIGNIN_URL})) as s:
            code, out = run(["--url", s.url, "--root", clean, "--listen-port", "11434"])
        self.assertEqual(code, 0, out)
        self.assertIn("127.0.0.1:11434: this machine only", out)
        self.assertIn("Nothing found", out)
        self.assertIn('gives away the machine name "gpu-box-01"', out)

    def test_old_version_needs_attention(self):
        with StandIn(version="0.5.7", me=(404, None), status=False,
                     models=[{"name": "qwen2.5:7b"}]) as s:
            code, out = run(["--url", s.url, "--no-host"])
        self.assertEqual(code, 1)
        self.assertIn("CVE-2026-7482", out)
        self.assertIn("CVE-2026-108836", out)
        self.assertIn("this version has no sign-in", out)
        self.assertIn("not reported by this version (no /api/status)", out)
        self.assertNotIn("\n\n\n", out)

    def test_cloud_off_still_leaks_account(self):
        with StandIn(cloud_disabled=True, models=[{"name": "llama3.1:8b"}]) as s:
            code, out = run(["--url", s.url, "--no-host"])
        self.assertEqual(code, 1)
        self.assertIn("Cloud      off (env); signed in as", out)
        self.assertIn("Cloud models are off, but anyone who can reach this server can still read", out)
        self.assertIn("ollama signout", out)

    def test_baseline(self):
        path = os.path.join(self.tmp.name, "models.json")
        models = [{"name": "llama3.1:8b", "digest": "a" * 64}]
        with StandIn(models=models, me=(404, None)) as s:
            code, _ = run(["--url", s.url, "--no-host", "--save-baseline", path])
            self.assertEqual(code, 0)
            models.append({"name": "gpt-4:latest", "digest": "b" * 64})
            code, out = run(["--url", s.url, "--no-host", "--baseline", path])
        self.assertEqual(code, 1)
        self.assertIn("NEW      gpt-4:latest", out)

    def test_unreachable_exits_3(self):
        code, out = run(["--url", "http://127.0.0.1:9", "--no-host", "--timeout", "2"])
        self.assertEqual(code, 3)
        self.assertIn("no answer", out)

    def test_logs_from_stdin(self):
        with mock.patch("sys.stdin", io.StringIO(SAMPLE)):
            code, out = run(["logs", "-"])
        self.assertEqual(code, 2)
        self.assertIn("198.51.100.23", out)
        self.assertIn("POST /api/pull", out)
        self.assertIn("X-Forwarded-For", out)


if __name__ == "__main__":
    unittest.main()
