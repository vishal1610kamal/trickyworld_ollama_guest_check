import unittest

from guestcheck import logs as L

# The first line's format is copied from a real Ollama journal; the addresses are documentation ones.
SAMPLE = """\
Nov 27 11:24:26 box ollama[3030]: [GIN] 2026/11/27 - 11:24:26 | 200 |     459.706µs |       127.0.0.1 | GET      "/api/tags"
Nov 27 11:25:01 box ollama[3030]: [GIN] 2026/11/27 - 11:25:01 | 200 |  3.20112ms |  198.51.100.23 | GET      "/api/tags"
Nov 27 11:25:03 box ollama[3030]: [GIN] 2026/11/27 - 11:25:03 | 200 |  1.9s |  198.51.100.23 | POST     "/api/pull"
Nov 27 11:25:09 box ollama[3030]: [GIN] 2026/11/27 - 11:25:09 | 200 |  12ms |  198.51.100.23 | POST     "/api/copy"
Nov 27 11:25:10 box ollama[3030]: [GIN] 2026/11/27 - 11:25:10 | 200 |  480ms |  198.51.100.23 | POST     "/api/me"
Nov 27 11:26:00 box ollama[3030]: [GIN] 2026/11/27 - 11:26:00 | 200 |  4.1s |  2001:db8::9 | POST     "/api/chat"
\x1b[97;42m[GIN] 2026/11/27 - 11:27:00 | 200 |  9ms |  127.0.0.1 | \x1b[97;46mPOST    \x1b[0m "/api/generate"
Nov 27 11:28:00 box ollama[3030]: time=2026-11-27T11:28:00 level=INFO msg="not a request line"
"""


class Logs(unittest.TestCase):
    def test_parse(self):
        e = L.parse(SAMPLE.splitlines())
        self.assertEqual(len(e), 7)
        self.assertEqual(e[0], {"time": "2026/11/27 11:24:26", "status": 200, "ip": "127.0.0.1",
                                "method": "GET", "path": "/api/tags", "kind": "read"})
        self.assertEqual([x["kind"] for x in e[2:5]], ["changes models", "changes models", "account"])
        self.assertEqual(e[5]["ip"], "2001:db8::9")
        self.assertEqual(e[6]["path"], "/api/generate")

    def test_kinds(self):
        self.assertEqual(L.kind("DELETE", "/api/delete"), "changes models")
        self.assertEqual(L.kind("POST", "/api/blobs/sha256:00"), "changes models")
        self.assertEqual(L.kind("GET", "/api/usage?range=30d"), "account")
        self.assertEqual(L.kind("POST", "/api/experimental/web_search"), "account")
        self.assertEqual(L.kind("POST", "/v1/chat/completions"), "inference")
        self.assertEqual(L.kind("GET", "/api/version"), "read")

    def test_summary_flags_the_stranger(self):
        s = L.summarize(L.parse(SAMPLE.splitlines()))
        self.assertEqual(s["requests"], 7)
        first = s["callers"][0]
        self.assertEqual(first["ip"], "198.51.100.23")
        self.assertTrue(first["flag"].startswith("changed models"))
        self.assertEqual(first["kinds"], {"read": 1, "changes models": 2, "account": 1})
        self.assertEqual(len(first["examples"]), 3)
        v6 = [c for c in s["callers"] if c["ip"] == "2001:db8::9"][0]
        self.assertEqual(v6["flag"], "non-local caller")
        self.assertEqual(s["non_local"], 2)
        self.assertIn("X-Forwarded-For", s["caveat"])


if __name__ == "__main__":
    unittest.main()
