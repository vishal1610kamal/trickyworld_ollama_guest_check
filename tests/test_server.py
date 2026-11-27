import socket
import unittest

from guestcheck import server as S
from tests.helpers import SIGNIN_URL, StandIn, load_fixture

READ_ONLY = {("GET", "/api/version"), ("GET", "/api/tags"), ("GET", "/api/status"), ("GET", "/api/ps"),
             ("POST", "/api/me"), ("GET", "/api/usage?range=30d&group_by=model"), ("GET", "/api/balance")}

USAGE = {"range": "30d", "scope": "self", "granularity": "day",
         "totals": {"request_count": 418, "usage_usd": 37.62, "input_tokens": 9100000,
                    "cached_input_tokens": 0, "output_tokens": 1500000,
                    "groups": [{"model": "kimi-k3", "request_count": 300, "usage_usd": 31.5},
                               {"model": "glm-5.3", "request_count": 118, "usage_usd": 6.12}]},
         "buckets": []}
BALANCE = {"included": {"balance_usd": 22.38, "allowance_usd": 60,
                        "period": {"from": "2026-11-05T00:00:00Z", "until": "2026-12-05T00:00:00Z"}},
           "purchased": {"balance_usd": 0}}


class Inspect(unittest.TestCase):
    def test_signed_in_server_gives_away_the_account(self):
        with StandIn(models=load_fixture("rapid7_sample.json")["models"], usage=USAGE, balance=BALANCE) as s:
            r = S.inspect(s.url, usage=True)
            self.assertTrue(set(s.requests) <= READ_ONLY, s.requests)
        self.assertTrue(r["reachable"])
        self.assertEqual(r["version"], "0.40.18")
        self.assertEqual(len(r["models"]), 28)
        self.assertEqual(r["cloud"], {"disabled": False, "source": "none"})
        a = r["account"]
        self.assertEqual(a["state"], "signed-in")
        self.assertEqual(a["email"], "a***@example.com")
        self.assertEqual(a["plan"], "pro")
        self.assertIn("email", a["exposed_fields"])
        self.assertEqual(r["usage"]["usage_usd"], 37.62)
        self.assertEqual(r["usage"]["by_model"][0], {"model": "kimi-k3", "requests": 300, "usd": 31.5})
        self.assertEqual(r["usage"]["included_usd"], 22.38)

    def test_show_account(self):
        with StandIn() as s:
            r = S.inspect(s.url, show_account=True)
        self.assertEqual(r["account"]["email"], "alice@example.com")

    def test_signed_out_server_gives_away_its_name(self):
        with StandIn(me=(401, {"error": "unauthorized", "signin_url": SIGNIN_URL})) as s:
            r = S.inspect(s.url)
        self.assertEqual(r["account"]["state"], "signed-out")
        self.assertEqual(r["account"]["hostname_in_signin_url"], "gpu-box-01")
        self.assertTrue(r["account"]["signin_url_has_key"])

    def test_cloud_switch_blocks_usage_but_not_me(self):
        with StandIn(cloud_disabled=True) as s:
            r = S.inspect(s.url, usage=True)
        self.assertEqual(r["cloud"], {"disabled": True, "source": "env"})
        self.assertEqual(r["account"]["state"], "signed-in")
        self.assertEqual(r["usage"]["usage_status"], 403)
        self.assertIn("ollama cloud is disabled", r["usage"]["usage_error"])

    def test_old_server_without_sign_in(self):
        with StandIn(version="0.5.7", me=(404, None), status=False) as s:
            r = S.inspect(s.url)
        self.assertEqual(r["account"]["state"], "no-endpoint")
        self.assertIsNone(r["cloud"]["disabled"])

    def test_no_account_check_means_no_post(self):
        with StandIn() as s:
            S.inspect(s.url, account=False)
            self.assertNotIn(("POST", "/api/me"), s.requests)

    def test_unreachable(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        r = S.inspect(f"http://127.0.0.1:{port}", timeout=2)
        self.assertFalse(r["reachable"])
        self.assertTrue(r["error"])

    def test_mask_email(self):
        self.assertEqual(S.mask_email("alice@example.com"), "a***@example.com")
        self.assertEqual(S.mask_email("bob"), "b***")
        self.assertEqual(S.mask_email(""), "")


if __name__ == "__main__":
    unittest.main()
