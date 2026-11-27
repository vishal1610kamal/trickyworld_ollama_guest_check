import os
import tempfile
import unittest

from guestcheck import host as H
from tests.helpers import build_host_root


class ProcNet(unittest.TestCase):
    def test_ipv4_listen_only(self):
        text = ("  sl  local_address rem_address   st\n"
                "   0: 00000000:2CAA 00000000:0000 0A 0\n"
                "   1: 0100007F:2CAA 00000000:0000 0A 0\n"
                "   2: 0A7100CB:2CAA 646433C6:D431 01 0\n"
                "   3: 0100007F:0277 00000000:0000 0A 0\n")
        self.assertEqual(H.parse_proc_net(text, 11434), ["0.0.0.0", "127.0.0.1"])

    def test_ipv6(self):
        text = ("  sl  local_address                         remote_address                        st\n"
                "   0: 00000000000000000000000001000000:2CAA 00000000000000000000000000000000:0000 0A\n"
                "   1: 00000000000000000000000000000000:2CAA 00000000000000000000000000000000:0000 0A\n")
        self.assertEqual(H.parse_proc_net(text, 11434), ["::1", "::"])


class HostTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_bind_all_with_secrets(self):
        build_host_root(self.root)
        r = H.inspect_host(11434, self.root)
        self.assertEqual(r["listening"]["addresses"], ["0.0.0.0"])
        self.assertEqual(r["listening"]["beyond_localhost"], ["0.0.0.0"])
        self.assertEqual(r["unit"]["environment"]["OLLAMA_HOST"], "0.0.0.0:11434")
        secrets = {s["name"]: s for s in r["unit"]["secrets"]}
        self.assertEqual(set(secrets), {"OPENAI_API_KEY", "HF_TOKEN"})
        self.assertTrue(secrets["OPENAI_API_KEY"]["world_readable"])
        self.assertFalse(secrets["HF_TOKEN"]["world_readable"])
        self.assertNotIn("not-a-real-key", repr(r))           # values never leave the module
        self.assertEqual(r["keys"][0]["mode"], "0o644")
        self.assertTrue(r["keys"][0]["too_open"])
        self.assertEqual(r["own_ips"], ["2001:db8::10", "203.0.113.10"])

    def test_localhost_only_clean(self):
        build_host_root(self.root, bind_all=False, secret=False, key_mode=0o600)
        r = H.inspect_host(11434, self.root)
        self.assertEqual(r["listening"]["beyond_localhost"], [])
        self.assertEqual(r["unit"]["secrets"], [])
        self.assertFalse(r["keys"][0]["too_open"])

    def test_empty_environment_resets(self):
        build_host_root(self.root, secret=False)
        with open(os.path.join(self.root, "etc/systemd/system/ollama.service.d/zz-reset.conf"), "w") as fh:
            fh.write("[Service]\nEnvironment=\nEnvironment=OLLAMA_NO_CLOUD=1\n")
        env = H.unit_config(self.root)["environment"]
        self.assertNotIn("OLLAMA_HOST", env)
        self.assertEqual(env["OLLAMA_NO_CLOUD"], "1")

    def test_cloud_switch_file(self):
        build_host_root(self.root)
        path = os.path.join(self.root, "usr/share/ollama/.ollama/server.json")
        with open(path, "w") as fh:
            fh.write('{"disable_ollama_cloud": true}')
        self.assertEqual(H.cloud_switch_files(self.root),
                         [{"file": "/usr/share/ollama/.ollama/server.json", "disable_ollama_cloud": True}])
        self.assertTrue(os.path.exists(path))

    def test_nothing_there(self):
        r = H.inspect_host(11434, self.root)
        self.assertFalse(r["listening"]["checked"])
        self.assertEqual(r["unit"]["files"], [])
        self.assertEqual(r["keys"], [])


class Parsing(unittest.TestCase):
    def test_environment_line(self):
        self.assertEqual(H.parse_environment('"OLLAMA_HOST=0.0.0.0:11434" "A=two words" B=3'),
                         [("OLLAMA_HOST", "0.0.0.0:11434"), ("A", "two words"), ("B", "3")])

    def test_env_file(self):
        self.assertEqual(H.parse_env_file('# c\nexport A="1 2"\nB=3\n\n;x\n'), [("A", "1 2"), ("B", "3")])

    def test_looks_secret(self):
        self.assertTrue(H.looks_secret("OPENAI_API_KEY", "anything"))
        self.assertTrue(H.looks_secret("UPSTREAM", "hf_" + "B" * 24))
        self.assertFalse(H.looks_secret("OLLAMA_KEEP_ALIVE", "24h"))
        self.assertFalse(H.looks_secret("OLLAMA_AUTH", "true"))
        self.assertFalse(H.looks_secret("OLLAMA_HOST", "0.0.0.0"))


if __name__ == "__main__":
    unittest.main()
