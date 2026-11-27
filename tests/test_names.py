import unittest

from guestcheck import names as N
from tests.helpers import load_fixture

OWN = {"203.0.113.10"}


class ParseName(unittest.TestCase):
    def test_library_model(self):
        n = N.parse_name("llama3.1:8b")
        self.assertEqual((n.host, n.namespace, n.model, n.tag), ("", "", "llama3.1", "8b"))

    def test_namespaced_model(self):
        n = N.parse_name("huihui_ai/Qwen3.8-abliterated:latest")
        self.assertEqual((n.host, n.namespace, n.model, n.tag), ("", "huihui_ai", "Qwen3.8-abliterated", "latest"))

    def test_host_with_port(self):
        n = N.parse_name("198.51.100.23:9882/trigger/benign:latest")
        self.assertEqual(n.host, "198.51.100.23:9882")
        self.assertEqual(n.hostname, "198.51.100.23")
        self.assertEqual((n.namespace, n.model, n.tag), ("trigger", "benign", "latest"))
        self.assertEqual(n.bare, "trigger/benign:latest")

    def test_scheme_and_ipv6(self):
        n = N.parse_name("http://[2001:db8::7]:5000/a/b:c")
        self.assertEqual(n.hostname, "2001:db8::7")
        self.assertEqual((n.namespace, n.model, n.tag), ("a", "b", "c"))

    def test_no_tag(self):
        n = N.parse_name("ttl.sh/dsv40110/dsv4probe")
        self.assertEqual((n.host, n.model, n.tag), ("ttl.sh", "dsv4probe", ""))


class Registry(unittest.TestCase):
    def kind(self, name):
        return N.registry_kind(N.parse_name(name))[0]

    def test_kinds(self):
        self.assertEqual(self.kind("llama3.1:8b"), "official")
        self.assertEqual(self.kind("registry.ollama.ai/library/llama3.1:8b"), "official")
        self.assertEqual(self.kind("hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M"), "huggingface")
        self.assertEqual(self.kind("198.51.100.23:9882/trigger/benign:latest"), "ip")
        self.assertEqual(self.kind("10.0.0.5:5000/team/model:latest"), "private-ip")
        self.assertEqual(self.kind("registry.local/team/model:latest"), "private-ip")
        self.assertEqual(self.kind("quick-red-fox.trycloudflare.com/read/x:1"), "tunnel")
        self.assertEqual(self.kind("abc.ngrok-free.app/a/b:c"), "tunnel")
        self.assertEqual(self.kind("bore.pub:41234/a/b:c"), "tunnel")
        self.assertEqual(self.kind("x1y2.oast.fun/a/b:c"), "callback")
        self.assertEqual(self.kind("registry.example.com/team/model:1"), "other")


class Decoding(unittest.TestCase):
    def paths(self, name):
        return N.decode_paths(N.parse_name(name))

    def test_rapid7_examples(self):
        self.assertEqual(self.paths("quick-red-fox.trycloudflare.com/read/L2V0Yy9zaGFkb3c:latest"), ["/etc/shadow"])
        self.assertEqual(self.paths("t.trycloudflare.com/read/L3Byb2Mvc2VsZi9lbnZpcm9u:latest"),
                         ["/proc/self/environ"])

    def test_hex_and_urlsafe(self):
        self.assertEqual(self.paths("x/2f6574632f706173737764:1"), ["/etc/passwd"])
        # URL-safe Base64 uses "_" and "-" where the standard alphabet has "/" and "+"
        self.assertEqual(self.paths("x/L3Jvb3QvLnNzaC9pZF9lZDI1NTE5Pz8_:latest"), ["/root/.ssh/id_ed25519???"])
        self.assertEqual(self.paths("x/L3Jvb3QvLmF3cy9jcmVkZW50aWFscz8-:1"), ["/root/.aws/credentials?>"])

    def test_no_false_paths(self):
        for name in ("instruct:latest", "quick-red-fox.trycloudflare.com/read/x5fa4534:b1",
                     "huihui_ai/Qwen3.8-abliterated:latest", "deepseek-v4-pro:cloud",
                     "qwen3-embedding:0.6b", "nomic-embed-text:latest", "mxbai-embed-large:335m",
                     "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M", "deadbeefcafebabe:latest"):
            self.assertEqual(self.paths(name), [], name)

    def test_goals(self):
        self.assertEqual(N.path_goal("/etc/shadow"), "credentials and keys")
        self.assertEqual(N.path_goal("/proc/self/environ"), "secrets in environment or service files")
        self.assertEqual(N.path_goal("/etc/systemd/system/ollama.service.d/override.conf"),
                         "secrets in environment or service files")
        self.assertEqual(N.path_goal("/usr/share/ollama/.ollama/id_ed25519"), "Ollama's private key")
        self.assertEqual(N.path_goal("/etc/ld.so.preload"), "persistence")
        self.assertEqual(N.path_goal("/etc/systemd/system/sysupd.service"), "persistence")
        self.assertEqual(N.path_goal("http://169.254.169.254/opc/v2/instance/"), "cloud metadata")
        self.assertEqual(N.path_goal("/etc/passwd"), "host fingerprinting")


class Embedded(unittest.TestCase):
    def test_ips(self):
        self.assertEqual(N.embedded_ips("pwn_ctl_203.0.113.10_ae52:latest"), ["203.0.113.10"])
        self.assertEqual(N.embedded_ips("seen-203-0-113-10"), ["203.0.113.10"])
        self.assertEqual(N.embedded_ips("qwen2.5-0.5b"), [])
        self.assertEqual(N.embedded_ips("model-300.1.1.1"), [])

    def test_times(self):
        self.assertEqual(N.embedded_times("probe-1781000000"), ["2026-06-09 10:13 UTC"])
        self.assertEqual(N.embedded_times("build-9999999999"), [])


class Classify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.found = {f.name: f for f in N.classify_all(load_fixture("rapid7_sample.json")["models"], OWN)}

    def level(self, name):
        return self.found[name].level

    def test_counts(self):
        levels = [f.level for f in self.found.values()]
        self.assertEqual(len(levels), 28)
        self.assertEqual(levels.count(N.STRANGER), 10)
        self.assertEqual(levels.count(N.CHECK), 2)
        self.assertEqual(levels.count(N.INFO), 9)
        self.assertEqual(levels.count(N.OK), 7)

    def test_strangers(self):
        for name in ("198.51.100.23:9882/trigger/benign:latest", "zzvitals-beacon:latest", "verif_sys:latest",
                     "quick-red-fox.trycloudflare.com/read/x5fa4534:b1", "pwn_ctl_203.0.113.10_ae52:latest",
                     "ttl.sh/dsv40110/dsv4probe:24h", "ops-verify:latest", "gpt-4o:latest-copy-test",
                     "quick-red-fox.trycloudflare.com/read/L2V0Yy9zaGFkb3c:latest",
                     "quick-red-fox.trycloudflare.com/read/L3Byb2Mvc2VsZi9lbnZpcm9u:latest"):
            self.assertEqual(self.level(name), N.STRANGER, name)

    def test_own_ip_reason(self):
        reasons = " ".join(self.found["pwn_ctl_203.0.113.10_ae52:latest"].reasons)
        self.assertIn("this server's own IP address (203.0.113.10)", reasons)

    def test_aliases_are_checks_with_their_twin(self):
        for name in ("gpt-4o:latest", "claude-3-opus:latest"):
            f = self.found[name]
            self.assertEqual(f.level, N.CHECK)
            self.assertIn("tinyllama:latest", " ".join(f.reasons))

    def test_cloud_and_info(self):
        for name in ("glm-5.3:cloud", "deepseek-v4-pro:cloud", "kimi-k2.7-code:cloud", "minimax-m3:cloud",
                     "mistral-large-4:cloud"):
            self.assertTrue(self.found[name].cloud, name)
            self.assertEqual(self.level(name), N.INFO)
        self.assertEqual(self.level("huihui_ai/Qwen3.8-abliterated:latest"), N.INFO)
        self.assertEqual(self.level("tinyllama:latest"), N.INFO)

    def test_ordinary_models_pass(self):
        for name in ("llama3.1:8b", "qwen3.6:27b", "nomic-embed-text:latest", "gemma4:e4b",
                     "qwen2.5-coder:7b", "bge-m3:latest", "qwen3-embedding:0.6b"):
            self.assertEqual(self.level(name), N.OK, name)

    def test_honest_names_are_not_strangers(self):
        for name in ("gpt-oss:20b", "gpt-oss:120b-cloud", "math-verifier:7b", "someone/claude-distill:latest",
                     "hf.co/bartowski/Llama-3.2-1B-Instruct-GGUF:Q4_K_M", "nvidia/canary-1b:latest",
                     "gemma3:4b", "deepseek-r1:8b", "llava:13b", "codellama:7b-instruct"):
            f = N.classify({"name": name}, OWN)
            self.assertNotEqual(f.level, N.STRANGER, name)
        self.assertEqual(N.classify({"name": "gpt-oss:20b"}).level, N.OK)
        self.assertEqual(N.classify({"name": "someone/claude-distill:latest"}).level, N.OK)

    def test_other_ip_and_private_registry_are_checks(self):
        self.assertEqual(N.classify({"name": "seen-198-51-100-77:latest"}, OWN).level, N.CHECK)
        self.assertEqual(N.classify({"name": "10.0.0.5:5000/team/model:latest"}, OWN).level, N.CHECK)

    def test_remote_host_elsewhere(self):
        f = N.classify({"name": "mine:cloud", "remote_host": "https://llm.example.net"})
        self.assertEqual(f.level, N.CHECK)
        self.assertIn("llm.example.net", " ".join(f.reasons))

    def test_timestamp_on_marker(self):
        f = N.classify({"name": "probe-1781000000:latest"})
        self.assertEqual(f.level, N.STRANGER)
        self.assertIn("2026-06-09", " ".join(f.reasons))


if __name__ == "__main__":
    unittest.main()
