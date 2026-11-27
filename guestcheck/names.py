"""Read an Ollama model list the way an investigator would: who put each model there?

Ollama names a model [host/][namespace/]model[:tag]. Models from the default registry show up
without a host ("llama3.1:8b", "huihui_ai/Qwen3.8-abliterated:latest"); anything pulled from
another registry keeps that registry's host in its name. That is what makes the list a visitors'
log: Rapid7's November 2026 scan of exposed servers found pulls from raw IP addresses and free
tunnels (the pull calls the stranger back), "I was here" names, names carrying the server's own
IP, and Base64 or hex strings that decode to file paths such as /etc/shadow.

Levels:
  stranger  very unlikely to be the owner's doing
  check     often a stranger's, but owners do this too (decide for yourself)
  info      worth knowing, not a sign of a visit by itself
  ok        nothing to say
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

STRANGER, CHECK, INFO, OK = "stranger", "check", "info", "ok"
LEVEL_ORDER = {STRANGER: 0, CHECK: 1, INFO: 2, OK: 3}

OFFICIAL_HOSTS = {"registry.ollama.ai", "ollama.com", "www.ollama.com"}
HUGGING_FACE_HOSTS = {"hf.co", "huggingface.co"}

# Free tunnels and throwaway registries: a public hostname in seconds, gone the next day.
TUNNEL_DOMAINS = (
    "trycloudflare.com",                      # Cloudflare Quick Tunnels
    "ngrok-free.app", "ngrok-free.dev", "ngrok.app", "ngrok.dev", "ngrok.io",
    "bore.pub",
    "ttl.sh",                                 # anonymous registry, images expire
    "pinggy.link", "pinggy.io", "pinggy.online", "pinggy.net",
    "loca.lt", "localtunnel.me",
    "serveo.net", "serveousercontent.com",
    "lhr.life", "localhost.run",
    "tunnelmole.net", "devtunnels.ms",
)

# Out-of-band testing services: a lookup or request to them is the whole point.
CALLBACK_DOMAINS = (
    "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me", "interact.sh",
    "burpcollaborator.net", "oastify.com", "dnslog.cn", "ceye.io", "requestbin.net",
    "pipedream.net", "webhook.site", "canarytokens.com", "canarytokens.org",
)

# "I was here" vocabulary. STRONG words are matched anywhere in the name ("dsv4probe"), the
# others only as the start of a word, because "verifier" or "canary" can be honest names.
STRONG_WORDS = ("pwn", "beacon", "probe", "ssrf", "zzvitals", "verif_sys", "ops-verify",
                "copy-test", "copytest", "write-test", "writetest", "backdoor", "callback")
WEAK_WORDS = ("verif", "canary", "marker", "poc", "rce", "recon", "pentest", "oast", "exploit",
              "hacked")

UNCENSORED = ("abliterated", "uncensored", "heretic", "obliterated", "jailbreak", "unfiltered")

# The cheapest models to pull when all you want to know is "can I write here?"
TINY_TEST_MODELS = ("tinyllama", "smollm2:135m", "smollm:135m")

# Closed models that can't run on a local Ollama: a model by this name is a copy of something
# else. Ollama's own docs suggest `ollama cp llama3.2 gpt-3.5-turbo` for tools that expect these
# names, so it may be yours.
CLOSED_MODEL = re.compile(
    r"^(gpt-?3\.5|gpt-?4|gpt-?5|chatgpt|text-davinci|claude|gemini|grok|o[134](-[a-z]+)?$)")

_B64 = re.compile(r"^[A-Za-z0-9+/_-]{8,}={0,2}$")
_HEX = re.compile(r"^(?:[0-9a-fA-F]{2}){4,}$")
_IP_IN_TEXT = re.compile(r"(?<![\d.])(\d{1,3})([._-])(\d{1,3})\2(\d{1,3})\2(\d{1,3})(?![\d])")
_TIMESTAMP = re.compile(r"(?<!\d)(1[5-9]\d{8}|20[0-4]\d{7})(?!\d)")
_TS_MIN, _TS_MAX = 1577836800, 2051222400        # 2020-01-01 .. 2035-01-01

# Decoded paths, sorted by what the visitor was after (first match wins).
PATH_GOALS = (
    ("Ollama's private key", re.compile(r"\.ollama/id_ed25519")),
    ("cloud metadata", re.compile(r"169\.254\.169\.254|metadata\.google\.internal|/opc/v[12]/")),
    ("persistence", re.compile(r"ld\.so\.preload|/etc/systemd/system/(?!ollama\.service)"
                               r"|/etc/cron|/etc/rc\.local|\.bashrc$|\.profile$")),
    ("credentials and keys", re.compile(r"/etc/shadow|authorized_keys|\.ssh/|id_rsa|id_ecdsa"
                                        r"|id_ed25519|\.aws/|\.netrc|\.git-credentials"
                                        r"|\.docker/config\.json|\.kube/config")),
    ("secrets in environment or service files", re.compile(
        r"/proc/[^/]+/environ|ollama\.service|override\.conf|/etc/environment|\.env$")),
    ("host fingerprinting", re.compile(r"/etc/passwd|/etc/hostname|/etc/hosts|/etc/os-release"
                                       r"|/proc/version|/proc/self/(cgroup|status|cmdline)"
                                       r"|/proc/cpuinfo|/etc/issue")),
)


@dataclass
class Name:
    """A model name split the way Ollama splits it."""
    raw: str
    host: str = ""
    namespace: str = ""
    model: str = ""
    tag: str = ""

    @property
    def hostname(self) -> str:
        """The host without a port or brackets."""
        h = self.host
        if h.startswith("["):
            return h[1:h.find("]")] if "]" in h else h[1:]
        if h.count(":") == 1:
            return h.split(":")[0]
        return h

    @property
    def bare(self) -> str:
        """Everything except the host: the part a stranger chooses freely."""
        parts = [p for p in (self.namespace, self.model) if p]
        return "/".join(parts) + (":" + self.tag if self.tag else "")


def parse_name(raw: str) -> Name:
    """Split [scheme://][host/][namespace/]model[:tag]. A tag can't hold '/', so a ':' after the
    last '/' starts the tag and a ':' before it belongs to the host's port."""
    n = Name(raw=raw)
    s = raw.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    if s.rfind(":") > s.rfind("/"):
        s, n.tag = s.rsplit(":", 1)
    parts = s.split("/")
    if len(parts) >= 3:
        n.host = parts[0]
        n.namespace = "/".join(parts[1:-1])
        n.model = parts[-1]
    elif len(parts) == 2:
        n.namespace, n.model = parts
    else:
        n.model = parts[0]
    return n


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# Networks an owner's own registry could sit on. (ipaddress.is_private would also count the
# documentation ranges, which the tests use as stand-ins for public addresses.)
PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"))


def is_private(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a.version == n.version and a in n for n in PRIVATE_NETS)


def _domain_in(hostname: str, domains) -> str:
    h = hostname.lower().rstrip(".")
    for d in domains:
        if h == d or h.endswith("." + d):
            return d
    return ""


def registry_kind(name: Name) -> tuple[str, str]:
    """(kind, detail) for the registry a model came from."""
    if not name.host:
        return "official", ""
    h = name.hostname.lower()
    if h in OFFICIAL_HOSTS:
        return "official", h
    if h in HUGGING_FACE_HOSTS:
        return "huggingface", h
    if _is_ip(h):
        return ("private-ip" if is_private(h) else "ip"), name.host
    if h == "localhost" or h.endswith((".localhost", ".local", ".internal", ".lan")):
        return "private-ip", name.host
    d = _domain_in(h, CALLBACK_DOMAINS)
    if d:
        return "callback", d
    d = _domain_in(h, TUNNEL_DOMAINS)
    if d:
        return "tunnel", d
    return "other", h


def _printable_path(data: bytes) -> str:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return ""
    if len(text) < 4 or any(not (32 <= ord(c) < 127) for c in text):
        return ""
    if text.startswith(("/", "~/")) or re.match(r"^[A-Za-z]:\\", text):
        return text
    if "169.254.169.254" in text or "metadata.google.internal" in text:
        return text
    return ""


def decode_paths(name: Name) -> list[str]:
    """File paths hidden in the name as Base64 or hex, e.g. L2V0Yy9zaGFkb3c -> /etc/shadow."""
    found = []
    pieces = re.split(r"[/:]", name.bare)
    for piece in pieces:
        candidates = {piece} | set(re.split(r"[._]", piece))
        for c in sorted(candidates, key=len, reverse=True):
            text = ""
            if _HEX.match(c):
                try:
                    text = _printable_path(binascii.unhexlify(c))
                except (binascii.Error, ValueError):
                    text = ""
            if not text and _B64.match(c):
                s = c.rstrip("=")
                s = s + "=" * (-len(s) % 4)
                for alt in (s, s.replace("-", "+").replace("_", "/")):
                    try:
                        text = _printable_path(base64.b64decode(alt, validate=True))
                    except (binascii.Error, ValueError):
                        text = ""
                    if text:
                        break
            if text and text not in found:
                found.append(text)
                break
    return found


def path_goal(path: str) -> str:
    for goal, rx in PATH_GOALS:
        if rx.search(path):
            return goal
    return "other files"


def embedded_ips(text: str) -> list[str]:
    """IPv4 addresses written into a name with dots, dashes or underscores (one kind per address).
    Short runs such as 2.5.0.5 (version numbers) are ignored."""
    out = []
    for m in _IP_IN_TEXT.finditer(text):
        octets = [m.group(1), m.group(3), m.group(4), m.group(5)]
        if sum(len(o) for o in octets) < 6 or any(int(o) > 255 for o in octets):
            continue
        ip = ".".join(str(int(o)) for o in octets)
        if ip not in out:
            out.append(ip)
    return out


def embedded_times(text: str) -> list[str]:
    """Unix timestamps in a name (Rapid7 dated markers this way), as UTC dates."""
    out = []
    for m in _TIMESTAMP.finditer(text):
        ts = int(m.group(1))
        if _TS_MIN <= ts <= _TS_MAX:
            out.append(datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    return out


def is_cloud(name: Name, entry: dict | None = None) -> bool:
    if entry and entry.get("remote_host"):
        return True
    return name.tag == "cloud" or name.tag.endswith("-cloud")


@dataclass
class Finding:
    name: str
    level: str = OK
    reasons: list[str] = field(default_factory=list)
    registry: str = "official"
    paths: list[str] = field(default_factory=list)
    times: list[str] = field(default_factory=list)
    cloud: bool = False
    modified_at: str = ""
    digest: str = ""

    def raise_to(self, level: str, reason: str) -> None:
        if LEVEL_ORDER[level] < LEVEL_ORDER[self.level]:
            self.level = level
        if reason not in self.reasons:
            self.reasons.append(reason)

    def as_dict(self) -> dict:
        return {"name": self.name, "level": self.level, "reasons": self.reasons,
                "registry": self.registry, "decoded_paths": self.paths, "embedded_times": self.times,
                "cloud": self.cloud, "modified_at": self.modified_at, "digest": self.digest}


def classify(entry: dict, own_ips: set[str] | frozenset = frozenset(),
             same_digest: list[str] | None = None) -> Finding:
    """Judge one entry of /api/tags. own_ips: this server's addresses (a name that carries one
    was written by someone keeping a list of targets)."""
    raw = entry.get("name") or entry.get("model") or ""
    n = parse_name(raw)
    f = Finding(name=raw, modified_at=str(entry.get("modified_at", ""))[:19],
                digest=str(entry.get("digest", ""))[:12])
    bare_l = n.bare.lower()
    model_l = n.model.lower()

    kind, detail = registry_kind(n)
    f.registry = kind
    if kind == "ip":
        f.raise_to(STRANGER, f"pulled from a raw IP address ({n.host}); the pull called that address back")
    elif kind == "tunnel":
        f.raise_to(STRANGER, f"pulled through a free tunnel or throwaway registry ({detail})")
    elif kind == "callback":
        f.raise_to(STRANGER, f"pulled from an out-of-band testing service ({detail})")
    elif kind == "private-ip":
        f.raise_to(CHECK, f"pulled from a private or local address ({n.host}): your own registry?")
    elif kind == "other":
        f.raise_to(CHECK, f"pulled from a registry other than Ollama's ({detail}): yours?")
    elif kind == "huggingface":
        f.raise_to(INFO, "pulled from Hugging Face")

    for word in STRONG_WORDS:
        if word in bare_l:
            f.raise_to(STRANGER, f'marker word "{word}" in the name')
            break
    else:
        tokens = [t for t in re.split(r"[^a-z0-9]+", bare_l) if t]
        for word in WEAK_WORDS:
            if any(t.startswith(word) for t in tokens):
                f.raise_to(CHECK, f'"{word}" in the name, common in strangers\' markers')
                break

    for ip in embedded_ips(n.bare):
        if ip in own_ips:
            f.raise_to(STRANGER, f"carries this server's own IP address ({ip}): someone's target list")
        else:
            f.raise_to(CHECK, f"carries an IP address ({ip})")

    f.paths = decode_paths(n)
    for p in f.paths:
        f.raise_to(STRANGER, f"hides a file path: {p} ({path_goal(p)})")

    f.times = embedded_times(n.bare)
    if f.times and f.level in (STRANGER, CHECK):
        f.reasons.append("time written into the name: " + ", ".join(f.times))

    f.cloud = is_cloud(n, entry)
    remote = str(entry.get("remote_host") or "")
    if f.cloud:
        f.raise_to(INFO, "runs on Ollama's cloud, paid by the account this server is signed in to")
        if remote:
            host = re.sub(r"^[a-z]+://", "", remote).split("/")[0].split(":")[0].lower()
            if host and host not in OFFICIAL_HOSTS:
                f.raise_to(CHECK, f"routes requests to {host}, not ollama.com")
    elif (not n.host and not n.namespace and CLOSED_MODEL.match(model_l)
          and not model_l.startswith("gpt-oss")):
        msg = "named after a closed model that can't run locally, so it's a copy of another model"
        if same_digest:
            msg += f" (same digest as {', '.join(same_digest[:3])})"
        f.raise_to(CHECK, msg + ": did you make it?")

    if any(w in bare_l for w in UNCENSORED):
        f.raise_to(INFO, "refusals removed (abliterated or uncensored)")
    if any(raw.lower().startswith(t) for t in TINY_TEST_MODELS):
        f.raise_to(INFO, "the cheapest model to pull when testing write access: did you pull it?")
    if same_digest and f.level in (STRANGER, CHECK) and not any("digest" in r for r in f.reasons):
        f.reasons.append(f"same digest as {', '.join(same_digest[:3])}")
    return f


def classify_all(models: list[dict], own_ips: set[str] | frozenset = frozenset()) -> list[Finding]:
    """Judge the whole list. Copies share a digest, which shows what a premium-named copy really is."""
    by_digest: dict[str, list[str]] = {}
    for m in models:
        d = m.get("digest")
        if d:
            by_digest.setdefault(d, []).append(m.get("name") or m.get("model") or "")
    out = []
    for m in models:
        name = m.get("name") or m.get("model") or ""
        twins = [x for x in by_digest.get(m.get("digest") or "", []) if x != name]
        out.append(classify(m, own_ips, twins or None))
    out.sort(key=lambda f: (LEVEL_ORDER[f.level], f.name))
    return out
