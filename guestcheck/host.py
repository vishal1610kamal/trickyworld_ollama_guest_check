"""Checks that need the machine Ollama runs on (Linux): what it listens on, how the service is
configured, whether secrets sit in its unit files, and where its ollama.com key lives.

Everything is read-only. Secret values are never printed or returned, only their names.
`root` lets you point the checks at a copy of a server's files (a mounted disk image, or the test
fixtures) instead of "/".
"""
from __future__ import annotations

import glob
import ipaddress
import json
import os
import re
import shlex
import stat

UNIT_FILES = (
    "etc/systemd/system/ollama.service",
    "etc/systemd/system/ollama.service.d/*.conf",
    "run/systemd/system/ollama.service.d/*.conf",
    "usr/lib/systemd/system/ollama.service",
    "lib/systemd/system/ollama.service",
    "usr/lib/systemd/system/ollama.service.d/*.conf",
)
USER_UNIT_FILES = (
    ".config/systemd/user/ollama.service",
    ".config/systemd/user/ollama.service.d/*.conf",
)
# The Linux service runs as user "ollama" with home /usr/share/ollama (Ollama's install script).
SERVICE_HOMES = ("usr/share/ollama", "root")

SECRET_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|_AUTH|AUTH_)", re.I)
SECRET_VALUE = re.compile(
    r"^(sk-[A-Za-z0-9_-]{16,}|hf_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}"
    r"|A[KS]IA[0-9A-Z]{16}|xox[abposr]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}"
    r"|AIza[0-9A-Za-z_-]{30,})")
NOT_SECRET_VALUES = {"", "0", "1", "true", "false", "yes", "no", "on", "off"}
WATCHED = ("OLLAMA_HOST", "OLLAMA_ORIGINS", "OLLAMA_NO_CLOUD", "OLLAMA_REMOTES", "OLLAMA_MODELS")


def _p(root: str, rel: str) -> str:
    return os.path.join(root, rel.lstrip("/"))


def _shown(root: str, path: str) -> str:
    """The path as it is on the server, without the --root prefix."""
    if root in ("", "/"):
        return path
    rel = os.path.relpath(path, root)
    return path if rel.startswith("..") else "/" + rel


# ---------------------------------------------------------------- listening sockets

def _hex_ip(h: str) -> str:
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return str(ipaddress.IPv6Address(words))


def parse_proc_net(text: str, port: int) -> list[str]:
    """Listening addresses for a port from /proc/net/tcp or tcp6 (state 0A = LISTEN)."""
    out = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4 or cols[3] != "0A" or ":" not in cols[1]:
            continue
        addr_hex, port_hex = cols[1].rsplit(":", 1)
        try:
            if int(port_hex, 16) != port:
                continue
            ip = _hex_ip(addr_hex)
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def listening(port: int, root: str = "/") -> dict:
    addrs, readable = [], False
    for name in ("proc/net/tcp", "proc/net/tcp6"):
        try:
            with open(_p(root, name)) as fh:
                addrs += [a for a in parse_proc_net(fh.read(), port) if a not in addrs]
            readable = True
        except OSError:
            pass
    beyond = [a for a in addrs if not ipaddress.ip_address(a).is_loopback]
    return {"port": port, "addresses": addrs, "beyond_localhost": beyond, "checked": readable}


# ---------------------------------------------------------------- local addresses

def local_ips(root: str = "/") -> set[str]:
    """This machine's own addresses: /proc/net/fib_trie (IPv4) and /proc/net/if_inet6."""
    ips: set[str] = set()
    try:
        with open(_p(root, "proc/net/fib_trie")) as fh:
            lines = fh.read().splitlines()
        for prev, line in zip(lines, lines[1:]):
            if "/32 host LOCAL" in line:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", prev)
                if m:
                    ips.add(m.group(1))
    except OSError:
        pass
    try:
        with open(_p(root, "proc/net/if_inet6")) as fh:
            for line in fh:
                h = line.split()[0] if line.split() else ""
                if len(h) == 32:
                    ips.add(str(ipaddress.IPv6Address(bytes.fromhex(h))))
    except (OSError, ValueError):
        pass
    return {i for i in ips if not ipaddress.ip_address(i).is_loopback}


# ---------------------------------------------------------------- unit files

def parse_environment(value: str) -> list[tuple[str, str]]:
    """Assignments in one Environment= line: Environment="A=1" "B=two words" C=3."""
    try:
        words = shlex.split(value, posix=True)
    except ValueError:
        words = value.split()
    out = []
    for w in words:
        if "=" in w:
            k, v = w.split("=", 1)
            out.append((k.strip(), v))
    return out


def parse_env_file(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("export "):
            line = line[7:]
        if "=" in line:
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out.append((k.strip(), v))
    return out


def _mode(path: str) -> dict:
    try:
        st = os.stat(path)
    except OSError as e:
        return {"error": e.strerror or str(e)}
    return {"mode": oct(stat.S_IMODE(st.st_mode)), "world_readable": bool(st.st_mode & stat.S_IROTH)}


def looks_secret(name: str, value: str) -> bool:
    if SECRET_VALUE.match(value or ""):
        return True
    return bool(SECRET_NAME.search(name)) and (value or "").strip().lower() not in NOT_SECRET_VALUES


def unit_config(root: str = "/", home: str | None = None) -> dict:
    """Read the ollama.service unit and its drop-ins in the order systemd applies them."""
    files: list[str] = []
    for pattern in UNIT_FILES:
        files += sorted(glob.glob(_p(root, pattern)))
    if home:
        for pattern in USER_UNIT_FILES:
            files += sorted(glob.glob(os.path.join(home, pattern)))
    env: dict[str, tuple[str, str]] = {}       # name -> (value, actual path of the file)
    secrets, env_files, unreadable = [], [], []
    exec_start = ""
    for path in files:
        try:
            with open(path) as fh:
                text = fh.read()
        except OSError as e:
            unreadable.append({"file": _shown(root, path), "error": e.strerror or str(e)})
            continue
        for line in text.splitlines():
            s = line.strip()
            if s.startswith(("#", ";")) or "=" not in s:
                continue
            key, value = s.split("=", 1)
            key = key.strip()
            if key == "Environment":
                if not value.strip():
                    env.clear()                 # an empty assignment resets the list
                for k, v in parse_environment(value):
                    env[k] = (v, path)
            elif key == "EnvironmentFile":
                ef = value.strip().lstrip("-")
                ef_path = _p(root, ef) if root != "/" else ef
                entry = {"file": ef, "from": _shown(root, path), **_mode(ef_path)}
                try:
                    with open(ef_path) as fh:
                        for k, v in parse_env_file(fh.read()):
                            env[k] = (v, ef_path)
                except OSError as e:
                    entry["read_error"] = e.strerror or str(e)
                env_files.append(entry)
            elif key == "ExecStart":
                exec_start = value.strip()
    for k, (v, src) in env.items():
        if looks_secret(k, v):
            secrets.append({"name": k, "file": _shown(root, src), "length": len(v), **_mode(src)})
    watched = {k: env[k][0] for k in WATCHED if k in env}
    return {"files": [_shown(root, f) for f in files], "environment": watched, "secrets": secrets,
            "env_files": env_files, "exec_start": exec_start, "unreadable": unreadable}


# ---------------------------------------------------------------- server.json and the key

def cloud_switch_files(root: str = "/", home: str | None = None) -> list[dict]:
    """~/.ollama/server.json files with "disable_ollama_cloud"."""
    homes = [_p(root, h) for h in SERVICE_HOMES] + ([home] if home else [])
    out = []
    for h in homes:
        path = os.path.join(h, ".ollama", "server.json")
        shown = _shown(root, path)
        try:
            with open(path) as fh:
                data = json.load(fh)
            out.append({"file": shown, "disable_ollama_cloud": bool(data.get("disable_ollama_cloud"))})
        except FileNotFoundError:
            continue
        except PermissionError:
            out.append({"file": shown, "error": "permission denied"})
        except (OSError, ValueError) as e:
            out.append({"file": shown, "error": str(e)})
    return out


def key_files(root: str = "/", home: str | None = None) -> list[dict]:
    """Where an ollama.com device key sits. With it, anyone can act as the signed-in account
    from anywhere, so it should be readable by its owner only (0600). Never read, only stat."""
    homes = [_p(root, h) for h in SERVICE_HOMES] + ([home] if home else [])
    out = []
    for h in homes:
        path = os.path.join(h, ".ollama", "id_ed25519")
        shown = _shown(root, path)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        except PermissionError:
            out.append({"file": shown, "state": "can't check (permission denied)"})
            continue
        mode = stat.S_IMODE(st.st_mode)
        out.append({"file": shown, "state": "present", "mode": oct(mode),
                    "too_open": bool(mode & 0o077)})
    return out


def inspect_host(port: int, root: str = "/", home: str | None = None) -> dict:
    return {
        "listening": listening(port, root),
        "unit": unit_config(root, home),
        "cloud_switch": cloud_switch_files(root, home),
        "keys": key_files(root, home),
        "own_ips": sorted(local_ips(root)),
    }
