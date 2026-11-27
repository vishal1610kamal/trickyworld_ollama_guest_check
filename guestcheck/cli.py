"""Command line: python3 -m guestcheck [check] [options] | python3 -m guestcheck logs FILE|-"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import urllib.parse
from datetime import datetime, timezone

from . import __version__, host as hostmod, logs as logsmod, names, report, server

DEFAULT_PORT = 11434


def default_url(env: str | None = None) -> str:
    """Where to look by default: OLLAMA_HOST if set (a bind-all address means this machine)."""
    raw = (env if env is not None else os.environ.get("OLLAMA_HOST", "")).strip()
    if not raw:
        return f"http://127.0.0.1:{DEFAULT_PORT}"
    return normalize_url(raw)


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    u = urllib.parse.urlparse(raw)
    host = u.hostname or "127.0.0.1"
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else DEFAULT_PORT)
    if ":" in host:
        host = f"[{host}]"
    return f"{u.scheme}://{host}:{port}"


def _host_is_this_machine(url: str, own: set[str]) -> bool:
    if report.url_is_local(url):
        return True
    h = urllib.parse.urlparse(url).hostname or ""
    return h in own


def _url_ip(url: str) -> str:
    h = urllib.parse.urlparse(url).hostname or ""
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        return ""


def baseline_snapshot(url: str, models: list[dict]) -> dict:
    return {"tool": f"ollama-guest-check {__version__}", "url": url,
            "saved": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "models": {str(m.get("name")): {"digest": m.get("digest", ""),
                                            "modified_at": m.get("modified_at", "")} for m in models}}


def compare_baseline(old: dict, models: list[dict]) -> dict:
    before = old.get("models", {})
    now = {str(m.get("name")): m for m in models}
    new = sorted(n for n in now if n not in before)
    changed = sorted(n for n in now if n in before and before[n].get("digest")
                     and now[n].get("digest") != before[n].get("digest"))
    gone = sorted(n for n in before if n not in now)
    return {"saved": old.get("saved", "?"), "new": new, "changed": changed, "removed": gone}


def run_check(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m guestcheck",
                                 description="Has anyone else been using your Ollama server?")
    ap.add_argument("--url", help="server to check (default: OLLAMA_HOST or http://127.0.0.1:11434)")
    ap.add_argument("--ip", action="append", default=[],
                    help="this server's public IP, to spot names that carry it (repeatable)")
    ap.add_argument("--no-account", action="store_true",
                    help="skip POST /api/me (it makes the server ask ollama.com who it is signed in as)")
    ap.add_argument("--usage", action="store_true",
                    help="also read 30 days of cloud spend and the balance through the server")
    ap.add_argument("--show-account", action="store_true", help="print the account email unmasked")
    ap.add_argument("--no-host", action="store_true", help="skip the checks of this machine")
    ap.add_argument("--listen-port", type=int,
                    help="port Ollama itself listens on, for the host checks (default: the URL's "
                         "port if the URL is this machine, else 11434; useful behind a proxy)")
    ap.add_argument("--root", default="/", help="read host files under this directory (a disk image)")
    ap.add_argument("--save-baseline", metavar="FILE", help="save today's model list to compare later")
    ap.add_argument("--baseline", metavar="FILE", help="compare with a saved model list")
    ap.add_argument("--all", action="store_true", help="also list models with nothing to report")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--version", action="version", version=f"ollama-guest-check {__version__}")
    a = ap.parse_args(argv)

    url = normalize_url(a.url) if a.url else default_url()
    srv = server.inspect(url, account=not a.no_account, usage=a.usage,
                         show_account=a.show_account, timeout=a.timeout)

    own = set(a.ip)
    ip = _url_ip(url)
    if ip and not ipaddress.ip_address(ip).is_loopback:
        own.add(ip)
    hst = None
    local_ips = hostmod.local_ips(a.root) if sys.platform.startswith("linux") or a.root != "/" else set()
    if not a.no_host and (a.root != "/" or (sys.platform.startswith("linux")
                                            and _host_is_this_machine(url, local_ips))):
        home = os.path.expanduser("~") if a.root == "/" else None
        if a.listen_port:
            port = a.listen_port
        elif _host_is_this_machine(url, local_ips):
            port = urllib.parse.urlparse(url).port or DEFAULT_PORT
        else:
            port = DEFAULT_PORT
        hst = hostmod.inspect_host(port, a.root, home)
        own |= set(hst["own_ips"])

    findings = names.classify_all(srv.get("models", []), own) if srv.get("reachable") else []
    assessment = report.assess(srv, hst, findings)

    base = None
    if srv.get("reachable") and a.baseline:
        with open(a.baseline) as fh:
            base = compare_baseline(json.load(fh), srv.get("models", []))
        if (base["new"] or base["changed"]) and assessment["exit"] == report.EXIT_CLEAN:
            assessment.update(verdict="attention", exit=report.EXIT_ATTENTION)
    if srv.get("reachable") and a.save_baseline:
        with open(a.save_baseline, "w") as fh:
            json.dump(baseline_snapshot(url, srv.get("models", [])), fh, indent=1)

    if a.json:
        srv_out = {k: v for k, v in srv.items() if k != "models"}
        print(json.dumps({"tool": f"ollama-guest-check {__version__}", "server": srv_out, "host": hst,
                          "assessment": assessment, "models": [f.as_dict() for f in findings],
                          "baseline": base}, indent=1))
    else:
        print(report.render(srv, hst, findings, assessment, show_ok=a.all))
        if base:
            print()
            print(f"Since the baseline of {base['saved']}: {len(base['new'])} new, "
                  f"{len(base['changed'])} changed, {len(base['removed'])} removed")
            for n in base["new"]:
                print(f"  NEW      {n}")
            for n in base["changed"]:
                print(f"  CHANGED  {n}")
            for n in base["removed"]:
                print(f"  REMOVED  {n}")
    return assessment["exit"]


def run_logs(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m guestcheck logs",
                                 description="Who called your Ollama server, from Ollama's request log.")
    ap.add_argument("file", help='a log file, or "-" for stdin (journalctl -u ollama --no-pager | ...)')
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.file == "-":
        entries = logsmod.parse(sys.stdin)
    else:
        with open(a.file, errors="replace") as fh:
            entries = logsmod.parse(fh)
    s = logsmod.summarize(entries)
    if a.json:
        print(json.dumps(s, indent=1))
    else:
        print(f"Ollama request log: {s['requests']} requests"
              + (f", {s['from']} to {s['to']}" if s["requests"] else ""))
        if s["requests"]:
            print(f"{'CALLER':<40} {'CALLS':>6} {'MODELS':>7} {'ACCOUNT':>8} {'INFER':>6}  LAST")
        for c in s["callers"]:
            k = c["kinds"]
            print(f"{c['ip']:<40} {c['calls']:>6} {k.get('changes models', 0):>7} "
                  f"{k.get('account', 0):>8} {k.get('inference', 0):>6}  {c['last']}"
                  + (f"  <- {c['flag']}" if c["flag"] else ""))
            if not c["local"]:
                for line in c["examples"][:8]:
                    print(f"{'':<5}{line}")
        if s["non_local"]:
            print("\nNote: " + s["caveat"])
    worst = [c for c in s["callers"] if c["flag"].startswith("changed")]
    if worst:
        return report.EXIT_STRANGERS
    return report.EXIT_ATTENTION if s["non_local"] else report.EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "logs":
        return run_logs(argv[1:])
    if argv and argv[0] == "check":
        argv = argv[1:]
    return run_check(argv)
