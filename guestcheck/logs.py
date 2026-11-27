"""Read Ollama's request log: who called what, from where.

Ollama's server logs one line per request through its web framework (gin):
  [GIN] 2026/11/27 - 11:24:26 | 200 |     459.706µs |       127.0.0.1 | GET      "/api/tags"
On Linux that lands in the journal:  journalctl -u ollama --no-pager --since "30 days ago"

The address column is gin's ClientIP(). Ollama 0.40.18 leaves gin's default of trusting every
proxy, so when a request carries X-Forwarded-For or X-Real-IP, the log shows the address the
caller wrote there. Treat the column as a claim, not proof: the report says so when non-local
callers appear. A proxy that overwrites those headers (see proxy/) makes the column reliable.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict

LINE = re.compile(r'\[GIN\]\s+(\d{4}/\d{2}/\d{2} - \d{2}:\d{2}:\d{2})\s*\|\s*(\d{3})\s*\|'
                  r'\s*[^|]*\|\s*([^|\s]*)\s*\|\s*([A-Z]+)\s+"([^"]*)"')
ANSI = re.compile(r"\x1b\[[0-9;]*m")

WRITE = re.compile(r"^/api/(pull|push|create|copy|delete|blobs/)")
ACCOUNT = re.compile(r"^/api/(me|signout|user/keys/|balance|usage|experimental/web_)")
INFER = re.compile(r"^/(api/(generate|chat|embed|embeddings)|v1/)")


def kind(method: str, path: str) -> str:
    p = path.split("?")[0]
    if WRITE.match(p) or (method == "DELETE" and p.startswith("/api/")):
        return "changes models"
    if ACCOUNT.match(p):
        return "account"
    if INFER.match(p):
        return "inference"
    return "read"


def _is_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_loopback


def parse(lines) -> list[dict]:
    out = []
    for raw in lines:
        m = LINE.search(ANSI.sub("", raw))
        if not m:
            continue
        when, status, ip, method, path = m.groups()
        out.append({"time": when.replace(" - ", " "), "status": int(status), "ip": ip or "?",
                    "method": method, "path": path, "kind": kind(method, path)})
    return out


def summarize(entries: list[dict]) -> dict:
    per_ip: dict = defaultdict(lambda: {"calls": 0, "kinds": Counter(), "first": "", "last": "",
                                        "writes": []})
    for e in entries:
        s = per_ip[e["ip"]]
        s["calls"] += 1
        s["kinds"][e["kind"]] += 1
        s["first"] = s["first"] or e["time"]
        s["last"] = e["time"]
        if e["kind"] in ("changes models", "account") and len(s["writes"]) < 20:
            s["writes"].append(f'{e["time"]} {e["status"]} {e["method"]} {e["path"]}')
    callers = []
    for ip, s in per_ip.items():
        local = _is_local(ip)
        flag = ""
        if not local and (s["kinds"]["changes models"] or s["kinds"]["account"]):
            flag = "changed models or touched the account from a non-local address"
        elif not local:
            flag = "non-local caller"
        callers.append({"ip": ip, "local": local, "calls": s["calls"], "kinds": dict(s["kinds"]),
                        "first": s["first"], "last": s["last"], "flag": flag,
                        "examples": s["writes"]})
    callers.sort(key=lambda c: (c["local"], not c["flag"].startswith("changed"), -c["calls"]))
    return {"requests": len(entries),
            "from": entries[0]["time"] if entries else "", "to": entries[-1]["time"] if entries else "",
            "callers": callers,
            "non_local": sum(1 for c in callers if not c["local"]),
            "caveat": "Addresses come from gin's ClientIP(); a caller can set them with "
                      "X-Forwarded-For or X-Real-IP unless a proxy overwrites those headers."}
