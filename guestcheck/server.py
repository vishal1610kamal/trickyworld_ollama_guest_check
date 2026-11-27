"""Ask an Ollama server what it tells anyone who asks.

Read-only: GET /api/version, /api/tags, /api/status, /api/ps and, unless told not to, POST /api/me.
On a signed-in server /api/me makes the server ask ollama.com who it is signed in as and hands the
answer back to the caller, with no password. With usage=True it also reads GET /api/usage and
/api/balance, which a signed-in server (0.40.1 and later) passes through to ollama.com the same way.
Run it only against servers you own.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

# Ignore http_proxy and friends: a proxy in the way would hide what the server itself says.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
UA = "ollama-guest-check/1.0 (+https://github.com/vishal1610kamal/trickyworld_ollama_guest_check)"


@dataclass
class Reply:
    status: int = 0
    data: object = None
    text: str = ""
    error: str = ""


def call(base: str, path: str, method: str = "GET", timeout: float = 10.0) -> Reply:
    url = base.rstrip("/") + path
    body = b"" if method in ("POST", "DELETE") else None
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            raw = r.read(4_000_000)
            status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read(200_000) if e.fp else b""
        status = e.code
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
        reason = getattr(e, "reason", e)
        return Reply(error=str(reason) or e.__class__.__name__)
    text = raw.decode("utf-8", "replace")
    try:
        data = json.loads(text) if text.strip() else None
    except ValueError:
        data = None
    return Reply(status=status, data=data, text=text[:500])


def mask_email(email: str) -> str:
    if "@" not in email:
        return email[:1] + "***" if email else ""
    user, domain = email.split("@", 1)
    return f"{user[:1]}***@{domain}"


def _account(r: Reply, show: bool) -> dict:
    """What POST /api/me said about the account this server is signed in to."""
    a: dict = {"http_status": r.status}
    d = r.data if isinstance(r.data, dict) else {}
    if r.error:
        a.update(state="error", detail=r.error)
    elif r.status == 200 and (d.get("name") or d.get("email")):
        email = str(d.get("email") or "")
        a.update(state="signed-in", plan=str(d.get("plan") or ""),
                 email=email if show else mask_email(email),
                 name=str(d.get("name") or "") if show else mask_email(str(d.get("name") or "")),
                 exposed_fields=sorted(k for k, v in d.items() if v))
    elif r.status == 401:
        a["state"] = "signed-out"
        link = str(d.get("signin_url") or "")
        if link:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
            a["hostname_in_signin_url"] = (q.get("name") or [""])[0]
            a["signin_url_has_key"] = bool(q.get("key"))
    elif r.status == 404:
        a["state"] = "no-endpoint"          # older Ollama, before sign-in existed
    elif r.status == 403:
        a["state"] = "blocked"               # e.g. a proxy in front refuses /api/me
    elif r.status == 503:
        a["state"] = "unavailable"           # the server couldn't reach ollama.com
    else:
        a.update(state="unknown", detail=r.text[:200])
    return a


def inspect(base: str, account: bool = True, usage: bool = False, show_account: bool = False,
            timeout: float = 10.0) -> dict:
    out: dict = {"url": base.rstrip("/")}
    v = call(base, "/api/version", timeout=timeout)
    if v.error or v.status != 200 or not isinstance(v.data, dict):
        out.update(reachable=False, error=v.error or f"HTTP {v.status}: {v.text[:120]}")
        return out
    out.update(reachable=True, version=str(v.data.get("version", "")))

    t = call(base, "/api/tags", timeout=timeout)
    if t.status == 200 and isinstance(t.data, dict):
        out["models"] = [m for m in (t.data.get("models") or []) if isinstance(m, dict)]
    else:
        out["models"] = []
        out["tags_error"] = t.error or f"HTTP {t.status}"

    s = call(base, "/api/status", timeout=timeout)
    if s.status == 200 and isinstance(s.data, dict) and isinstance(s.data.get("cloud"), dict):
        out["cloud"] = {"disabled": bool(s.data["cloud"].get("disabled")),
                        "source": str(s.data["cloud"].get("source", ""))}
    else:
        out["cloud"] = {"disabled": None, "source": "unknown (no /api/status)"}

    p = call(base, "/api/ps", timeout=timeout)
    if p.status == 200 and isinstance(p.data, dict):
        out["running"] = [str(m.get("name") or m.get("model")) for m in (p.data.get("models") or [])
                          if isinstance(m, dict)]

    if account:
        out["account"] = _account(call(base, "/api/me", method="POST", timeout=timeout), show_account)
    if usage:
        out["usage"] = _usage(base, timeout)
    return out


def _usage(base: str, timeout: float) -> dict:
    """Cloud spend over 30 days by model, and the remaining balance, as the server's account sees it."""
    res: dict = {}
    u = call(base, "/api/usage?range=30d&group_by=model", timeout=timeout)
    res["usage_status"] = u.status or u.error
    if u.status == 200 and isinstance(u.data, dict):
        totals = u.data.get("totals") or {}
        res["range"] = u.data.get("range", "30d")
        res["request_count"] = totals.get("request_count")
        res["usage_usd"] = totals.get("usage_usd")
        res["by_model"] = [{"model": g.get("model"), "requests": g.get("request_count"),
                            "usd": g.get("usage_usd")} for g in (totals.get("groups") or [])]
    elif isinstance(u.data, dict) and u.data.get("error"):
        res["usage_error"] = str(u.data["error"])
    b = call(base, "/api/balance", timeout=timeout)
    res["balance_status"] = b.status or b.error
    if b.status == 200 and isinstance(b.data, dict):
        inc = b.data.get("included") or {}
        pur = b.data.get("purchased") or {}
        res["included_usd"] = inc.get("balance_usd")
        res["allowance_usd"] = inc.get("allowance_usd")
        res["purchased_usd"] = pur.get("balance_usd")
    elif isinstance(b.data, dict) and b.data.get("error"):
        res["balance_error"] = str(b.data["error"])
    return res
