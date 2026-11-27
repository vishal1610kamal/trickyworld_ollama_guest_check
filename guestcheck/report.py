"""Turn the raw checks into a verdict, an exit code and a readable report."""
from __future__ import annotations

import ipaddress
import textwrap
import urllib.parse
from datetime import datetime, timezone

from . import __version__, names, versions

EXIT_CLEAN, EXIT_ATTENTION, EXIT_STRANGERS, EXIT_UNREACHABLE = 0, 1, 2, 3
TRUE = {"1", "true", "yes", "on"}
FIELD_WORDS = {"email": "email", "name": "user name", "firstname": "first name",
               "lastname": "last name", "plan": "plan", "id": "account ID", "bio": "bio",
               "avatarurl": "avatar"}


def _and(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def url_is_local(url: str) -> bool:
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assess(server: dict, host: dict | None, findings: list) -> dict:
    """Facts plus a verdict. `findings` is names.classify_all(...) output."""
    a: dict = {"notes": [], "problems": []}
    if not server.get("reachable"):
        a.update(verdict="unreachable", exit=EXIT_UNREACHABLE)
        return a

    strangers = [f for f in findings if f.level == names.STRANGER]
    checks = [f for f in findings if f.level == names.CHECK]
    cloud_models = [f for f in findings if f.cloud]
    a["counts"] = {"models": len(findings), "strangers": len(strangers), "check": len(checks),
                   "cloud": len(cloud_models)}

    exposed = False
    if not url_is_local(server["url"]):
        exposed = True
        a["problems"].append(f"answers at {server['url']} with no password")
    if host and host["listening"]["beyond_localhost"]:
        exposed = True
        a["problems"].append("listens on " + ", ".join(host["listening"]["beyond_localhost"])
                             + f":{host['listening']['port']}, not only on localhost")
    a["exposed"] = exposed

    acct = server.get("account") or {}
    env = (host or {}).get("unit", {}).get("environment", {})
    switch_files = (host or {}).get("cloud_switch", [])
    cloud = server.get("cloud") or {}
    disabled = cloud.get("disabled")
    a["cloud_reported"] = disabled is not None
    if disabled is None:
        disabled = (env.get("OLLAMA_NO_CLOUD", "").lower() in TRUE
                    or any(s.get("disable_ollama_cloud") for s in switch_files))
    a["cloud_disabled"] = bool(disabled)
    a["cloud_source"] = cloud.get("source", "")
    a["signed_in"] = acct.get("state") == "signed-in"
    if a["signed_in"]:
        a["problems"].append("signed in to an ollama.com account"
                             + (" and reachable by others" if exposed else ""))
        if a["cloud_disabled"]:
            a["notes"].append("cloud is off, but /api/me still answers with the account's details: "
                              "run `ollama signout` on a shared server")
    if acct.get("hostname_in_signin_url"):
        a["notes"].append(f"its sign-in link gives away the machine name "
                          f"\"{acct['hostname_in_signin_url']}\"")

    vulns = versions.affected(server.get("version", ""))
    a["vulnerabilities"] = [{"cve": c, "fixed_in": fx, "summary": s} for c, fx, s in vulns]
    if vulns:
        a["problems"].append(f"Ollama {server.get('version')} has {len(vulns)} known "
                             f"vulnerabilit{'y' if len(vulns) == 1 else 'ies'}")

    if host:
        if host["unit"]["secrets"]:
            a["problems"].append("secrets in the service configuration")
        origins = env.get("OLLAMA_ORIGINS", "")
        if "*" in origins.split(",") or origins.strip() == "*":
            a["problems"].append("OLLAMA_ORIGINS=* lets any web page call the API from a browser")
        if any(k.get("too_open") for k in host["keys"]):
            a["problems"].append("the ollama.com key file is readable by other users")

    if strangers:
        a.update(verdict="strangers", exit=EXIT_STRANGERS)
    elif a["problems"] or checks:
        a.update(verdict="attention", exit=EXIT_ATTENTION)
    else:
        a.update(verdict="clean", exit=EXIT_CLEAN)
    return a


def _wrap(label: str, text: str, width: int = 100) -> str:
    pad = " " * 11
    return textwrap.fill(text, width=width, initial_indent=f"{label:<11}", subsequent_indent=pad)


def render(server: dict, host: dict | None, findings: list, a: dict, show_ok: bool = False) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"ollama-guest-check {__version__} · {server['url']} · {now}", ""]
    if not server.get("reachable"):
        out.append(_wrap("Server", f"no answer: {server.get('error')}"))
        return "\n".join(out)

    out.append(_wrap("Server", f"Ollama {server.get('version') or '?'}; answers without a password "
                               "(Ollama has no login of its own)."))
    if host:
        ls = host["listening"]
        if not ls["checked"]:
            out.append(_wrap("Listening", "couldn't read /proc/net/tcp"))
        elif ls["beyond_localhost"]:
            out.append(_wrap("Listening", ", ".join(f"{x}:{ls['port']}" for x in ls["addresses"])
                             + ": reachable from other machines, not just this one"))
        elif ls["addresses"]:
            out.append(_wrap("Listening", ", ".join(f"{x}:{ls['port']}" for x in ls["addresses"])
                             + ": this machine only"))
        else:
            out.append(_wrap("Listening", f"nothing on port {ls['port']} (use --listen-port if Ollama "
                                          "uses another port)"))
        env = host["unit"]["environment"]
        for k in ("OLLAMA_HOST", "OLLAMA_ORIGINS", "OLLAMA_NO_CLOUD", "OLLAMA_REMOTES"):
            if k in env:
                out.append(_wrap("", f"{k}={env[k]} (service configuration)"))
    elif a.get("exposed"):
        out.append(_wrap("Reachable", f"yes, at {server['url']}, from where this check ran"))

    acct = server.get("account") or {}
    state = acct.get("state")
    if a.get("cloud_reported"):
        cloud_word = (f"off ({a['cloud_source']})" if a.get("cloud_disabled") and a.get("cloud_source")
                      else "off" if a.get("cloud_disabled") else "on")
    elif a.get("cloud_disabled"):
        cloud_word = "off in its settings (this version can't confirm it: no /api/status)"
    else:
        cloud_word = "not reported by this version (no /api/status)"
    if state == "signed-in":
        who = acct.get("email") or acct.get("name") or "an account"
        plan = f", plan {acct['plan']}" if acct.get("plan") else ""
        out.append(_wrap("Cloud", f"{cloud_word}; signed in as {who}{plan}."))
        have = set(acct.get("exposed_fields") or [])
        fields = _and([word for key, word in FIELD_WORDS.items() if key in have] or ["details"])
        if a.get("cloud_disabled"):
            msg = (f"Cloud models are off, but anyone who can reach this server can still read the "
                   f"account's {fields} (POST /api/me) and sign it out.")
        else:
            msg = (f"Anyone who can reach this server can read the account's {fields} "
                   "(POST /api/me), run :cloud models and web searches on it, read its balance "
                   "and usage, and sign it out.")
        out.append(_wrap("", msg))
    elif state == "signed-out":
        out.append(_wrap("Cloud", f"{cloud_word}; not signed in to ollama.com."))
    elif state == "no-endpoint":
        out.append(_wrap("Cloud", f"{cloud_word}; this version has no sign-in (no /api/me)."))
    elif state:
        out.append(_wrap("Cloud", f"{cloud_word}; account check: {state}"))
    else:
        out.append(_wrap("Cloud", f"{cloud_word}; account not checked"))

    usage = server.get("usage")
    if usage:
        if usage.get("usage_usd") is not None:
            top = ", ".join(f"{g['model']} ${g['usd']}" for g in usage.get("by_model", [])[:5])
            out.append(_wrap("Spend", f"${usage['usage_usd']} over {usage.get('range', '30d')} "
                                      f"({usage.get('request_count')} requests){': ' + top if top else ''}"))
        else:
            out.append(_wrap("Spend", f"not available ({usage.get('usage_error') or usage.get('usage_status')})"))
        if usage.get("included_usd") is not None or usage.get("purchased_usd") is not None:
            out.append(_wrap("Balance", f"included ${usage.get('included_usd')} of "
                                        f"${usage.get('allowance_usd')}, purchased ${usage.get('purchased_usd')}"))

    if host:
        for s in host["unit"]["secrets"]:
            how = ("any local user can read it" if s.get("world_readable")
                   else f"mode {s.get('mode', '?')}")
            out.append(_wrap("Secret", f"{s['name']} in {s['file']} ({how}); value not shown"))
        for k in host["keys"]:
            if k.get("state") == "present":
                out.append(_wrap("Key", f"{k['file']} ({k['mode']}"
                                        + (", readable by others)" if k.get("too_open") else ")")))
            else:
                out.append(_wrap("Key", f"{k['file']}: {k['state']}"))
    for v in a.get("vulnerabilities", []):
        out.append(_wrap("CVE", f"{v['cve']}: {v['summary']} (fixed in {v['fixed_in']})"))

    c = a.get("counts", {})
    out.append(_wrap("Models", f"{c.get('models', 0)} listed: {c.get('strangers', 0)} left by strangers, "
                               f"{c.get('check', 0)} to check, {c.get('cloud', 0)} run on Ollama's cloud"))
    for note in a.get("notes", []):
        out.append(_wrap("Note", note))
    out.append("")

    listed = 0
    for f in findings:
        if f.level == names.OK or (f.level == names.INFO and not show_ok):
            continue
        listed += 1
        when = f"  ({f.modified_at[:10]})" if f.modified_at else ""
        out.append(f"{f.level.upper():<11}{f.name}{when}")
        for r in f.reasons:
            out.append(textwrap.fill(r, width=100, initial_indent=" " * 11 + "- ",
                                     subsequent_indent=" " * 13))
    if show_ok:
        for f in findings:
            if f.level == names.OK:
                listed += 1
                out.append(f"{'OK':<11}{f.name}")
    if listed:
        out.append("")

    verdicts = {
        "strangers": "Strangers have used this server. Treat it as compromised, not misconfigured: "
                     "see \"If you find a stranger's model\" in the README.",
        "attention": "No stranger's model found, but this server needs work: "
                     + "; ".join(a["problems"] or ["see the models marked CHECK"]) + ".",
        "clean": "Nothing found. A clean list doesn't prove a clean host: names can be deleted.",
    }
    out.append(_wrap("Verdict", verdicts[a["verdict"]]))
    return "\n".join(out)
