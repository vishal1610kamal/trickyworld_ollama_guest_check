# ollama-guest-check: has anyone else been using your Ollama server?

On 10 November 2026 Rapid7 read the model lists of 7,675 Ollama servers that answered from the internet
([Open by Default, Already Occupied](https://www.rapid7.com/blog/post/tr-self-hosted-ai-renting-compute-exposed-servers/),
18 November). **54.8% held something a stranger had left**: models pulled from raw IP addresses and free tunnels
(the pull calls the stranger back), "I was here" names, names carrying the server's own IP, and Base64 strings
that decode to `/etc/shadow` or `/proc/self/environ`. **79% listed at least one `:cloud` model**, which a
signed-in server runs on its owner's ollama.com account for anyone who asks.

Ollama's local API has no login. This tool reads what your server tells anyone who asks, looks for the marks
strangers leave, and checks the machine it runs on:

| Check | What it looks at |
|---|---|
| Visitors | Every model in `/api/tags`: registries other than Ollama's and Hugging Face's (raw IPs, tunnels, throwaway registries, out-of-band testing services), marker words, this server's own IP, encoded file paths (and what they were after), dates written into names, closed-model names such as `gpt-4o` and which model they are really a copy of (same digest), cloud models that route anywhere but ollama.com. |
| Exposure | Whether Ollama listens beyond localhost (`/proc/net/tcp`), `OLLAMA_HOST`, `OLLAMA_ORIGINS`, `OLLAMA_REMOTES` in the systemd unit and its drop-ins. |
| The account | Whether the server is signed in to ollama.com and what it gives away about the account (`POST /api/me`), whether cloud features are off (`/api/status`), and, with `--usage`, 30 days of cloud spend by model and the balance, read through the server itself. |
| Secrets | API keys and tokens in the unit file, its drop-ins and `EnvironmentFile`s (names only, never values), and who can read those files; where the ollama.com key (`id_ed25519`) is and whether others can read it. |
| Version | Known CVEs for the version it reports. |
| Logs | `logs`: who called which endpoint, from Ollama's own request log. |

Python 3.10 or newer, standard library only, read-only. Linux for the host checks; the server checks work
against any Ollama you can reach. This is the code behind the TrickyWorld article
[Is Your Ollama Server Serving Strangers?](https://www.trickyworld.in/artificial-intelligence-machine-learning/ai-agents/ollama-server-serving-strangers/).

**Run it only against servers you own.**

## Run it

```
git clone https://github.com/vishal1610kamal/trickyworld_ollama_guest_check
cd trickyworld_ollama_guest_check

python3 -m guestcheck                                   # this machine's Ollama (OLLAMA_HOST or 127.0.0.1:11434)
python3 -m guestcheck --url http://203.0.113.10:11434   # a server you own, from another machine
python3 -m guestcheck --ip 203.0.113.10                 # add the public IP if the server sits behind NAT
python3 -m guestcheck --usage                           # also: cloud spend by model and the balance
python3 -m guestcheck --json > check.json               # for scripts; exit code 0/1/2/3 below

python3 -m guestcheck --save-baseline models.json       # today's list...
python3 -m guestcheck --baseline models.json            # ...then, from cron, anything new since

journalctl -u ollama --no-pager --since "30 days ago" | python3 -m guestcheck logs -

python3 -m tests.demo                                   # what a visited server looks like (no Ollama needed)
```

Exit codes: `0` nothing found, `1` needs attention (exposed, signed in and reachable, outdated, secrets in the
service files, models to check, new models since the baseline), `2` strangers' models found, `3` no answer.

`POST /api/me` makes a signed-in server ask ollama.com which account it belongs to; skip it with `--no-account`.
The account email is masked unless you pass `--show-account`. `--root /mnt/image` runs the host checks against a
copy of a server's disk instead of `/`.

## What it looks like

`python3 -m tests.demo` runs the check against a stand-in server loaded with a model list modelled on
Rapid7's published sample (documentation IP addresses and a made-up tunnel name in place of real ones),
signed in to an account, listening on every interface (shortened here):

```
Server     Ollama 0.40.18; answers without a password (Ollama has no login of its own).
Listening  0.0.0.0:11434: reachable from other machines, not just this one
           OLLAMA_HOST=0.0.0.0:11434 (service configuration)
Cloud      on; signed in as a***@example.com, plan pro.
           Anyone who can reach this server can read the account's email, user name, first name,
           last name, plan and account ID (POST /api/me), run :cloud models and web searches on it,
           read its balance and usage, and sign it out.
Secret     OPENAI_API_KEY in /etc/systemd/system/ollama.service.d/override.conf (any local user can
           read it); value not shown
Models     28 listed: 10 left by strangers, 2 to check, 5 run on Ollama's cloud

STRANGER   pwn_ctl_203.0.113.10_ae52:latest  (2026-09-30)
           - marker word "pwn" in the name
           - carries this server's own IP address (203.0.113.10): someone's target list
STRANGER   quick-red-fox.trycloudflare.com/read/L2V0Yy9zaGFkb3c:latest  (2026-11-02)
           - pulled through a free tunnel or throwaway registry (trycloudflare.com)
           - hides a file path: /etc/shadow (credentials and keys)
CHECK      gpt-4o:latest  (2026-10-14)
           - named after a closed model that can't run locally, so it's a copy of another model
             (same digest as claude-3-opus:latest, tinyllama:latest, gpt-4o:latest-copy-test): did
             you make it?

Verdict    Strangers have used this server. Treat it as compromised, not misconfigured: see "If you
           find a stranger's model" in the README.
```

`CHECK` means "often a stranger's, but owners do it too". Ollama's own docs suggest
`ollama cp llama3.2 gpt-3.5-turbo` for tools that expect OpenAI's model names, so a `gpt-4o` copy may be yours.
A clean list doesn't prove a clean host: names can be deleted.

## What a signed-in server gives away

Ollama's [authentication page](https://docs.ollama.com/api/authentication.md) says the local API "does not
require authentication" and that, once you run `ollama signin`, cloud models also work "through the local API".
Ollama 0.40.18's source code (`server/routes.go`, `server/cloud_proxy.go`) shows what else the same port does
for any caller:

| Endpoint | What it does on a signed-in server | Blocked by `OLLAMA_NO_CLOUD=1`? |
|---|---|---|
| `/api/chat`, `/api/generate`, `/v1/...` with a `:cloud` model | Runs the model on ollama.com, paid from the account's credits | Yes |
| `POST /api/me` | Returns the account: ID, email, name, plan | **No** |
| `GET /api/balance`, `GET /api/usage` | The account's remaining credits and its usage by model (since 0.40.1) | Yes |
| `POST /api/experimental/web_search`, `web_fetch` | Web search and page fetches on the account | Yes |
| `POST /api/signout` | Unlinks the server from the account | **No** |
| `GET /api/status` | Whether cloud features are off, and why | (it reports it) |

The local server signs these requests with its own key, "regardless of caller credentials", as the code
comment puts it. Ollama's API docs describe `/api/balance` and `/api/usage` only as ollama.com endpoints that
need an API key, and don't mention `/api/me`, `/api/signout` or `/api/status` at all. A server that isn't signed
in answers `/api/me` with a sign-in link that contains its hostname.

So `OLLAMA_NO_CLOUD=1` (or `"disable_ollama_cloud": true` in `~/.ollama/server.json`) stops the spending but
not the account details: on a shared server, also run `ollama signout`, or never sign it in.

## If you find a stranger's model

Rapid7's advice is to treat the host as compromised, not misconfigured. In order:

1. **Keep the evidence** before you change anything: `python3 -m guestcheck --json > check.json`,
   `curl -s http://127.0.0.1:11434/api/tags > tags.json`, and the journal:
   `journalctl -u ollama --no-pager > ollama-journal.txt`.
2. **Cut access**: close the port in the firewall (and on the cloud provider's firewall), stop any tunnel, or
   stop the service: `sudo systemctl stop ollama`.
3. **Unlink the account**: run `ollama signout` on the server, then remove the server's key on ollama.com's
   Keys page (`https://ollama.com/settings/keys`). Look at the usage page for spend you don't recognise.
4. **Rotate every secret the server could read**: its unit files and `EnvironmentFile`s, `.env` files, cloud
   keys, SSH keys. Rapid7 saw encoded paths aimed at all of these, and at Ollama's own private key.
5. **Rebuild rather than clean**: a fresh system, the latest Ollama, models pulled again from the official
   registry. Look for persistence too: `/etc/ld.so.preload` and service files you didn't write.
6. **Bring it back locked down** (below), with a baseline saved and the check in cron.

## Lock it down

- **Keep Ollama on localhost.** It binds `127.0.0.1:11434` unless `OLLAMA_HOST` says otherwise: remove
  `OLLAMA_HOST=0.0.0.0...` from `systemctl edit ollama.service`, then `sudo systemctl daemon-reload && sudo
  systemctl restart ollama`.
- **Docker publishes to every interface, past ufw.** Ollama's docs use `-p 11434:11434`; Docker's docs warn
  that published ports skip ufw's rules. Use `-p 127.0.0.1:11434:11434`.
- **Reach it over SSH or a private network** instead of opening it:
  `ssh -N -L 11434:127.0.0.1:11434 you@server`, then use `http://127.0.0.1:11434` on your laptop.
- **If it must be reachable, put a login in front.** [proxy/apache-ollama.conf](proxy/apache-ollama.conf)
  (tested) and [proxy/nginx-ollama.conf](proxy/nginx-ollama.conf) (not run here: no nginx on the test machine)
  add basic auth over HTTPS, refuse the model-management and account endpoints for everyone, keep Ollama's
  local-only Host check happy, and overwrite `X-Forwarded-For` so Ollama's log shows real addresses.
- **Tunnels:** Ollama's FAQ shows ngrok and Cloudflare Tunnel commands with no login. Cloudflare says of a Quick
  Tunnel: "Anyone with the URL can access your local service". Its `--allowed-mail` option adds an email PIN but
  doesn't work for non-interactive clients; ngrok's `basic-auth` traffic-policy action adds a password.
- **Turn cloud off unless you use it**, and don't sign a shared server into your account.
- **Watch it**: `--baseline` in cron, and the `logs` command over the journal.

## Ollama's request log, and why its addresses can lie

Ollama logs every request (`[GIN] 2026/11/27 - 11:24:26 | 200 | 459.706µs | 127.0.0.1 | GET "/api/tags"`). The
address is gin's `ClientIP()`. Gin 1.12.0 trusts every proxy by default and takes the left-most
`X-Forwarded-For` (or `X-Real-IP`) address; Ollama 0.40.18 doesn't change that. So a caller can put any address
in your log, and a proxy that only appends (Apache's default) keeps the forged one first. The `logs` command
says so whenever non-local callers appear, and the configs in `proxy/` overwrite both headers. The live test
checks that: without the two `RequestHeader unset` lines, the backend receives `203.0.113.99, 127.0.0.1`.

## Versions

| CVE | Affected | Fixed in | What |
|---|---|---|---|
| CVE-2024-28224 | before 0.1.29 | 0.1.29 | DNS rebinding reaches the API |
| CVE-2024-37032 (Probllama) | before 0.1.34 | 0.1.34 | path traversal through `/api/pull` and `/api/push` |
| CVE-2026-7482 | before 0.17.1 | 0.17.1 | heap over-read through `/api/create`, sent out with `/api/push` |
| CVE-2026-103663 | 0.14.3 to before 0.35.0 | 0.35.0 | path traversal in `/api/pull` layer digests; root code execution in many Docker images |
| CVE-2026-85180 | 0.30.0 through 0.33.2 | later | pulls follow redirects to internal hosts (SSRF) |
| CVE-2026-108836 | up to 0.34.1 | 0.34.2 | SSRF through crafted model names |

None is in CISA's Known Exploited Vulnerabilities catalog (2026.11.25). CVE-2025-63389 describes the missing
authentication itself and lists versions up to 0.12.3; no later release added authentication (0.40.18 of
24 November and 0.40.19-rc0 of 26 November have the same routes and middleware), so the tool doesn't treat
newer versions as fixed for it.

## Tests

```
python3 -m unittest discover -s tests -t .                       # 56 offline tests
GUESTCHECK_LIVE=1 python3 -m unittest discover -s tests -t .     # + the proxy configs, run for real
```

Results on 27 November 2026: **56 offline tests pass on Python 3.10.12, 3.11.14, 3.12.12 and 3.13.11**; with
`GUESTCHECK_LIVE=1`, **6 live tests pass against Apache 2.4.52** (password required, management and account
paths refused without reaching Ollama, look-alike paths still served, a local Host header, the forged
`X-Forwarded-For` gone, tokens streamed as they come, plain HTTP redirected). The nginx test (`nginx -t` only)
was skipped: nginx isn't installed on the test machine. `pyflakes` is clean.

A real run against an older Ollama install (0.5.7, bound to localhost) found no strangers and flagged its two
known CVEs; the `logs` command parsed its journal (78 requests, all local).

What was **not** tested: Ollama 0.40.18 itself was not run. The account, cloud-switch, balance and usage
behaviour comes from its source code and documentation, and the tests use a stand-in built from them
(`tests/helpers.py`), so a mistake shared by those sources would pass here too. Host checks for macOS and
Windows aren't implemented.

## Sources

- Rapid7, [Open by Default, Already Occupied: Threat Actors are Renting your Compute](https://www.rapid7.com/blog/post/tr-self-hosted-ai-renting-compute-exposed-servers/) (18 Nov 2026)
- Ollama docs: [Authentication](https://docs.ollama.com/api/authentication.md), [FAQ](https://docs.ollama.com/faq.md), [Cloud usage](https://docs.ollama.com/api/cloud-usage.md), [Balance](https://docs.ollama.com/api/balance.md), [Pricing](https://ollama.com/pricing)
- Ollama source, [v0.40.18](https://github.com/ollama/ollama/tree/v0.40.18): `server/routes.go`, `server/cloud_proxy.go`, `internal/cloud/policy.go`, `envconfig/config.go`
- [CVE-2026-103663](https://cert.pl/en/posts/2026/10/CVE-2026-103663/) (CERT Polska), the NVD records above, [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Docker, [Packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/); Cloudflare, [Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/); ngrok, [Basic Auth action](https://ngrok.com/docs/gateway/traffic-policy/actions/basic-auth/)
- gin [v1.12.0](https://github.com/gin-gonic/gin/tree/v1.12.0): `gin.go` (default trusted proxies), `context.go` (`ClientIP`)

## License

MIT
