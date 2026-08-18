# RailGate

A personal VPN/proxy gateway built **specifically for Railway**.

Deploy this repository to Railway, open the admin dashboard, create an account,
scan a QR code, and your Android phone routes its traffic through your own
Railway container.

```
Android phone
    |  v2rayNG / Hiddify / NekoBox
    v
Encrypted VLESS connection
    |
    v
Railway TCP Proxy   (something.proxy.rlwy.net:<random port>)
    |
    v
Xray-core  (VLESS + XTLS Vision + REALITY, internal port 2443)
    |
    v
Internet
```

Everything runs in **one container**: Xray-core, a FastAPI admin backend, a web
dashboard, a `vpnctl` CLI and a small purpose-built process supervisor.

| | |
|---|---|
| **Xray-core** | v26.3.27 (pinned, checksum-verified at build time) |
| **Primary transport** | VLESS + REALITY + XTLS Vision over raw TCP |
| **Fallback transport** | VLESS over WebSocket on Railway's HTTPS domain |
| **Storage** | SQLite + REALITY keys on a Railway Volume at `/data` |
| **Admin** | Web dashboard, JSON API and `vpnctl` over `railway ssh` |

---

## Table of contents

1. [What you get](#what-you-get)
2. [Section 1 — Create a GitHub repository](#section-1--create-a-github-repository)
3. [Section 2 — Push this project](#section-2--push-this-project)
4. [Section 3 — Deploy on Railway](#section-3--deploy-on-railway)
5. [Section 4 — Environment variables](#section-4--environment-variables)
6. [Section 5 — Create the volume (/data)](#section-5--create-the-volume-data)
7. [Section 6 — Enable public networking (dashboard)](#section-6--enable-public-networking-dashboard)
8. [Section 7 — Enable the TCP Proxy (the VPN port)](#section-7--enable-the-tcp-proxy-the-vpn-port)
9. [Section 8 — Redeploy](#section-8--redeploy)
10. [Section 9 — Log in to the dashboard](#section-9--log-in-to-the-dashboard)
11. [Section 10 — Create your first VPN user](#section-10--create-your-first-vpn-user)
12. [Section 11 — Open the credential page](#section-11--open-the-credential-page)
13. [Section 12 — Connect Android](#section-12--connect-android)
14. [Terminal access and vpnctl](#terminal-access-and-vpnctl)
15. [The WebSocket fallback](#the-websocket-fallback)
16. [Choosing a REALITY destination](#choosing-a-reality-destination)
17. [Backup and restore](#backup-and-restore)
18. [Troubleshooting](#troubleshooting)
19. [Updating Xray-core](#updating-xray-core)
20. [Local development](#local-development)
21. [Security notes](#security-notes)
22. [Known limitations](#known-limitations)

---

## What you get

* **Multi-user accounts** with optional expiry dates, enable/disable, renew,
  credential regeneration and notes.
* **A real admin panel** — dashboard, users, server info, tools, settings, logs.
  Dark/light, mobile friendly.
* **Automatic credential generation.** You never hand-assemble a `vless://` URI.
  The server knows the UUID and REALITY public material, Railway supplies the
  host and port, and the link plus QR code are produced for you.
* **`vpnctl`**, a menu-driven CLI in the style of the classic SSH/VPN scripts,
  but correct for Railway.
* **Safe configuration handling.** Every config is validated by the actual Xray
  binary before it is activated, and rolled back automatically if Xray fails to
  start. Adding or removing an account uses Xray's runtime API, so existing
  tunnels are not interrupted.
* **Persistence.** Redeploying does not change UUIDs, regenerate REALITY keys or
  reset the database, as long as the `/data` volume survives.

---

## Section 1 — Create a GitHub repository

1. Go to <https://github.com/new>.
2. Give it a name, e.g. `RailGate`.
3. Choose **Private** (recommended — it is your gateway).
4. Do **not** add a README, `.gitignore` or licence; this project already has them.
5. Click **Create repository**.

---

## Section 2 — Push this project

From the project folder on your machine:

```bash
git init
git add .
git commit -m "RailGate: personal VPN gateway for Railway"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

Before pushing, confirm nothing secret is included:

```bash
git status --porcelain          # must not list .env, *.db or any key file
```

The `.gitignore` already blocks `data/`, `*.db`, `.env`, `backups/`, generated
Xray configs and REALITY key files.

---

## Section 3 — Deploy on Railway

1. Go to <https://railway.com> and sign in.
2. **New Project** -> **Deploy from GitHub repo**.
3. Authorise Railway for your account if prompted, then pick your repository.
4. Railway detects `railway.json` and builds with the `Dockerfile`. The first
   build takes a few minutes (it downloads and verifies Xray-core).

**The first deploy will not be fully healthy yet** — that is expected. You still
need to add variables and a volume. Continue with Section 4.

---

## Section 4 — Environment variables

Railway -> your service -> **Variables** -> **New Variable**.

### You MUST create these

| Variable | Value | Why |
|---|---|---|
| `ADMIN_PASSWORD` | a long random string | **Required.** Without it the container refuses to start. |
| `ADMIN_SESSION_SECRET` | a long random hex string | Keeps you logged in across redeploys. |
| `REALITY_SERVER_NAME` | e.g. `www.microsoft.com` | The site your traffic is disguised as. |
| `REALITY_DESTINATION` | e.g. `www.microsoft.com:443` | Where Xray forwards non-VPN probes. Must match the name above. |

`ADMIN_USERNAME` defaults to `admin`; set it if you want something else.

### Generating secure values

```bash
# ADMIN_PASSWORD
openssl rand -base64 24

# ADMIN_SESSION_SECRET
openssl rand -hex 32
```

Or without OpenSSL:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Paste the output into Railway. Never commit these to Git.

### You do NOT need to set these

`PORT`, `RAILWAY_PUBLIC_DOMAIN`, `RAILWAY_TCP_PROXY_DOMAIN`,
`RAILWAY_TCP_PROXY_PORT` and friends are injected by Railway and detected
automatically.

`XRAY_PORT` defaults to `2443` and only needs changing if you want a different
internal port (then point the TCP Proxy at that port instead).

See [.env.example](.env.example) for every supported variable with comments.

---

## Section 5 — Create the volume (/data)

Railway -> your service -> **Settings** -> **Volumes** -> **Add Volume**.

* **Mount path:** `/data`

> **Without a persistent volume, a redeploy can destroy your account data.**
> The SQLite database, the REALITY private key and the randomised fallback path
> all live in `/data`. If they are lost, every client link you handed out stops
> working and must be re-issued.

RailGate still starts without a volume (useful for a quick look), and the
dashboard will warn you, but do not run it that way for real.

---

## Section 6 — Enable public networking (dashboard)

Railway -> your service -> **Settings** -> **Networking** -> **Public Networking**
-> **Generate Domain**.

Railway asks which port to expose — choose the HTTP port your app listens on
(Railway supplies it through `PORT`; the app binds `0.0.0.0:$PORT`). If asked
for a number, use `8080`.

You get a URL like `https://railgate-production.up.railway.app`. That is your
**admin dashboard** — and also the host for the WebSocket fallback.

---

## Section 7 — Enable the TCP Proxy (the VPN port)

This is the step that makes the primary VLESS + REALITY transport reachable.

Railway -> your service -> **Settings** -> **Networking** -> **TCP Proxy** ->
**Add TCP Proxy**

* **Internal port:** `2443`

Railway then shows something like:

```
metro.proxy.rlwy.net:18423
```

### Internal port vs external port — read this once

| | Value | Meaning |
|---|---|---|
| **Internal port** | `2443` | The port *inside* the container that Xray listens on. This is what you type into Railway's TCP Proxy form. It is fixed and configured by `XRAY_PORT`. |
| **External port** | e.g. `18423` | The port Railway assigns on the public internet. **It is random, and it is not 2443.** Your phone connects to this one. |

**Never assume the external port is 2443.** RailGate reads
`RAILWAY_TCP_PROXY_DOMAIN` and `RAILWAY_TCP_PROXY_PORT` automatically and puts
the correct external values into every generated link — you do not have to copy
them anywhere.

Until you do this step, the dashboard shows **TCP Proxy: NOT CONFIGURED** along
with these instructions, and the service keeps running normally.

---

## Section 8 — Redeploy

Railway injects the new TCP proxy variables into the environment. A running
container does not see variables that appeared after it started, so:

Railway -> **Deployments** -> the latest deployment's menu -> **Redeploy**

After the redeploy, the dashboard should show the real
`something.proxy.rlwy.net:<port>` endpoint. If it still says NOT CONFIGURED, see
[Troubleshooting](#troubleshooting).

---

## Section 9 — Log in to the dashboard

Open your Railway public domain, e.g.
`https://railgate-production.up.railway.app`.

Sign in with `ADMIN_USERNAME` (default `admin`) and your `ADMIN_PASSWORD`.

The dashboard shows Xray status, account counts, the VPN endpoint, system usage
and recent activity.

---

## Section 10 — Create your first VPN user

**Users** -> **Create VPN account**.

* **Username** — e.g. `phone-main` (2–32 chars: letters, digits, `.`, `-`, `_`)
* **Expiration** — Never / 1 day / 7 days / 30 days / Custom date
* **Notes** — optional

Press **Create**. The account is stored, the Xray configuration is re-rendered,
validated and applied — normally without restarting Xray — and you land straight
on the credential page.

---

## Section 11 — Open the credential page

The credential page shows everything for the account:

Protocol, Transport, Security, Flow, SNI, Public Key, Short ID, Fingerprint,
UUID, Server and Port — plus:

* **Copy VLESS link** — the complete `vless://...` URI
* **Show QR code** — generated directly from that URI
* **Download config** — a ready-made Xray client JSON

You never need to dig through Railway logs to find a credential.

---

## Section 12 — Connect Android

Install one of these from Google Play or GitHub:

* **v2rayNG**
* **Hiddify**
* **NekoBox (NekoRay for Android)**

> Menu labels differ between client versions. The wording below matches common
> recent releases; if yours differs, look for the equivalent option.

### v2rayNG

1. Tap the **+** button (top right).
2. Choose **Scan QR code** and scan the QR on the credential page.
   (Or **Import config from clipboard** after tapping *Copy VLESS link*.)
3. The profile appears in the list. Tap it to select it.
4. Tap the round start button at the bottom.
5. Android asks to allow a VPN connection — accept. All apps now route through
   the gateway.

### Hiddify

1. Tap **+** / **New profile**.
2. Choose **Add from clipboard** (after copying the link) or **Scan QR code**.
3. Select the imported profile.
4. Tap the large connect button, and accept Android's VPN permission prompt.

### NekoBox

1. Tap **+** (top right) -> **Scan QR code**, or
   **Import from clipboard** via the menu.
2. Select the new profile in the list.
3. Toggle the connection switch on and accept the VPN permission prompt.

### Verify it works

On the phone, open a browser and search "what is my IP". It should show your
Railway container's outbound address, not your mobile carrier's. The **Server**
page in the dashboard shows the container's own **Outbound Public IP** for
comparison.

---

## Terminal access and vpnctl

RailGate deliberately does **not** run an SSH server. Railway already provides
authenticated shell access; adding a public `sshd` would only enlarge the attack
surface.

```bash
npm i -g @railway/cli        # or: brew install railway
railway login
railway link                 # pick your project/service once
railway ssh
```

For a persistent session that survives a dropped connection:

```bash
railway ssh --session
```

Once inside the container:

```bash
vpnctl                                  # interactive menu
```

```
============================================================
 Railway Personal Gateway
============================================================
  1. Create VPN account
  2. Delete account
  3. Renew account
  4. Disable account
  5. Enable account
  6. List accounts
  7. Show credential
  8. Show QR
  9. Server information
 10. Xray status
 11. Restart Xray
 12. Diagnostics
 13. Backup
 14. Exit
============================================================
 Choose:
```

### Command reference

```bash
vpnctl add USERNAME                     # never expires
vpnctl add USERNAME --days 30
vpnctl add USERNAME --expire 2026-12-31
vpnctl add USERNAME --days 30 --qr      # also print a scannable QR

vpnctl remove USERNAME                  # -y to skip the confirmation
vpnctl disable USERNAME
vpnctl enable USERNAME
vpnctl renew USERNAME --days 30
vpnctl regenerate USERNAME              # new UUID; old links stop working

vpnctl list                             # --json for machine output
vpnctl show USERNAME                    # full credential block
vpnctl uri USERNAME                     # just the vless:// link
vpnctl qr USERNAME                      # QR in the terminal

vpnctl status                           # server summary
vpnctl xray-test                        # validate the configuration
vpnctl restart                          # restart Xray only
vpnctl resync                           # re-render and apply
vpnctl diagnose                         # full diagnostics
vpnctl backup                           # archive db + keys
vpnctl backups                          # list archives
vpnctl restore FILE --confirm           # restore (explicit confirmation)
vpnctl help
```

`vpnctl show` prints everything needed to connect, immediately:

```
============================================================
 Railway Personal Gateway
============================================================
 User        : phone-main
 Status      : Active
 Expires     : Never
 Created     : 2026-08-18 01:02:13+00:00

 VLESS + REALITY (raw TCP)
 ----------------------------------------------------------
 Protocol          : VLESS
 Transport         : TCP
 Security          : REALITY
 Flow              : xtls-rprx-vision
 SNI / Server Name : www.microsoft.com
 Public Key        : yqO8c22cnZs-_looIs6MXwKYfTPeZivGx4g0GXgBWwA
 Short ID          : 258a6c6ffbb6d009
 Fingerprint       : chrome
 UUID              : 6084ceb4-f6fc-474e-9e17-209834a8e385
 Server            : metro.proxy.rlwy.net
 Port              : 18423

 Link:
 vless://6084ceb4-...@metro.proxy.rlwy.net:18423?type=tcp&security=reality&...
```

---

## The WebSocket fallback

Besides the primary REALITY transport, RailGate can serve **VLESS over
WebSocket** through Railway's ordinary HTTPS domain on port 443.

Why it exists:

* It works **before** you configure the TCP Proxy.
* It works on networks that block unusual ports but allow HTTPS.

How it works: the admin app answers the WebSocket upgrade on a **randomised,
unguessable path** (e.g. `/gateway/358d14e97a3ebe0e`), strips the WebSocket
framing and pipes the raw stream to a loopback-only VLESS inbound. That is
exactly what Xray's own `ws` transport does, so unmodified clients work.

* The path is generated on first boot and stored on the volume. It is shown on
  the Server and Settings pages, never guessable, and never `/vless`.
* Requests to any other path get a normal `403`/`404`, revealing nothing.
* TLS is terminated by Railway's edge, so the hop from Railway to your container
  is plaintext *inside Railway's network*; the client-to-Railway hop is HTTPS.
  This is inherent to riding a platform HTTP router.
* XTLS Vision (`flow`) is intentionally **absent** from the fallback link —
  Vision is only valid on raw TCP with TLS/REALITY.

Both links appear on the credential page. Disable the fallback entirely with
`ENABLE_WS_FALLBACK=false`. **The primary REALITY transport works independently
of the fallback.**

---

## Choosing a REALITY destination

REALITY disguises your server as a real third-party HTTPS site.
`REALITY_DESTINATION` must be a genuine site that:

* supports **TLS 1.3** and **X25519**,
* supports **HTTP/2**,
* is **not** your own infrastructure and ideally not behind a big CDN,
* is reachable **from Railway's region**,
* is **not blocked** where your phone is.

`REALITY_SERVER_NAME` must be the hostname of that same site.

Reasonable choices: `www.microsoft.com`, `www.apple.com`, `dl.google.com`,
`www.samsung.com`. The default is `www.microsoft.com:443`.

Verify your choice from inside the container:

```bash
railway ssh
vpnctl diagnose               # shows outbound HTTPS reachability
```

or use **Tools -> REALITY destination check** in the dashboard, which confirms
that the target really negotiates TLS 1.3.

> The Railway public domain is **not** a valid REALITY destination. REALITY needs
> an independent third-party TLS site, not the host you are running on.

---

## Backup and restore

```bash
railway ssh
vpnctl backup
```

The archive contains only what cannot be regenerated:

* `vpn.db` — accounts, settings and events (consistent snapshot via `VACUUM INTO`)
* `reality-private-key`, `reality-public-key`, `short-id`

Logs, rendered configs and other runtime files are excluded.

Copy it off the container:

```bash
railway ssh 'cat /data/backups/railgate-backup-YYYYMMDD-HHMMSS.tar.gz' > backup.tar.gz
```

Restore (destructive — requires explicit confirmation):

```bash
railway ssh
# dry run: prints the manifest and refuses to touch anything
vpnctl restore /data/backups/railgate-backup-YYYYMMDD-HHMMSS.tar.gz
# actually restore
vpnctl restore /data/backups/railgate-backup-YYYYMMDD-HHMMSS.tar.gz --confirm
```

A safety copy of the current state is taken automatically before anything is
overwritten, so a mistaken restore is itself recoverable. Backups are never
downloadable over HTTP.

---

## Troubleshooting

Start here:

```bash
railway ssh
vpnctl diagnose
```

It reports the application and Xray versions, process states, listening sockets,
every Railway variable, database and volume health, account counts, config
validation, DNS and outbound connectivity — with secrets masked.

| Symptom | Cause and fix |
|---|---|
| Deploy crashes: `ADMIN_PASSWORD is missing` | Add the `ADMIN_PASSWORD` variable (Section 4). The container fails closed on purpose. |
| Dashboard says **TCP Proxy: NOT CONFIGURED** | Add the TCP Proxy to internal port `2443` (Section 7), then **redeploy** so the variables are injected. |
| Endpoint still missing after a redeploy | Set `PUBLIC_PROXY_HOST` and `PUBLIC_PROXY_PORT` manually to the values Railway shows. Links keep working regardless of the Railway variables. |
| `Persistent /data directory is not writable` | Attach a Volume mounted at `/data` (Section 5). |
| Healthcheck fails / `/health` returns 503 | Xray is not listening. Run `vpnctl diagnose`, then `vpnctl xray-test`. Health deliberately reports degraded when Xray is down rather than lying. |
| `Xray configuration validation failed; the previous configuration remains active` | Your change was rejected *before* activation, so the tunnel is untouched. `vpnctl xray-test` shows the exact error. |
| Client imports the link but never connects | Check the REALITY destination is reachable and TLS 1.3 (Tools -> REALITY destination check), and that you used the **external** Railway port, not 2443. |
| Older client rejects the link | Set `URI_NETWORK_ALIAS=raw` (or back to `tcp`). Default `tcp` is understood by the widest range of clients; `raw` is the modern Xray name. |
| Logged out after every redeploy | Set `ADMIN_SESSION_SECRET` (Section 4). |
| Account still connects after being disabled | It should not — disabling removes it from the live Xray process immediately. Run `vpnctl resync` and check `vpnctl diagnose`. |

Useful one-liners:

```bash
vpnctl status                                   # quick summary
vpnctl xray-test                                # validate config
/opt/railgate/scripts/validate-xray.sh          # validate the active file
ss -tlnp                                        # listening sockets
jq '.inbounds[].tag' /data/xray/config.json
```

---

## Updating Xray-core

The version is pinned in the [Dockerfile](Dockerfile) and verified twice: once
against a checksum written in the Dockerfile, and once against the publisher's
own `.dgst` file. An unbounded "latest" is deliberately avoided.

1. Pick a release (prefer a **stable**, non-prerelease tag):
   <https://github.com/XTLS/Xray-core/releases>
2. Fetch its checksums:

   ```bash
   V=v26.3.27
   curl -sSL "https://github.com/XTLS/Xray-core/releases/download/$V/Xray-linux-64.zip.dgst"
   curl -sSL "https://github.com/XTLS/Xray-core/releases/download/$V/Xray-linux-arm64-v8a.zip.dgst"
   ```

3. Update `XRAY_VERSION`, `XRAY_SHA256_AMD64` and `XRAY_SHA256_ARM64` in the
   `Dockerfile` with the `SHA2-256` values.
4. Commit and push. Railway rebuilds; the build fails loudly if a checksum
   mismatches.
5. After deploy, confirm with `vpnctl status` and `vpnctl xray-test`.

`geoip.dat` / `geosite.dat` (~30 MB) are intentionally not shipped: routing uses
explicit CIDR literals, so no geo database is needed.

---

## Local development

Docker Compose is for local testing only; Railway does not use it.

```bash
cp .env.example .env
# set ADMIN_PASSWORD in .env
docker compose up --build
```

* Admin panel: <http://localhost:8080>
* Xray (VLESS): `localhost:2443`
* Data: `./data` (git-ignored)

Run the tests:

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Tests that need a real Xray binary are marked `xray` and are skipped
automatically when it is not present:

```bash
python -m pytest -m xray
```

---

## Security notes

* **Fails closed.** In `APP_ENV=production` a missing `ADMIN_PASSWORD` aborts
  startup with exit code 2. There is no default admin password.
* **Argon2id** password hashing; the plaintext password is never stored or logged.
* **Server-side sessions.** The cookie holds a random token; only a keyed hash is
  stored. Cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` in production.
* **CSRF protection** on every state-changing request, including logout.
* **Login rate limiting** with lockout.
* **Strict security headers**, including a CSP with no inline scripts or styles.
* **The REALITY private key never leaves the server** — not in the dashboard, the
  API, share links, logs or diagnostics.
* **No web shell.** The Tools page runs a fixed allow-list of actions with fixed
  argument vectors; there is no arbitrary command execution from the browser.
* **No public SSH daemon.** Use `railway ssh`.
* **The database is never served over HTTP**, and backups are not downloadable.
* **No anonymous accounts.** A fresh deploy has zero users, so nobody can connect
  until you create one.
* **VPN users cannot reach the container's own services or Railway's private
  network** — loopback, RFC1918, link-local and ULA ranges plus
  `*.railway.internal` are blocked in the routing rules. The Xray management API
  and the WebSocket backend bind to `127.0.0.1` only.
* **No browsing activity is recorded.** Logs contain application events only, and
  secrets are scrubbed before anything is written.

---

## Known limitations

These are honest constraints of running a VPN on Railway, not missing features:

* **UDP does not work through the public endpoint.** Railway's TCP Proxy is
  TCP-only. QUIC/HTTP-3 and plain UDP cannot reach the gateway from outside, so
  clients fall back to TCP. Most apps handle this transparently; some UDP-only
  games and voice protocols will not work through the tunnel.
* **No WireGuard, no `/dev/net/tun`, no `NET_ADMIN`, no `iptables`.** Railway
  containers do not grant these, which is why this is a VLESS proxy rather than
  a kernel-level VPN. The Android client provides the system-wide VPN mode.
* **The external TCP port is assigned by Railway and is random.** It can change
  if you recreate the proxy. RailGate re-reads it automatically, but links
  generated earlier would then need regenerating.
* **New Railway variables require a redeploy** before a running container sees
  them.
* **The outbound IP is not guaranteed to be static.** It depends on your Railway
  plan and configuration. Do not assume stability unless Static Outbound IP is
  enabled for your service.
* **The WebSocket fallback is slower than the REALITY path** — it adds an extra
  hop through the Python process, and TLS is terminated at Railway's edge rather
  than by Xray. Use it as a fallback, not the default.
* **Without the `/data` volume, nothing persists.** Accounts and REALITY keys
  would be regenerated on each deploy and all issued links would break.
* **One replica only.** Scaling to multiple replicas would split the SQLite
  database and the REALITY state; `numReplicas` is pinned to 1.
* **This is a personal gateway.** It is not built for reselling access or for
  large numbers of users.

---

## Licence

MIT for this project's code. Xray-core is distributed under its own licence,
included in the image at `/usr/local/share/LICENSE.Xray-core`.