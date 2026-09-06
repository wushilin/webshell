# webshell

A browser-based login shell built with **axum** + **tokio** and
[xterm.js](https://xtermjs.org/). Sign in with **Google** or a
**webshell-managed password**, add a **TOTP second factor**, and get persistent,
resumable terminal slots — like an always-attached `tmux`, in the browser — plus
read-only share links so others can watch a session live.

It links to no PAM library and shells out to nothing, so it ships as a **single
static binary** with no runtime dependency on the host's auth stack.

You should put this behind tlsproxy which can manage tls proxying, with automatic ACME (let's encrypt) certificate management.

See https://github.com/wushilin/tlsproxy_rs

You can proxy /webshell to this service by reverse proxy, or simply using SNI host.example.com to do TLS -> Plaintext to this service. Both OK.

## Quick start (no config)

To try it out or share a shell quickly, `webshell simple` needs no config file,
no MFA and no Google — just one local user, straight from the environment:

```sh
cargo build --release
WEBSHELL_USER=alice WEBSHELL_PASSWORD=hunter2 target/release/webshell simple
# Web Shell listening on http://127.0.0.1:9023/webshell/
```

| Variable | Default | Description |
|---|---|---|
| `WEBSHELL_USER` | *(required)* | The single username to log in as. |
| `WEBSHELL_PASSWORD` | *(required)* | Its password (checked verbatim; not hashed). |
| `WEBSHELL_BIND` | `127.0.0.1:9023` | Listen address. Set `0.0.0.0:PORT` to expose it. |

```sh
# expose on all interfaces, custom port
WEBSHELL_BIND=0.0.0.0:12702 WEBSHELL_USER=alice WEBSHELL_PASSWORD=hunter2 target/release/webshell simple
```

Nothing is written to disk and no enrollment or session file is created. This
mode is meant for quick, local, trusted sharing — the password lives in the
process environment, and there is no second factor. For anything exposed to the
internet, use the full config below: put it behind TLS and enable MFA.

## Install

Every release ships **statically linked musl binaries** for both architectures.
They have no shared-library dependencies at all — no glibc version to match, no
PAM, nothing to install alongside them. Drop one on any Linux host and run it:

```sh
VER=0.3.0                       # or whatever the latest release is
ARCH=x86_64                     # or aarch64
BASE=https://github.com/wushilin/webshell/releases/download/v$VER

curl -fsSLO $BASE/webshell-$VER-linux-$ARCH-musl
sudo install -m 0755 webshell-$VER-linux-$ARCH-musl /usr/local/bin/webshell
webshell --version
```

Verify the download against the checksums published with the release:

```sh
curl -fsSLO $BASE/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

## Build

```sh
cargo build --release
```

For a fully static binary that runs on any Linux with no shared libraries:

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

This works because nothing here depends on the host's auth stack — no PAM, no
`dlopen`, no setuid helper. `./build-release.sh` builds the static musl binaries
for both x86_64 and aarch64 (via `cargo-zigbuild`) exactly as a release does;
`./build-x86_64.sh` cross-compiles a glibc build if you prefer one.

The one thing a static build gives up is NSS: `getpwuid` reads `/etc/passwd`
directly, so the process owner's login shell and home directory resolve there
and not from LDAP or SSSD. For the single account webshell runs as, that is
almost always what you want anyway — set `[terminals] login_cmd` if it is not.

## Stateful: the shell outlives the connection

This is the point of the project, so it is worth being explicit about.

Most browser terminals hand you a **new shell on every page load**. Here a slot
*is* a long-lived login shell process, and connecting **attaches** to it. Close
the tab, drop off wifi, switch laptops, come back tomorrow — you reattach to the
same process, not a replacement for it.

Across a disconnect and reattach you keep:

- **the same process** — same PID, same children, same jobs still running
- **the working directory**, exported variables, activated virtualenv, `ssh-agent`
  socket, sudo timestamp — everything a fresh `bash -l` would have thrown away
- **whatever was running while you were gone.** A build started before the
  disconnect keeps going with nothing attached; its output is buffered and
  delivered when you return.

Reattaching performs one authoritative replay of the slot's retained console
output, then follows live bytes from that exact cut point. The replay resets the
browser terminal first, which avoids carrying stale parser or fullscreen-screen
state across a dropped connection. There is no screen-scraping or redraw
guesswork.

**The honest limits:**

- Slots live in the server process. They survive dropped connections and
  restarts of your *browser* — **not** a restart of `webshell` itself.
- The snapshot comes from a ring buffer per slot (`scrollback_bytes`, 128 KiB by
  default), so it contains the retained recent console output, not unlimited
  history.
- The slot count is fixed (`max_sessions`, default 10).

### Why this is agent friendly

The same properties that make it pleasant for a human make it genuinely useful
for an automated agent driving a shell:

- **No re-establishing context.** An agent that reconnects is already in the
  right directory with the right environment. No re-`cd`, no re-`export`, no
  re-activating anything — the state it built up is still there.
- **Long tasks don't need a babysitter.** Start a migration or a build, drop the
  connection entirely, reattach later and collect the output. Nothing has to stay
  connected for the work to continue.
- **Deterministic reconnect.** Each attachment receives a bounded console
  snapshot before live output, so a reconnect converges on the server's retained
  state even when the browser's previous terminal renderer became stale.
- **Parallel workstreams.** Slots are independent shells on one connection: run
  the build in one, tail logs in another, keep a REPL in a third.
- **Supervision without interference.** A read-only share link lets a human watch
  an agent work live, from a URL, with **no** ability to type into the session —
  read-only is enforced server-side, not in the UI.
- **Pollable state.** `GET /webshell/private/api/terminals` reports which slots
  are live, so a supervisor can see what is running without attaching.

The wire protocol is deliberately small — JSON control frames (`open`, `resize`,
`mode`, `close`) and binary frames tagged with a one-byte slot index — so it is
straightforward to drive programmatically. Note that authentication still
applies — signed cookie + CSRF, behind Google or a local password: an agent has
to log in like anyone else, and there is no API-token path today.

## Screenshots

**Login**

<!-- paste: login screen -->
<img width="414" height="393" alt="image" src="https://github.com/user-attachments/assets/c7be480e-75c0-456e-be13-a3f8a2ee74e4" />

**Supports MFA**

<img width="401" height="228" alt="image" src="https://github.com/user-attachments/assets/8e876f46-8679-48e5-a643-e05dd0133cc7" />

**Supports Google Login**

<img width="416" height="392" alt="image" src="https://github.com/user-attachments/assets/d5ee2146-c5ee-48e9-b5ee-e192e443f512" />

**Terminal with slot switcher**

<img width="1728" height="366" alt="image" src="https://github.com/user-attachments/assets/bc9fe122-086d-4727-b1c6-e85cae20a0b7" />

**Customizable Terminal Font**

<img width="239" height="172" alt="image" src="https://github.com/user-attachments/assets/3de4a10b-b8bb-4ab6-b9a5-4c7d1e07822a" />


**Create a share link**

<img width="470" height="284" alt="image" src="https://github.com/user-attachments/assets/2dd06b7f-12e8-46bd-80c4-c4714adce794" />


<img width="468" height="253" alt="image" src="https://github.com/user-attachments/assets/a319f25f-8b24-4d88-8c47-7076fc3f7f6e" />

**Read-only shared view (with expiry countdown)**

<!-- paste: read-only viewer -->
<img width="1728" height="367" alt="image" src="https://github.com/user-attachments/assets/920699e5-4793-4321-9bd1-8a0ea73117f5" />


## What it does

Point a browser at `https://your-host/webshell/`, sign in, and you get a real
terminal. Each identity has its own fixed set of **persistent slots**: the shell in a slot keeps running even after you close the tab, and
reconnecting replays the recent scrollback — so long-running work survives
disconnects and you can pick up exactly where you left off from any device.

You can also hand out **read-only share links** to any slot: a login-free URL
that lets someone watch that terminal live (for pairing, demos, or debugging),
with a validity you choose and no ability to type.

You can even broadcast your live session in 1 to N multicasting.

## Features

- **Two ways in, both optional.** **Google sign-in** (OpenID Connect) and a
  **webshell-managed password**. Enable either or both; a method only appears
  when it is also fully configured, so there are no buttons that cannot work.
- **An explicit allowlist.** Every login must match an entry in `auth.users`,
  written as `provider:subject` — `google:you@gmail.com`, `local:alice`. The
  prefix matters: the same address at two providers is two different identities.
- **Optional TOTP second factor.** With `mfa.required`, the first login walks you
  through enrolling an authenticator (QR code or a typed setup key), **per
  identity**. Codes are **single-use** — an accepted code is refused if presented
  again inside its validity window.
- **Multiple people, separate workspaces.** Each identity gets its own slots,
  scrollback and share links. Note they all run as the **same OS account** — this
  is workspace separation, not privilege separation.
- **Genuine login shell.** Each slot opens the process owner's configured login
  shell with the correct home directory and environment.
- **Persistent, resumable slots** (default 10). A slot's shell survives
  disconnects; reattaching replays recent scrollback. Switching between opened
  slots is **instant** — each is its own always-connected session, not a repaint.
- **Reset / recycle** a slot from the toolbar to kill a stuck shell and start
  fresh; other viewers of that slot follow the reset automatically.
- **Read-only share links.** Generate a login-free URL for a slot with a chosen
  validity (1 day / 3 / 7 / 30, or custom seconds) and an optional note saying
  what it is for. Read-only and expiry are **enforced server-side**; the link
  stops working exactly at expiry (the viewer pops an "expired" notice), and
  dies immediately if sharing is disabled. The server ends the stream itself,
  with nothing required of the viewer: the socket's write half lives inside a
  lease guard that checks expiry and revocation before every frame, a timer
  consumes the guard at the deadline, and a scheduled sweep closes anything
  that somehow outlived it. Once invalid, a lease can never become valid again.
- **Revocable sharing.** Every link you hand out is listed under
  *share → Manage existing links*, with its note, slot and time left. Revoke one
  and it stops resolving **and disconnects anyone watching through it right
  then** — not at their next reload. Links are HMAC-signed capabilities tracked
  in memory, so they also all die when the server restarts, and one account may
  hold at most 32 live links.
- **Faithful viewer.** The read-only view mirrors the owner's terminal grid and
  font and scales to fit — no wrong-wrapping from size mismatches — and shows a
  live "expires in …" countdown.
- **Auto-reconnect** with backoff on the client, and a live **font size / family**
  setting persisted in your browser.
- **Security by construction.** Structural auth middleware on
  `/webshell/private/*`, signed `HttpOnly` `SameSite=Lax` session cookies
  (`Secure` when configured), per-session CSRF tokens on every state-changing
  request and the WebSocket, an `Origin` check on WS upgrades, session-id
  rotation on login, short-lived pre-auth sessions, and a login tarpit.
- **No host auth dependency.** No PAM, no `dlopen`, no setuid helper, nothing
  exec'd — so it is unaffected by SELinux confinement and builds as a **static
  musl binary** that runs anywhere.
- **Single static binary.** All HTML/JS is embedded (`include_str!`); deploy just
  the binary + a small TOML config.

## How it works

```
browser (xterm.js)  ──TLS──►  reverse proxy  ──►  webshell (axum)
  /webshell/login              (terminates TLS)     allowlist, CSRF, session
  /webshell/oauth/*      ◄── google sign-in ──►     per-identity slots
  /webshell/private/...  ◄── auth-gated ──►         + TOTP second factor
  /webshell/public/access  ◄── token, read-only ──► each slot = login shell / PTY
```

- `/webshell/login` — the sign-in page (local form, Google button, or both).
- `/webshell/oauth/start` and `/webshell/oauth/callback` — the Google flow.
- `/webshell/mfa` — TOTP enrollment and verification.
- `/webshell/private/*` — the terminal UI, WebSocket, and APIs (auth-gated by a
  single middleware layer).
- `/webshell/public/access?token=…` — the login-free, read-only viewer.

## Configure

Configuration is a TOML file (default `config.toml`), grouped into tables:

```sh
webshell genconfig -c config.toml   # write a starter config
webshell validate  -c config.toml   # check it
webshell passwd    local:alice      # hash a password to paste in
webshell run       -c config.toml   # run (also the default subcommand)
```

Every table and key is optional; a missing one falls back to the default.

| Table | Key | Default | Description |
|---|---|---|---|
| `[network]` | `bind` | `127.0.0.1:8080` | Listen address. |
| | `public_base_url` | *(none)* | Browser-facing base URL. Builds share links, is accepted as a WS `Origin`, and **the Google redirect URI is derived from it**. |
| | `allowed_origins` | *(empty)* | Extra WebSocket `Origin`s, on top of the request's own `Host`. |
| | `strict_origin` | `false` | Accept only the listed origins, dropping the Host fallback. |
| | `cookie_secure` | `false` | Mark the session cookie `Secure`. **Set `true` when served over HTTPS.** |
| `[auth]` | `users` | *(empty)* | The allowlist, as `provider:subject`. Nobody can log in while empty. |
| | `login_methods` | `["local"]` | `"local"`, `"google"`, or both. |
| | `session_ttl_secs` | `28800` | Login-session lifetime. |
| | `session_path` | *(none)* | Optional restart-surviving login session state file. Relative paths resolve beside the config file. |
| | `secret_base64` | *(generated)* | base64 cookie key (≥64 bytes). If unset in config-backed mode, webshell generates one and writes it into the config on startup. |
| `[mfa]` | `required` | `true` | Require a TOTP code. |
| | `enrollment_path` | `enrollment.toml` | Per-identity enrollment state, relative to the config file. |
| | `remember_device` | `false` | Offer "remember this device", letting a browser that has already passed a code skip the **code** — never the password — for a while. See below. |
| | `remember_device_days` | `30` | How long a remembered device stays trusted. Absolute from the moment the box was ticked; clamped to 1–90. |
| | `device_path` | `devices.toml` | Trusted-device state, relative to the config file. |
| | `max_devices_per_identity` | `10` | Simultaneously-trusted browsers per identity; reaching it evicts the least recently used. |
| `[google]` | `client_id` | *(none)* | OAuth client ID. |
| | `client_secret` | *(none)* | OAuth client secret. |
| `[terminals]` | `max_sessions` | `10` | Persistent slots per identity. |
| | `scrollback_bytes` | `131072` | Replay buffer per slot. |
| | `login_cmd` | *(passwd shell + `-l`)* | Shell override, as an argv array — see below. |
| | `envs` | *(empty)* | Extra environment for every shell — see below. |
| `[sharing]` | `enabled` | `true` | Master switch for share links. |
| | `max_duration_secs` | `2592000` | Cap on a link's lifetime. |
| `[certs]` | `lets_encrypt_enabled` | `false` | Terminate TLS in-process with an auto-obtained/renewed Let's Encrypt certificate — see below. |
| | `store_dir` | `certs` | ACME account key + certificate cache, relative to the config file. |
| | `lets_encrypt_staging` | `false` | Use the staging endpoint (untrusted certs, generous rate limits) for first-time setup. |
| | `contact_email` | *(none)* | ACME contact; Let's Encrypt mails expiry warnings if renewal breaks. |
| `[local_passwords]` | *(per identity)* | — | Password per `local:` identity. **Must be last** — see below. |

`WEBSHELL_CONFIG` may point at the config file instead of `-c`.

> **The one TOML trap:** a `[table]` header captures every key after it, so
> `[local_passwords]` has to be the **last** section in the file. Put a plain
> key below it and it silently becomes a password entry, and the server refuses
> to start with a confusing type error.

### Local passwords

Generate a hash and paste the printed line into the config:

```sh
$ webshell passwd local:alice
password for local:alice: ********

[local_passwords]
"local:alice" = "$argon2id$v=19$m=19456,t=2,p=1$...$..."
```

A value that **looks like a hash** — anything shaped `$id$...`, covering argon2,
bcrypt (`$2a$`/`$2b$`/`$2y$`) and crypt(3) `$6$` — is only ever verified as a
hash. There is no fallback to a plaintext comparison, so someone who can read
the config cannot log in by typing the hash itself. A value that is *not* hash
shaped is treated as a literal password, which is convenient for a first run and
compared in constant time. Prefer hashes.

### Custom shell & environment

By default every slot runs your login shell from the passwd database, as
`<shell> -l`. To run a different shell (say fish while your passwd entry
still says bash) and seed extra environment variables:

```toml
[terminals]
login_cmd = ["/usr/bin/fish", "-l"]

[terminals.envs]
EDITOR = "vim"
LANG = "en_US.UTF-8"
```

`login_cmd` is an argv array, used verbatim — no shell quoting or PATH
tricks. `envs` is applied after the built-ins (`TERM`, `HOME`, `USER`,
`LOGNAME`), so it can override them. Leave both out to keep the default
behavior. Note `[terminals.envs]` is a sub-table: plain `[terminals]` keys
must be written above it.

### Typical scenarios

**Just me, one machine, no Google.** Simplest possible setup — no OAuth client,
no internet dependency at login.

```toml
[network]
bind = "127.0.0.1:8080"
public_base_url = "https://shell.example.com"
cookie_secure = true

[auth]
users = ["local:alice"]
login_methods = ["local"]
session_path = "sessions.toml"
# secret_base64 is generated and persisted on first startup if omitted.

[mfa]
required = true

[local_passwords]
"local:alice" = "$argon2id$..."
```

**Google sign-in only.** No password to manage; access is whoever you list.
Remember this puts Google in your login path — if it or your network is down,
you cannot get in.

```toml
[auth]
users = ["google:alice@gmail.com", "google:bob@gmail.com"]
login_methods = ["google"]

[google]
client_id = "....apps.googleusercontent.com"
client_secret = "GOCSPX-..."
```

**Both — recommended.** Google for everyday use, a local password as
break-glass for when Google, DNS or your certificate is having a bad day.

```toml
[auth]
users = ["google:alice@gmail.com", "local:alice"]
login_methods = ["local", "google"]
```

**A small team.** Each identity gets its own slots, scrollback and share links —
but every shell runs as the **same OS account**, so they can read and delete each
other's files. Fine for people who already trust each other; not a substitute for
separate accounts.

```toml
[auth]
users = ["google:alice@gmail.com", "google:bob@gmail.com", "google:carol@gmail.com"]
login_methods = ["google"]
```

### Getting Google credentials

You need an OAuth client of your own — every deployment does, because the
redirect URI is registered per host. It takes about five minutes, costs nothing,
and **requires no review or approval**: webshell asks only for
`openid email profile`, which Google classifies as non-sensitive.

1. **Google Cloud Console** → create (or pick) a project.
2. **APIs & Services → OAuth consent screen.** User type **External**. Fill in
   the app name and your support email. Leave it in **Testing** and add yourself
   under **Test users** — that avoids publishing and any brand review entirely.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID.**
   Application type: **Web application** — *not* "Desktop app". Webshell does the
   code exchange server-side, so it is a confidential client.
4. **Authorised redirect URIs** — add `<public_base_url>/webshell/oauth/callback`,
   exactly, for every hostname you serve. Google does no wildcard or prefix
   matching, and a mismatched trailing slash is a mismatch:

   ```
   https://shell.example.com/webshell/oauth/callback
   http://127.0.0.1:8080/webshell/oauth/callback      # local testing
   ```

   `http://` is only allowed for `localhost`/`127.0.0.1`; everything else must be
   `https://`. Raw IPs other than loopback are rejected. A hostname that resolves
   to a private address is fine — Google validates the string, your DNS decides
   where it points.
5. **Authorised JavaScript origins** — webshell does **not** need any. They are
   for browser-side flows (One Tap, the JS SDK); our token exchange is
   server-to-server. Adding them is harmless, just unnecessary.
6. **Copy two values** into `[google]`: the **Client ID**
   (`...apps.googleusercontent.com`) and the **Client secret** (`GOCSPX-...`).
   Nothing else from the JSON is needed.

The server logs the redirect URI it derived at startup — that line is the
authoritative copy to paste into the console:

```
INFO webshell: google sign-in redirect URI: https://shell.example.com/webshell/oauth/callback
```

If the URI does not match, Google refuses with `redirect_uri_mismatch` before
webshell is ever reached. If your account is not under **Test users** while the
app is in Testing, Google refuses with an "app has not completed verification"
notice.

#### If Google sign-in is your only method, plan the lockout

With `login_methods = ["google"]` there is no other door. A revoked OAuth
client, an expired secret, a DNS or network outage, or simply deleting yourself
from **Test users** locks everyone out of the web UI at once. Nothing is lost —
the config is a file on the host, and you fix it with shell access:

```sh
# on the host, as the account webshell runs as
$EDITOR config.toml        # login_methods = ["local", "google"]
                           # and make sure [local_passwords] has an entry
webshell passwd local:alice   # prints an argon2id hash to paste in
webshell validate -c config.toml
# restart the service
```

Keeping `"local"` in `login_methods` permanently — with MFA on and a strong
argon2id password — costs nothing and removes the failure mode entirely. If you
do run Google-only, make sure you can still get a shell on the host by some
other route.

### TOTP MFA

With `mfa.required = true`, an identity with no enrolled secret is sent through
enrollment on its next login: scan the QR (or type the setup key) and submit a
code. **The secret is only stored once a code proves the authenticator has it**,
so an abandoned enrollment leaves nothing behind. Enrollment is per identity, so
signing in with Google and with a local password gives you two separate entries.

**Codes are single-use.** A TOTP code stays valid for its whole time step plus
one either side, so without this the same six digits would authenticate more than
once — the property a one-time password exists to prevent. Webshell remembers the
last few accepted codes per identity and refuses a repeat for as long as it could
still verify. Resubmit one and you are told it has already been used; wait for the
next. The memory lives in the process, so a restart clears it — harmless, since a
code from before a restart has almost certainly expired.

`[mfa].enrollment_path` is written by webshell, not you. It holds each identity's
secret and the Google `sub` pinned on first login, and is created mode `0600`.

### Remember this device

Off by default. With `mfa.remember_device = true`, the verify screen offers
**Remember this device for 30 days**. Tick it and that browser stops being asked
for a code until the window runs out.

**It skips the second factor only.** The password, or the Google sign-in, is
verified on every single login regardless. The cookie is not a credential that
logs anyone in — it is evidence that this browser has already proved possession
of the authenticator. It also never skips enrollment: an identity with no secret
always goes through the QR screen.

Some details worth knowing before turning it on:

- **The window is absolute**, counted from when you ticked the box, and using the
  device never extends it. A sliding window would let a stolen cookie refresh its
  own lifetime indefinitely.
- **Re-enrolling a TOTP secret revokes every device** for that identity. This is
  also the recovery path: to un-trust everything for someone who lost their
  authenticator, delete their `mfa_secret` line from `enrollment.toml`. Their
  devices stop working the moment the secret changes, with no second cleanup step.
- **Turning `remember_device` back off revokes trust immediately** — an existing
  cookie stops being honoured, it does not merely stop being issued. The records
  are kept, so switching it on again restores them.
- **Trust survives logging out**, which is the point. The devices dialog offers
  *Sign out & forget this browser* when you want both.
- One cookie holds trust for one identity. A browser used by two allowlisted
  identities is only trusted for whichever ticked the box most recently.

Manage them from the **devices** button in the terminal toolbar (under `⋯` on a
narrow screen): every trusted browser you hold, which one you are using now, when
each was last used, and a revoke button for one or all. It is self-service — you
see only your own devices, exactly as with share links.

`[mfa].device_path` is written by webshell, not you, and is created mode `0600`.
It stores a hash of each cookie rather than the cookie itself, so the file is not
a set of usable bypasses.

## Run

```sh
webshell run -c config.toml
# then browse to  https://<public_base_url>/webshell/
```

Run `webshell` as the unprivileged account whose shell you want. It refuses to
start as root, and every slot — whoever signed in — runs as that account.

It also refuses to start when no login method can work, rather than presenting a
page nobody can get past:

```
invalid config: No login methods possible.
  local:  needs "local" in login_methods and at least one local: user
  google: needs "google" in login_methods, google_client_id, google_client_secret and public_base_url
```

## Security notes

- **Serve over TLS.** The login carries a password and the shell stream is
  interactive — over plaintext HTTP both are exposed on the wire. Terminate TLS
  in front (tlsproxy/nginx/caddy) — or let webshell do it, see *Built-in TLS with Let's Encrypt* — set `[network].cookie_secure = true`, and
  restrict who can reach it.
- **Protect the config file.** It holds the cookie key, the Google client secret
  and every local password hash. Keep it `0600`; webshell writes
  `enrollment.toml` and configured session stores that way itself.
- **`local:` passwords are not system passwords.** They are webshell's own, and
  their hashes live in a file owned by the account being protected rather than in
  root-only `/etc/shadow`. Use hashes, not plaintext, and pair them with MFA.
- **One OS account.** Multiple identities mean separate workspaces, not separate
  privileges — everyone who can log in gets a shell as the process owner.
- **Session persistence is opt-in login persistence, not PTY persistence.** Set
  `[auth].session_path` to keep meaningful login state across restarts:
  authenticated sessions, MFA-pending sessions and in-progress Google flows.
  Anonymous login-page CSRF sessions stay memory-only and bounded. Running
  shells still live in the webshell process, so a webshell restart drops
  terminal processes even though the browser login can survive.
- The server is in the keystroke path, as with any web terminal — run it only on
  hosts and networks you trust.

### WebSocket `Origin`

Every hostname the server is legitimately reached on is accepted out of the box:
the upgrade is allowed when the browser's `Origin` matches the `Host` it asked
for. That holds for `localhost`, a LAN IP and your public domain alike, while a
third-party page still fails — it sends *its* origin with *your* host, which is
the whole point of the check.

`[network].allowed_origins` is for when the browser-facing origin cannot be
recovered from the request — typically a proxy that rewrites `Host` to the
upstream. Symptom: the page loads but the terminal sits at "reconnecting", with
an `origin not allowed` warning in the log naming what it saw. Entries may be
written with or without a scheme; any path or trailing slash is stripped:

```toml
[network]
allowed_origins = [
  "shell.example.com",          # any scheme, this authority
  "https://alt.example.com",    # this scheme only
  "https://a.example.com:8443", # non-default ports are part of the authority
]
```

Set `strict_origin = true` to turn the list into a pin: the `Host` fallback is
dropped and only listed origins (plus `public_base_url`) are served, so the
server refuses to work through an unexpected hostname. Remember to list *every*
hostname you serve, or its terminal will not connect.

### Built-in TLS with Let's Encrypt

Instead of a TLS proxy in front, webshell can terminate TLS itself:

```toml
[network]
bind = "0.0.0.0:443"                       # must be :443, non-loopback
public_base_url = "https://shell.example.com"  # the certificate hostname

[certs]
lets_encrypt_enabled = true
contact_email = "you@example.com"          # optional: expiry warnings
```

The certificate hostname is derived from `public_base_url` (which must be
`https://` and a real DNS name — no IPs, no localhost). Validation is
TLS-ALPN-01 on the same listener: no port 80, no separate challenge server,
but Let's Encrypt must be able to reach **this** machine on port 443 of that
hostname, so DNS has to point here and the bind is checked at startup —
anything other than a non-loopback `:443` refuses to start with the reason.
`cookie_secure` is forced on. Certificates renew automatically; every ACME
event is logged under an `acme:` prefix.

Binding port 443 as an unprivileged user (webshell refuses to run as root)
needs one of:

```sh
sudo setcap cap_net_bind_service=+ep "$(command -v webshell)"   # or:
# systemd unit:  AmbientCapabilities=CAP_NET_BIND_SERVICE
# or:            sysctl net.ipv4.ip_unprivileged_port_start=443
```

First time on a new host, set `lets_encrypt_staging = true`, confirm issuance
in the log (the browser will warn — staging certs are untrusted), then flip
it off and delete the contents of `store_dir`. A failed production attempt
counts against Let's Encrypt's strict rate limits; staging's are generous.
