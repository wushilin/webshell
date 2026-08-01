# webshell

A browser-based login shell built with **axum** + **tokio** and
[xterm.js](https://xtermjs.org/). It authenticates against **PAM** (your real
system password), opens a genuine login shell, and gives you persistent,
resumable terminal slots — like an always-attached `tmux`, in the browser — plus
read-only share links so others can watch a session live.

You should put this behind tlsproxy which can manage tls proxying, with automatic ACME (let's encrypt) certificate management.

See https://github.com/wushilin/tlsproxy_rs

You can proxy /webshell to this service by reverse proxy, or simply using SNI host.example.com to do TLS -> Plaintext to this service. Both OK.

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

Reattaching is **byte-exact, not a repaint**. Each shell instance has an `epoch`,
and the client tracks a byte `offset` in that shell's output stream. On reconnect
it sends both back, and the server replies with *exactly the bytes it missed* —
or a full replay, but only if it fell outside the retained window. There is no
screen-scraping, no redraw guesswork, no duplicated output.

**The honest limits:**

- Slots live in the server process. They survive dropped connections and
  restarts of your *browser* — **not** a restart of `webshell` itself.
- The replay window is a ring buffer per slot (`scrollback_bytes`, 128 KiB by
  default). Miss more than that and you get a full replay of what is retained,
  not the whole history.
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
- **Deterministic resume.** The `(epoch, offset)` pair means an agent can know
  precisely what it missed, and can tell "same shell, here's the delta" from
  "this is a different shell now" — a distinction you cannot make by looking at
  a repainted screen.
- **Parallel workstreams.** Slots are independent shells on one connection: run
  the build in one, tail logs in another, keep a REPL in a third.
- **Supervision without interference.** A read-only share link lets a human watch
  an agent work live, from a URL, with **no** ability to type into the session —
  read-only is enforced server-side, not in the UI.
- **Pollable state.** `GET /webshell/private/api/terminals` reports which slots
  are live, so a supervisor can see what is running without attaching.

The wire protocol is deliberately small — JSON control frames (`open`, `resize`,
`mode`, `close`) and binary frames tagged with a one-byte slot index — so it is
straightforward to drive programmatically. Note that authentication is still
PAM + signed cookie + CSRF: an agent has to log in like anyone else, and there is
no API-token path today.

## Screenshots

**Login**

<!-- paste: login screen -->
<img width="447" height="331" alt="image" src="https://github.com/user-attachments/assets/0d5a4457-2bdd-4ca7-9e4c-cb5261e47532" />


**Terminal with slot switcher**

<!-- paste: main terminal + slot bar -->
<img width="1725" height="839" alt="image" src="https://github.com/user-attachments/assets/78ce8119-8f5a-4fa7-961f-87e2b3482633" />


**Create a share link**

<img width="481" height="207" alt="image" src="https://github.com/user-attachments/assets/2339a997-5a00-40f9-b098-4367a40485c9" />


<img width="487" height="252" alt="image" src="https://github.com/user-attachments/assets/b3427b65-6a3a-4a1a-bdf1-3f174d937b68" />

**Read-only shared view (with expiry countdown)**

<!-- paste: read-only viewer -->
<img width="1728" height="457" alt="image" src="https://github.com/user-attachments/assets/d8f918ca-ab98-4673-87e3-c924f7382801" />


## What it does

Point a browser at `https://your-host/webshell/`, log in with your system
password, and you get a real terminal. Each user has a fixed set of **persistent
slots**: the shell in a slot keeps running even after you close the tab, and
reconnecting replays the recent scrollback — so long-running work survives
disconnects and you can pick up exactly where you left off from any device.

You can also hand out **read-only share links** to any slot: a login-free URL
that lets someone watch that terminal live (for pairing, demos, or debugging),
with a validity you choose and no ability to type.

You can even broadcast your live session in 1 to N multicasting.

## Features

- **PAM authentication, single user.** Only the user the process runs as can log
  in, with their real system password (username + password). No app-specific
  accounts to manage.
- **Genuine login shell.** Each session opens the process owner's configured
  login shell with the correct home directory and identity environment.
- **Persistent, resumable slots** (default 10). A slot's shell survives
  disconnects; reattaching replays recent scrollback. Switching between opened
  slots is **instant** — each is its own always-connected session, not a repaint.
- **Reset / recycle** a slot from the toolbar to kill a stuck shell and start
  fresh; other viewers of that slot follow the reset automatically.
- **Read-only share links.** Generate a login-free URL for a slot with a chosen
  validity (1 day / 3 / 7 / 30, or custom seconds) and an optional note saying
  what it is for. Read-only and expiry are **enforced server-side**; the link
  stops working exactly at expiry (the viewer pops an "expired" notice), and
  dies immediately if sharing is disabled.
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
  `/webshell/private/*`, signed `HttpOnly` `SameSite=Strict` session cookies,
  per-session CSRF tokens on every state-changing request and the WebSocket, an
  `Origin` check on WS upgrades, session-id rotation on login, short-lived
  pre-auth sessions, and a login brute-force tarpit.
- **Single static binary.** All HTML/JS is embedded (`include_str!`); deploy just
  the binary + a small YAML config.

## How it works

```
browser (xterm.js)  ──TLS──►  reverse proxy  ──►  webshell (axum)
  /webshell/login              (terminates TLS)     PAM auth, CSRF, session
  /webshell/private/...  ◄── auth-gated ──►         persistent owner-only slots
  /webshell/public/access  ◄── token, read-only ──► each slot = login shell / PTY
```

- `/webshell/login` — PAM login form.
- `/webshell/private/*` — the terminal UI, WebSocket, and APIs (auth-gated by a
  single middleware layer).
- `/webshell/public/access?token=…` — the login-free, read-only viewer.

## Build

```sh
cargo build --release
```

Cross-compile a Linux x86_64 binary from any host with `./build-x86_64.sh` — it
targets **glibc** via `cargo-zigbuild` (not static musl, because PAM is loaded at
runtime with `dlopen("libpam.so.0")`, which a static musl binary can't do).

## Configure

Configuration is a YAML file (default `config.yaml`):

```sh
webshell genconfig -c config.yaml   # write a default config
webshell validate -c config.yaml    # check it
webshell run -c config.yaml         # run (this is also the default subcommand)
```

Keys (all optional; `genconfig` writes the defaults):

| Key | Default | Description |
|---|---|---|
| `bind` | `127.0.0.1:8080` | Listen address. |
| `pam_service` | `login` | PAM service under `/etc/pam.d`. |
| `max_sessions` | `10` | Persistent slots for the user. |
| `max_sharing_duration_secs` | `2592000` | Cap on a share link's lifetime. |
| `sharing_enabled` | `true` | Master switch for share links. |
| `public_base_url` | *(none)* | External base URL — builds absolute share links, and is accepted as a WebSocket `Origin`. |
| `scrollback_bytes` | `131072` | Replay buffer per slot. |
| `session_ttl_secs` | `28800` | Login-session lifetime. |
| `cookie_secure` | `false` | Set `true` when served over HTTPS. |
| `allowed_origins` | *(empty)* | **Extra** WebSocket `Origin`s to accept, on top of the request's own `Host`. Rarely needed — see below. |
| `strict_origin` | `false` | Accept only `allowed_origins` (+ `public_base_url`), refusing any other hostname. |
| `secret_base64` | *(ephemeral)* | base64 signing key (≥64 bytes). Signs session cookies **and** share tokens; set a stable value so both survive restarts. Ephemeral resets both. |

`WEBSHELL_SECRET` (base64 key) and `WEBSHELL_CONFIG` (config path) may also be set
via the environment.

Behind a **TLS reverse proxy**, set `public_base_url` to the browser-facing base
URL — e.g. `https://shell.example.com` — so share links come out absolute.

### WebSocket `Origin`

Every hostname the server is legitimately reached on is accepted out of the box,
with nothing configured: the upgrade is allowed when the browser's `Origin`
matches the `Host` it asked for. That holds for `localhost`, a LAN IP, a tailnet
name and your public domain alike, while a third-party page still fails (it
sends *its* origin with *your* host) — which is the whole point of the check.

`allowed_origins` is only for the case where the browser-facing origin cannot be
recovered from the request — typically a reverse proxy that rewrites `Host` to
the upstream (`Host: 127.0.0.1:8080`), leaving nothing to compare against. Most
proxies forward the original `Host` and need none of this. Symptom when you do
need it: the page loads fine but the terminal sits at "reconnecting", with an
`origin not allowed` warning in the log naming the `Origin` and `Host` it saw.

Entries may be written with or without a scheme, and any path or trailing slash
is stripped:

```yaml
allowed_origins:
  - shell.example.com          # any scheme, this authority
  - https://alt.example.com    # this scheme only
  - https://a.example.com:8443 # non-default ports are part of the authority
```

Set `strict_origin: true` to turn the list into a pin instead of an addition:
the `Host` fallback is dropped and only listed origins (plus `public_base_url`)
are served, so the server refuses to work through an unexpected hostname. It is
ignored while nothing is configured, which would reject every client.

## Run

```sh
webshell run -c config.yaml
# then browse to  https://<public_base_url>/webshell/
```

Run `webshell` as the unprivileged account that will use it. The service is
intentionally single-user and refuses to start as root.

## Security notes

- **Serve over TLS.** The login sends your system password and the shell stream
  is interactive — over plaintext HTTP both are exposed on the wire. Terminate
  TLS in front (nginx/caddy/etc.), set `cookie_secure: true`, and restrict who
  can reach it.
- The server is in the keystroke path, as with any web terminal — run it only on
  hosts and networks you trust.
