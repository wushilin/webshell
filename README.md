# webshell

A browser-based login shell built with **axum** + **tokio** and
[xterm.js](https://xtermjs.org/). It authenticates against **PAM** (your real
system password), opens a genuine login shell, and gives you persistent,
resumable terminal slots — like an always-attached `tmux`, in the browser — plus
read-only share links so others can watch a session live.

## Screenshots

**Login**

<!-- paste: login screen -->
<img width="447" height="331" alt="image" src="https://github.com/user-attachments/assets/0d5a4457-2bdd-4ca7-9e4c-cb5261e47532" />


**Terminal with slot switcher**

<!-- paste: main terminal + slot bar -->
<img width="1725" height="839" alt="image" src="https://github.com/user-attachments/assets/78ce8119-8f5a-4fa7-961f-87e2b3482633" />


**Create a share link**

<img width="481" height="207" alt="image" src="https://github.com/user-attachments/assets/2339a997-5a00-40f9-b098-4367a40485c9" />

<!-- paste: share modal -->
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
- **Genuine login shell.** Running as root, each session is spawned as the
  authenticated user via `login -f` (real PAM session, correct uid/gid, groups,
  `$HOME`, utmp). Running unprivileged, it opens the owner's own login shell.
- **Persistent, resumable slots** (default 10). A slot's shell survives
  disconnects; reattaching replays recent scrollback. Switching between opened
  slots is **instant** — each is its own always-connected session, not a repaint.
- **Reset / recycle** a slot from the toolbar to kill a stuck shell and start
  fresh; other viewers of that slot follow the reset automatically.
- **Read-only share links.** Generate a login-free URL for a slot with a chosen
  validity (1 day / 3 / 7 / 30, or custom seconds). Read-only and expiry are
  **enforced server-side**; the link stops working exactly at expiry (the viewer
  pops an "expired" notice), and dies immediately if sharing is disabled. Tokens
  are **stateless and HMAC-signed** (they carry their own slot + expiry), so they
  keep working **across server restarts** — provided a stable `secret_base64` is
  set — with nothing stored server-side.
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
  /webshell/private/...  ◄── auth-gated ──►         persistent per-user slots
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
| `public_base_url` | *(none)* | External base URL — builds absolute share links and derives the accepted WebSocket `Origin`. |
| `scrollback_bytes` | `131072` | Replay buffer per slot. |
| `session_ttl_secs` | `28800` | Login-session lifetime. |
| `cookie_secure` | `false` | Set `true` when served over HTTPS. |
| `allowed_origin` | *(derived)* | Exact WebSocket `Origin` to accept. |
| `secret_base64` | *(ephemeral)* | base64 signing key (≥64 bytes). Signs session cookies **and** share tokens; set a stable value so both survive restarts. Ephemeral resets both. |

`WEBSHELL_SECRET` (base64 key) and `WEBSHELL_CONFIG` (config path) may also be set
via the environment.

Behind a **TLS reverse proxy**, set `public_base_url` (and thus `allowed_origin`)
to the exact browser-facing origin — e.g. `https://shell.example.com` (include a
non-default port if any). A mismatch here rejects the WebSocket upgrade and the
terminal will just say "reconnecting".

## Run

```sh
webshell run -c config.yaml
# then browse to  https://<public_base_url>/webshell/
```

For real multi-user shells (each person gets their own login shell as themselves),
run as **root**; the owner-only single-user model applies when running
unprivileged.

## Security notes

- **Serve over TLS.** The login sends your system password and the shell stream
  is interactive — over plaintext HTTP both are exposed on the wire. Terminate
  TLS in front (nginx/caddy/etc.), set `cookie_secure: true`, and restrict who
  can reach it.
- The server is in the keystroke path, as with any web terminal — run it only on
  hosts and networks you trust.
