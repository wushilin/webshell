# webshell

A browser-based login shell built with **axum** + **tokio** and
[xterm.js](https://xtermjs.org/). Authenticates against **PAM** (your real
system password), opens a genuine login shell, and gives you persistent,
resumable terminal slots — like an always-attached `tmux`, in the browser.

## Features

- **PAM authentication, single user.** Only the process owner can log in, with
  their system password. Running as root additionally spawns each shell as the
  authenticated user via `login -f`; non-root runs the owner's `$SHELL -l`.
- **Persistent, resumable slots** (default 10). A slot's shell keeps running
  across disconnects; reconnecting replays recent scrollback. Switching between
  opened slots is instant (each is its own always-connected session).
- **Read-only share links.** Generate a login-free, read-only URL to a slot with
  a chosen validity (1d/3d/7d/30d/custom). Read-only and expiry are enforced
  server-side; the viewer mirrors the owner's grid + font, scaled to fit.
- **Security by construction.** Structural auth middleware on `/webshell/private/*`,
  signed `HttpOnly` `SameSite=Strict` session cookies, per-session CSRF tokens on
  every state-changing request and the WebSocket, an `Origin` check on WS
  upgrades, session-id rotation on login, and a login brute-force tarpit.

## Build

```sh
cargo build --release
```

Cross-compile a Linux x86_64 binary from any host (used for deployment) with
`./build-x86_64.sh` — it targets **glibc** via `cargo-zigbuild`, not static musl,
because PAM is loaded at runtime with `dlopen("libpam.so.0")` (static musl's
`dlopen` is a stub). The HTML is embedded into the binary (`include_str!`), so
only the binary is needed at runtime.

## Configure

Configuration is a YAML file (default `config.yaml`):

```sh
webshell genconfig -c config.yaml   # write a default config
webshell validate -c config.yaml    # check it
webshell run -c config.yaml         # run (default subcommand)
```

Keys (all optional; `genconfig` writes the defaults):

| Key | Default | Description |
|---|---|---|
| `bind` | `127.0.0.1:8080` | Listen address. |
| `pam_service` | `login` | PAM service under `/etc/pam.d`. |
| `max_sessions` | `10` | Persistent slots for the user. |
| `max_sharing_duration_secs` | `2592000` | Cap on a share link's lifetime. |
| `sharing_enabled` | `true` | Master switch for share links. |
| `public_base_url` | *(none)* | External base URL — builds absolute share links and derives the accepted WS `Origin`. |
| `scrollback_bytes` | `131072` | Replay buffer per slot. |
| `session_ttl_secs` | `28800` | Login-session lifetime. |
| `cookie_secure` | `false` | Set `true` when served over HTTPS. |
| `allowed_origin` | *(derived)* | Exact WS `Origin` to accept. |
| `secret_base64` | *(ephemeral)* | base64 cookie-signing key (≥64 bytes). |

`WEBSHELL_SECRET` (base64 key) and `WEBSHELL_CONFIG` (config path) may also be set
via the environment.

## Run

```sh
webshell run -c config.yaml
# browse to http://<bind>/webshell/
```

For real multi-user shells (each person gets their own login shell), run as
**root**; the owner-only single-user model applies when running unprivileged.

## Security notes

- **Serve over TLS.** Login sends your system password and the shell stream is
  interactive — over plaintext HTTP both are exposed on the wire. Put TLS in
  front (nginx/caddy), set `cookie_secure: true`, and restrict network exposure.
- The server is in the keystroke path, as with any web terminal — run it only on
  hosts and networks you trust.
