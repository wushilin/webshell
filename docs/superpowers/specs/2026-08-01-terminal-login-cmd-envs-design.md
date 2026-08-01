# Configurable shell command and environment

Date: 2026-08-01
Scope: `src/config.rs`, `src/terminals.rs`, `README.md`. No protocol or
client changes.

## Problem

The spawned shell is always the process owner's passwd login shell run as
`<shell> -l`. A user whose passwd entry says bash but who prefers fish (or
wants tmux, a jail wrapper, etc.) cannot change it without `chsh`. There is
also no way to seed environment variables into every spawned shell.

## Design

Two new optional keys in the existing `[terminals]` table:

```toml
[terminals]
max_sessions = 10
scrollback_bytes = 131072
# Optional. Default (empty/absent) = the owner's passwd login shell + "-l".
login_cmd = ["/usr/bin/fish", "-l"]

# Optional. Extra environment for every spawned shell, applied AFTER the
# built-ins (TERM, HOME, USER, LOGNAME) so it can override them.
[terminals.envs]
EDITOR = "vim"
LANG = "en_US.UTF-8"
```

- `login_cmd` empty or absent → current behavior, byte for byte:
  `[pw_shell, "-l"]` from the passwd DB. Non-empty → used verbatim as
  `argv` (first element = program, rest = args). No shell-quoting, no
  PATH search semantics beyond what `CommandBuilder` provides.
- `envs` is applied to every spawn after the built-in
  `TERM=xterm-256color`, `HOME`, `USER`, `LOGNAME` assignments, so a
  configured key overrides a built-in. cwd stays the owner's home.

## Implementation

`src/config.rs`:

- `TerminalSettings` gains:
  - `login_cmd: Vec<String>` — default empty.
  - `envs: BTreeMap<String, String>` — default empty, **declared last** in
    the struct: TOML serialization requires scalar values before
    sub-tables, and `envs` becomes the `[terminals.envs]` sub-table.
- `Config` gains `envs: BTreeMap<String, String>`.
- `Config::from_settings`: `login_cmd` = the configured vector when
  non-empty, else `vec![owner.shell, "-l"]`; `envs` passes through.
- Both keys appear in `sample_toml()` output (serialized defaults).
  `deny_unknown_fields` stays on every table.

`src/terminals.rs`:

- `Terminals` stores `envs` alongside its existing `login_cmd` field;
  constructor takes it; `attach`'s spawn call passes it down.
- `spawn_terminal` takes `envs: &BTreeMap<String, String>` and, after the
  existing built-in `cmd.env(...)` calls, applies
  `for (k, v) in envs { cmd.env(k, v); }`.

`src/main.rs` (`Terminals::new` call, ~line 362): thread `config.envs`
through.

Startup logs the effective login command (`tracing::info!`) so a
misconfiguration is visible immediately.

## Error handling

- A bad `login_cmd` (nonexistent program, non-executable) fails at spawn
  exactly like today's failure path: the error is logged, the attach
  returns an error, the client's slot gets `closed "error"`. The server
  keeps running; other slots are unaffected. No startup validation of the
  program path — the file may legitimately appear later (e.g. a mount).
- An empty string as the program (e.g. `login_cmd = [""]`) fails at spawn
  with the OS error; an empty vector means "use the default".

## Out of scope

- Documenting `{user}` substitution: the internal template mechanism
  remains, but `user` there is the login identity
  (`google:x@example.com`), not the OS account — advertising it would
  confuse.
- Per-slot or per-identity commands.
- Startup validation that the program exists.

## Testing

- `cargo test` unit test in config.rs: `login_cmd`/`envs` set →
  `Config.login_cmd`/`Config.envs` carry them; unset → passwd-shell
  default and empty map.
- `cargo build` + manual: set `login_cmd = ["/usr/bin/fish", "-l"]` and an
  `envs` override, open a slot, verify `echo $SHELL`-independent fish
  prompt and `echo $EDITOR`.
