# Configurable login_cmd + envs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the config override the spawned shell command (`[terminals] login_cmd`) and seed environment variables (`[terminals.envs]`), defaulting to today's exact behavior; then release v0.1.2 on GitHub with a static musl binary.

**Architecture:** Two new optional keys on the existing `TerminalSettings` table flow through `Config::from_settings` into `Terminals`, and land in a new testable `build_command()` helper extracted from `spawn_terminal`. No protocol or client changes.

**Tech Stack:** Rust (axum, portable-pty 0.8, toml 0.8), cargo-zigbuild + cached zig for the musl cross-build, `gh` CLI for the release.

Spec: `docs/superpowers/specs/2026-08-01-terminal-login-cmd-envs-design.md`

## Global Constraints

- Empty/absent `login_cmd` and `envs` must reproduce current behavior byte for byte: `[pw_shell, "-l"]`, built-in env only.
- `envs` applies AFTER built-ins (`TERM`, `HOME`, `USER`, `LOGNAME`) so config overrides them; cwd stays `owner_home`.
- `envs` must be the LAST field of `TerminalSettings` (TOML: scalar keys before sub-tables).
- `deny_unknown_fields` stays on every settings table.
- Commit trailer on every commit:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_014JpU84cXrJ8o5zuhafCCGw`
- Verified empirically: toml 0.8 `to_string_pretty` DOES emit an empty `[terminals.envs]` header and `login_cmd = []` for the defaults — the sample-config test below relies on that (user approved the empty header).

---

### Task 1: Config plumbing (`[terminals] login_cmd` / `[terminals.envs]`)

**Files:**
- Modify: `src/config.rs` (TerminalSettings ~line 124-141, Config ~line 255, from_settings ~line 331 & 388, tests mod at end)

**Interfaces:**
- Produces: `Config.login_cmd: Vec<String>` (semantics: configured override or passwd-shell default — field already exists), `Config.envs: std::collections::BTreeMap<String, String>` (new). Task 2 consumes both.

- [ ] **Step 1: Write the failing tests** — append inside `mod tests` at the bottom of `src/config.rs`:

```rust
    #[test]
    fn custom_login_cmd_and_envs_pass_through() {
        let cfg = Config::from_settings(Settings {
            terminals: TerminalSettings {
                login_cmd: vec!["/usr/bin/fish".into(), "-l".into()],
                envs: [("EDITOR".to_string(), "vim".to_string())].into(),
                ..TerminalSettings::default()
            },
            ..Settings::default()
        });
        assert_eq!(cfg.login_cmd, vec!["/usr/bin/fish", "-l"]);
        assert_eq!(cfg.envs.get("EDITOR").map(String::as_str), Some("vim"));
    }

    #[test]
    fn unset_login_cmd_and_envs_keep_the_default_behavior() {
        let cfg = Config::from_settings(Settings::default());
        // The default is the runner's passwd shell (unknowable here) + "-l".
        assert_eq!(cfg.login_cmd.len(), 2);
        assert_eq!(cfg.login_cmd[1], "-l");
        assert!(cfg.envs.is_empty());
    }

    #[test]
    fn sample_config_documents_login_cmd_and_envs() {
        let sample = Settings::sample_toml();
        assert!(sample.contains("login_cmd = []"));
        assert!(sample.contains("[terminals.envs]"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib config 2>&1 | tail -20` (or `cargo test config::`)
Expected: COMPILE ERROR — `TerminalSettings` has no field `login_cmd`/`envs`, `Config` has no field `envs`.

- [ ] **Step 3: Implement** — three edits in `src/config.rs`:

(a) Replace the `TerminalSettings` struct + its `Default` (currently ~lines 124-141) with:

```rust
/// The persistent terminal slots themselves.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TerminalSettings {
    /// Persistent slots per user.
    pub max_sessions: usize,
    /// Bytes of recent output retained per slot for replay on reattach.
    pub scrollback_bytes: usize,
    /// Login command override, as an argv array, e.g. ["/usr/bin/fish", "-l"].
    /// Empty = the owner's passwd login shell, run with "-l".
    pub login_cmd: Vec<String>,
    /// Extra environment for every spawned shell, applied after the built-ins
    /// (TERM, HOME, USER, LOGNAME) so a key here overrides them. Declared
    /// last: this serializes as the [terminals.envs] sub-table, and TOML
    /// wants scalar keys before sub-tables.
    pub envs: std::collections::BTreeMap<String, String>,
}

impl Default for TerminalSettings {
    fn default() -> Self {
        TerminalSettings {
            max_sessions: 10,
            scrollback_bytes: 128 * 1024,
            login_cmd: Vec::new(),
            envs: std::collections::BTreeMap::new(),
        }
    }
}
```

(b) In `pub struct Config`, replace the `login_cmd` field + doc comment (~line 255-256) with:

```rust
    /// The spawn command: `[terminals] login_cmd` when set, else the process
    /// owner's passwd login shell invoked with `-l`.
    pub login_cmd: Vec<String>,
    /// Extra environment seeded into every spawned shell ([terminals.envs]).
    pub envs: std::collections::BTreeMap<String, String>,
```

(c) In `from_settings`, replace `let login_cmd = vec![owner.shell.clone(), "-l".into()];` (~line 331) with:

```rust
        // The configured override wins verbatim; empty means the passwd shell.
        let login_cmd = if s.terminals.login_cmd.is_empty() {
            vec![owner.shell.clone(), "-l".into()]
        } else {
            s.terminals.login_cmd.clone()
        };
```

and in the `Config { ... }` literal add, right after `login_cmd,`:

```rust
            envs: s.terminals.envs,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test 2>&1 | tail -10`
Expected: all tests pass, including the 3 new ones. (Full suite, not just config: `main.rs` doesn't yet pass `envs` anywhere, so nothing else breaks — `Config` gaining a field only errors where a `Config` literal is built, which is `from_settings` and `Config::simple` → both go through `from_settings`.)

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "Add [terminals] login_cmd and [terminals.envs] config keys

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014JpU84cXrJ8o5zuhafCCGw"
```

---

### Task 2: Thread envs into the spawn (`build_command` extraction)

**Files:**
- Modify: `src/terminals.rs` (struct ~line 164, `new` ~line 183, `attach` spawn call ~line 248, `spawn_terminal` ~line 357-397, tests mod at end)
- Modify: `src/main.rs` (`Terminals::new` call ~line 362)

**Interfaces:**
- Consumes: `Config.envs: BTreeMap<String, String>` from Task 1.
- Produces: `fn build_command(login_cmd: &[String], user: &str, owner: &str, owner_home: &str, envs: &std::collections::BTreeMap<String, String>) -> anyhow::Result<CommandBuilder>` (private to terminals.rs); `Terminals::new` gains an `envs: std::collections::BTreeMap<String, String>` parameter (6th, after `scrollback_cap` is fine — put it after `login_cmd` to group with it).

- [ ] **Step 1: Write the failing tests** — append inside `mod tests` at the bottom of `src/terminals.rs` (the mod exists; it holds the resume/cut tests):

```rust
    #[test]
    fn build_command_seeds_and_overrides_env() {
        let envs = [
            ("EDITOR".to_string(), "vim".to_string()),
            ("TERM".to_string(), "screen-256color".to_string()),
        ]
        .into();
        let cmd = build_command(
            &["/bin/sh".to_string(), "-l".to_string()],
            "google:x@example.com",
            "alice",
            "/home/alice",
            &envs,
        )
        .unwrap();
        // Config wins over the built-in TERM; new keys are added.
        assert_eq!(
            cmd.get_env("TERM"),
            Some(std::ffi::OsStr::new("screen-256color"))
        );
        assert_eq!(cmd.get_env("EDITOR"), Some(std::ffi::OsStr::new("vim")));
        // Built-ins survive when not overridden.
        assert_eq!(cmd.get_env("HOME"), Some(std::ffi::OsStr::new("/home/alice")));
        assert_eq!(cmd.get_env("USER"), Some(std::ffi::OsStr::new("alice")));
        assert_eq!(cmd.get_env("LOGNAME"), Some(std::ffi::OsStr::new("alice")));
    }

    #[test]
    fn build_command_rejects_an_empty_command() {
        assert!(build_command(&[], "u", "o", "/", &Default::default()).is_err());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib 2>&1 | tail -10`
Expected: COMPILE ERROR — `build_command` not found.

- [ ] **Step 3: Implement** — four edits:

(a) `src/terminals.rs`: extract `build_command` and use it in `spawn_terminal`. Replace the block from `// Resolve the command template.` through `cmd.cwd(owner_home);` (~lines 374-397) with a call, and add the new function ABOVE `spawn_terminal`:

```rust
/// Assemble the spawn command: resolved argv template plus environment.
/// Split from `spawn_terminal` so the env/argv logic is testable without
/// opening a PTY.
fn build_command(
    login_cmd: &[String],
    user: &str,
    owner: &str,
    owner_home: &str,
    envs: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<CommandBuilder> {
    // Resolve the command template. The current configuration contains no
    // user-controlled fields, but keeping substitution here makes Terminals
    // independent of how a command template is assembled.
    let resolved: Vec<String> = login_cmd
        .iter()
        .map(|part| part.replace("{user}", user))
        .collect();
    let (program, args) = resolved
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty login command"))?;

    let mut cmd = CommandBuilder::new(program);
    cmd.args(args);
    cmd.env("TERM", "xterm-256color");
    // Do not trust the service manager's inherited identity environment. The
    // process is already running as the owner, and these values come from that
    // effective user's passwd entry.
    // These name the OS account the shell actually runs as. `user` is the
    // login identity (google:someone@example.com) and only keys the slot pool
    // — putting it in $USER would disagree with `whoami`, which reads the uid.
    cmd.env("HOME", owner_home);
    cmd.env("USER", owner);
    cmd.env("LOGNAME", owner);
    cmd.cwd(owner_home);
    // Config-seeded environment last, so it can override the built-ins.
    for (k, v) in envs {
        cmd.env(k, v);
    }
    Ok(cmd)
}
```

In `spawn_terminal`, the replaced section becomes:

```rust
    let cmd = build_command(login_cmd, user, owner, owner_home, envs)?;
    let program = cmd.get_argv()[0].to_string_lossy().into_owned();
```

(the following `spawn_command` error-mapping line keeps using `{program:?}` and compiles unchanged; `get_argv()[0]` cannot panic — `build_command` already rejected an empty argv).

(b) `spawn_terminal` signature gains the envs parameter (after `owner_home`):

```rust
fn spawn_terminal(
    login_cmd: &[String],
    user: &str,
    owner: &str,
    owner_home: &str,
    envs: &std::collections::BTreeMap<String, String>,
    cols: u16,
    rows: u16,
    scrollback_cap: usize,
) -> anyhow::Result<Terminal> {
```

(c) `Terminals` struct + constructor + attach call site:

```rust
pub struct Terminals {
    pools: Mutex<HashMap<String, Arc<UserPool>>>,
    slots_per_user: usize,
    /// Login command template; `{user}` is substituted per user.
    login_cmd: Vec<String>,
    /// Config-seeded extra environment for every spawn.
    envs: std::collections::BTreeMap<String, String>,
    /// The OS account every shell runs as (login identities all share it).
    owner: String,
    /// The owner's home directory, for the spawned shell's cwd/$HOME.
    owner_home: String,
    scrollback_cap: usize,
}
```

`new` gains `envs: std::collections::BTreeMap<String, String>` right after `login_cmd: Vec<String>`, stored as `envs,`. In `attach`, the `spawn_terminal(...)` call adds `&self.envs,` after `&self.owner_home,`.

(d) `src/main.rs` (~line 362): pass it through and log the effective command right above:

```rust
    tracing::info!("login command: {:?}", config.login_cmd);
    let terminals = Arc::new(Terminals::new(
        config.slots_per_user,
        config.login_cmd.clone(),
        config.envs.clone(),
        config.owner.clone(),
        config.owner_home.clone(),
        config.scrollback_cap,
    ));
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test 2>&1 | tail -10`
Expected: full suite passes, including both new tests.

- [ ] **Step 5: Commit**

```bash
git add src/terminals.rs src/main.rs
git commit -m "Apply configured login_cmd/envs to every shell spawn

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014JpU84cXrJ8o5zuhafCCGw"
```

---

### Task 3: README documentation

**Files:**
- Modify: `README.md` (config table ~line 268-269, new subsection after "Local passwords" ~line 298)

**Interfaces:** none (docs only).

- [ ] **Step 1: Add the two table rows** — the `[terminals]` block of the config table becomes:

```markdown
| `[terminals]` | `max_sessions` | `10` | Persistent slots per identity. |
| | `scrollback_bytes` | `131072` | Replay buffer per slot. |
| | `login_cmd` | *(passwd shell + `-l`)* | Shell override, as an argv array — see below. |
| | `envs` | *(empty)* | Extra environment for every shell — see below. |
```

- [ ] **Step 2: Add the subsection** — insert after the "Local passwords" section (before "### Typical scenarios"):

````markdown
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
````

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Document [terminals] login_cmd and envs

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014JpU84cXrJ8o5zuhafCCGw"
```

---

### Task 4: v0.1.2 release (musl binary via gh)

**Files:**
- Modify: `Cargo.toml` (version 0.1.1 → 0.1.2), `Cargo.lock` (regenerated)

**Interfaces:** none (release engineering). Notes discovered up front:
- PAM is gone from the codebase, so the glibc-only rationale in `build-x86_64.sh` no longer applies — a fully static musl binary is now correct.
- Toolchain present: rustup target `x86_64-unknown-linux-musl`, zig at `~/.cache/musl-cross/zig-linux-x86_64-0.13.0/zig`, `musl-gcc` in `/opt/musl/bin`.
- `gh` is NOT installed and no auth is configured — install + auth are explicit steps.

- [ ] **Step 1: Bump the version**

In `Cargo.toml`: `version = "0.1.1"` → `version = "0.1.2"`.

- [ ] **Step 2: Full test run**

Run: `cargo test 2>&1 | tail -5`
Expected: all pass (this also refreshes `Cargo.lock` with the new version).

- [ ] **Step 3: Build the static musl binary**

```bash
export PATH="$HOME/.cache/musl-cross/zig-linux-x86_64-0.13.0:$PATH"
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

If `cargo zigbuild` is unavailable, fall back to
`cargo build --release --target x86_64-unknown-linux-musl` (musl-gcc is on PATH).

- [ ] **Step 4: Verify the binary**

```bash
BIN=target/x86_64-unknown-linux-musl/release/webshell
readelf -l "$BIN" | grep -c INTERP   # expect 0 (static)
readelf -h "$BIN" | grep Machine     # expect X86-64
"$BIN" genconfig -c /tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/rel-sample.toml
grep -c 'login_cmd\|\[terminals.envs\]' /tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/rel-sample.toml   # expect 2
```

Expected: static x86_64 ELF that runs on this host and its sample config documents the new keys.

- [ ] **Step 5: Commit the bump and push everything**

```bash
git add Cargo.toml Cargo.lock
git commit -m "Bump version to 0.1.2

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_014JpU84cXrJ8o5zuhafCCGw"
git push origin master
```

- [ ] **Step 6: Install gh and authenticate**

```bash
V=$(curl -s https://api.github.com/repos/cli/cli/releases/latest | grep -oP '"tag_name": "v\K[^"]+')
curl -sL "https://github.com/cli/cli/releases/download/v${V}/gh_${V}_linux_amd64.tar.gz" \
  | tar xz -C /tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/
install -D /tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/gh_${V}_linux_amd64/bin/gh ~/.local/bin/gh
gh auth status || true
```

If `gh auth status` shows no auth: STOP and ask the user to run `! gh auth login`
(or provide a `GH_TOKEN`). Git pushes use SSH and work regardless; only the
release API needs the token.

- [ ] **Step 7: Create the release with the binary asset**

```bash
cp target/x86_64-unknown-linux-musl/release/webshell \
   /tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/webshell-0.1.2-linux-x86_64-musl
gh release create v0.1.2 \
  "/tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/webshell-0.1.2-linux-x86_64-musl#webshell 0.1.2 static linux x86_64 (musl)" \
  --title "v0.1.2" \
  --generate-notes \
  --notes "Adds configurable shell command and environment: \`[terminals] login_cmd\` (argv array, default = your passwd login shell + \`-l\`) and \`[terminals.envs]\` (seeded into every shell, overrides built-ins). Unset = previous behavior. Static musl binary attached — no runtime dependencies."
```

Expected: release URL printed; verify with `gh release view v0.1.2`.

---

## Self-review notes

- Spec coverage: config keys (Task 1), spawn application + startup log (Task 2), README (Task 3), sample-config documentation (Task 1 test + Task 4 Step 4 smoke). Release work is user-added scope beyond the spec.
- Type check: `envs` is `std::collections::BTreeMap<String, String>` everywhere (Settings, Config, Terminals, build_command, spawn_terminal). `Terminals::new` param order: `slots_per_user, login_cmd, envs, owner, owner_home, scrollback_cap` — matches the main.rs call in Task 2(d).
- Error message in `spawn_terminal` still interpolates `program` — provided by the `get_argv()[0]` line in Task 2(a).
