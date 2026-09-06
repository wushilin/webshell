# Remember This Device (MFA Trust) — Design

**Date:** 2026-09-06
**Status:** Approved

## Goal

Let a user who has just passed a TOTP challenge mark the browser they are
sitting at as trusted, so that for a bounded window (default 30 days) logging
in on that browser asks for the password or Google sign-in but **not** the
authenticator code. Opt-in per deployment: when the feature is off — the
default — no checkbox is rendered, no trust cookie is minted, and any trust
cookie that already exists is ignored.

The user manages their own trusted devices from a modal in the terminal UI's
`⋯` menu, alongside the existing share-link management.

## Background

MFA today is unconditional whenever `[mfa] required = true`. Both login paths
end identically (`main.rs:940` for local, `main.rs:1120` for Google):

```rust
if !state.config.mfa_required { /* login */ }
let new_id = state.sessions.begin_mfa(&id, &user);
```

A second factor exists to establish that a *new* context possesses the
authenticator. Once a specific browser has proved that, re-proving it on every
session expiry (`session_ttl_secs`, 8h by default) buys little and costs a
phone reach several times a day.

Two existing mechanisms are reused rather than reinvented:

- **The signed cookie jar.** `webshell_sid` is already an opaque random token
  carried in a `SignedCookieJar` and looked up server-side by
  `sha256(token)` (`session.rs`, `session_key`). The trust cookie is the same
  shape.
- **The share-grant store.** `share.rs` mints HMAC-authenticated capabilities
  with an absolute expiry, tracks them server-side so the owner can list and
  revoke them, caps them per user, and sweeps them on a timer. Device trust is
  the same problem with a longer clock and a disk file behind it.

## What the trust cookie is and is not

It skips **the second factor only**. The first factor — the local password or
the Google sign-in — is verified on every single login, unchanged. The cookie
is not a credential that logs anyone in; it is evidence that this browser has
already demonstrated possession of the authenticator for this identity.

It also never skips **enrollment**. An identity with no `mfa_secret` always
goes through the QR screen, whatever cookie the browser presents.

## Token shape

A new cookie:

```
name      webshell_td
value     random_token(24), opaque
signed    by the existing SignedCookieJar (master key), like webshell_sid
Path      /webshell
HttpOnly  yes
SameSite  Lax
Secure    follows network.cookie_secure
Max-Age   the trust window
```

`SameSite=Lax` is required, not merely preferred: the Google callback is a
cross-site top-level GET, and `Strict` would withhold the cookie at exactly
the moment it is needed. Unlike `webshell_sid` this cookie carries an explicit
`Max-Age` — a browser-session cookie would evaporate on browser restart,
which is the main thing the feature is supposed to survive.

Server-side, the record is keyed by `sha256(cookie value)`, so the file never
holds a value that is itself a bearer token.

### Why not a self-contained token

A stateless signed token (all the claims inside, verified by HMAC alone) is
simpler, and it is the wrong choice here. It cannot be revoked, cannot be
listed, and cannot record a last-used time — which is precisely the management
UI this feature is being built around. Key rotation would be the only
revocation, and it would sign everyone out at once.

So: signature **and** server-side record. The signature is the cheap filter
that rejects a garbage or tampered cookie without taking a lock or touching
the disk; the record is what actually authorizes.

## Binding

A trust record is bound to two things:

- **The identity** (`google:you@example.com`), not the OS account. Every
  allowlisted identity gets its own trust.
- **`enrolled_at`** from `enrollment.toml`. This is the load-bearing one: if
  the TOTP secret is ever reset and re-enrolled, `enrolled_at` changes and
  every existing trust record for that identity stops matching. "Reset my MFA"
  implies "forget my devices" with no separate step to remember, and if the
  enrollment is deleted outright the identity is no longer enrolled, so trust
  is never honoured at all.

Deliberately **not** bound to IP or User-Agent. Phones roam between cell and
wifi, laptops move between networks, and browsers auto-update their UA string;
comparing either would un-trust honest users at random. Both are *recorded*
for display in the management modal, never compared.

## Expiry

Absolute, counted from the moment the box was ticked. It never slides forward
on use.

Sliding renewal would mean a stolen cookie that keeps getting used never has
to face the authenticator again — it refreshes its own lifetime indefinitely.
An absolute ceiling means every trusted browser re-proves possession roughly
once a window, and a cookie stolen on day 29 is worth one day.

The token is not rotated on use either. Rotation would give stolen-cookie
detection, but two tabs logging in concurrently would race and one would be
spuriously un-trusted. Not worth it at this scale.

## Config surface

New keys in the existing `[mfa]` table:

```toml
[mfa]
required = true
enrollment_path = "enrollment.toml"
remember_device = false          # master switch; default off
remember_device_days = 30        # clamped to 1..=90
device_path = "devices.toml"     # relative paths resolve against the config dir
max_devices_per_identity = 10
```

`remember_device = false` means both that the checkbox is never rendered *and*
that a presented trust cookie is never honoured. Turning the switch off must
revoke trust immediately, not merely stop minting more.

`Settings` uses `deny_unknown_fields` with `#[serde(default)]`, so an existing
config file keeps parsing against the new binary; a config using the new keys
against an old binary fails loudly, which is correct.

Simple mode (`webshell simple`) runs with `mfa.required = false`, so the
feature is inert there.

## Storage

A new file, `devices.toml`, written by a new `src/devices.rs` — not folded
into `enrollment.toml`. The reasoning in `enrollment.rs`'s own header applies
twice over here: that file holds every user's TOTP secret and is rewritten
rarely, while device trust is churny (a `last_used_at` update per login), and
a bad write to the churny file must not be able to take the secrets with it.

Same discipline as the other state files: whole-file atomic write via a
`.tmp` + `rename`, mode 0600, stable sort order so diffs stay readable.

```rust
pub struct Device {
    pub id: String,            // public, shown in the UI and logs
    pub identity: Identity,
    pub token_hash: String,    // base64(sha256(cookie value))
    pub created_at: u64,
    pub expires_at: u64,
    pub last_used_at: u64,
    pub enrolled_at: u64,      // binds to the TOTP secret generation
    pub user_agent: String,    // display only, sanitized
    pub created_ip: String,    // display only
    pub last_ip: String,       // display only
}
```

`user_agent` and the IP strings are attacker-influenced values that end up in
an HTML page. They get the `share::sanitize_note` treatment — control
characters collapsed to spaces, length bounded — and the modal renders them
via `textContent`, exactly as share notes already are.

`max_devices_per_identity` is enforced on mint by evicting the
least-recently-used record rather than refusing, mirroring the intent of
`MAX_GRANTS_PER_USER` but choosing eviction: a real person has a handful of
browsers, and a refusal at the cap would be baffling where a silent recycle is
not.

Expired records are pruned on load, on mint, and by the existing 60-second
sweep task in `serve()` that already drives `sessions.sweep()` and
`shares.sweep()`.

## Login flow

Both login paths grow a middle branch. Today:

```rust
if !state.config.mfa_required { /* login */ }
begin_mfa(...)
```

Becomes:

```rust
if !state.config.mfa_required { /* login */ }
if let Some(device) = trusted_device(&state, &jar, &identity) {
    // logs: "MFA skipped for {identity} via trusted device {device.id}"
    /* login */
}
begin_mfa(...)
```

`trusted_device` returns a record only when all of the following hold:
`mfa.remember_device` is on, the cookie is present and its signature is valid,
a record exists for `sha256(value)`, the record's identity matches the
identity that just passed the first factor, the record has not expired, the
identity is currently enrolled, and the record's `enrolled_at` equals the
current enrollment's. Anything else falls through to `begin_mfa`.

A cookie that is presented but fails any of these is **cleared** from the
browser and logged, rather than left in place to fail again on every
subsequent login.

The check sits after the first factor, so the existing `LoginGuard` tarpit
still governs the rate at which anyone can probe it.

## Minting

The checkbox lives on `static/mfa_verify.html` only. `static/mfa.html` — the
first-enrollment QR screen — is untouched, so enrollment stays one job:
scan, confirm, done. Trust is established on a later login.

The checkbox is rendered by a template substitution that produces an empty
string when `mfa.remember_device` is off, following the `render_login`
convention already in `main.rs`: a disabled affordance is *absent from* the
page, not merely invisible in it.

`mfa_submit` mints the record and sets the cookie only after the code has
verified, passed the replay guard, and (in the enrolling case) the secret has
been persisted.

## Management UI

A "trusted devices" entry in the existing `⋯` menu in `static/terminal.html`,
opening a modal structurally identical to the "Manage existing links" share
modal: a list of the caller's own devices with a revoke button each, plus
"revoke all", reusing the modal CSS and the generic confirm dialog already
there.

Two new routes under the existing private router — so they are protected
structurally, by the `require_auth` layer, rather than by each handler
remembering to check:

```
GET  /webshell/private/api/devices          list the caller's own devices
POST /webshell/private/api/device/revoke    revoke one, or all
```

Both are scoped to `session.username` the same way `share::revoke(username,
id)` is: a caller can only ever see and revoke their own records, and an id
belonging to someone else is indistinguishable from one that does not exist.
Revoke takes the CSRF token like every other mutating endpoint.

The device the request is coming from is flagged as "this browser" in the
list, so revoking the others is unambiguous.

## Logout

Logging out does **not** clear the trust cookie. Surviving logout is the
entire point of the feature. The logout control grows a companion action —
"sign out and forget this device" — which revokes the current device's record
and clears the cookie in the same request.

## Known limitation

One cookie holds trust for one identity. A browser used by two allowlisted
identities can only be trusted for whichever ticked the box most recently; the
other is challenged normally and can re-tick, displacing the first. Carrying a
set of identities in one cookie is over-engineering for a service whose logins
all land on a single OS account.

## Testing

Unit tests in `devices.rs`, in the style of the existing `enrollment.rs` and
`totp.rs` suites:

- a record round-trips through a save and reload
- `devices.toml` is written 0600
- an expired record is not honoured and is pruned
- a record whose `enrolled_at` no longer matches the enrollment is not honoured
  (the MFA-reset path)
- a record for identity A is not honoured for identity B
- the per-identity cap evicts least-recently-used, and the cap counts only
  live records
- with `remember_device = false`, an otherwise-perfect record is not honoured

Plus a `tests/` level check that a trusted cookie skips the TOTP step while a
wrong password still fails, so the "first factor is never skipped" property is
pinned by a test and not only by review.

## Out of scope

- Any admin or operator role. There is none in this codebase today: every
  allowlisted identity is equal and they all get a shell as the same OS
  account, so an "admin" would be a UI convenience rather than a real
  privilege boundary. Recovery for a lost authenticator is the operator
  editing `enrollment.toml` to drop that identity's `mfa_secret`, which kills
  their device records for free via the `enrolled_at` binding.
- CLI subcommands for device management.
- Sliding expiry, token rotation on use, and IP or User-Agent pinning — all
  considered and rejected above.
- User-supplied device labels. The recorded User-Agent is enough to tell one
  browser from another, and a free-text field is another attacker-influenced
  string to sanitize for no real gain.
