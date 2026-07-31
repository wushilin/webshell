# Mobile UX design — key bar, compact top bar, keyboard-aware layout, fast reconnect

Date: 2026-07-31
Scope: `static/terminal.html` only. No server changes, no protocol changes.
Primary target: iPhone Chrome (WebKit — behaves like iOS Safari). Android Chrome
and desktop must not regress.

## Problems

1. Mobile soft keyboards have no Ctrl/Esc/Tab/arrow keys, so interactive
   programs (vim, less, shell history, Ctrl+C) are unusable.
2. The top bar's controls (slots, read-only, share, reset, status, cog, logout)
   overflow on narrow screens; today a media-query hack bumps the pane area to
   `top: 76px` to make room for the wrapped second line.
3. When the soft keyboard opens, iOS WebKit does not resize the layout
   viewport — it scrolls the page, leaving the terminal (and the cursor line)
   hidden behind the keyboard until the user scrolls manually.
4. When the tab is backgrounded, sockets die (accepted — sessions persist
   server-side and replay on reconnect). But on return to foreground, the
   exponential backoff can sit at up to 10 s before reconnecting.

Explicitly out of scope: multiplexing all slots over one WebSocket. Considered
and deferred — background kill happens regardless, sessions persist, and the
per-slot socket design with replay already handles recovery. Not worth
rewriting the transport for reconnect count alone.

## Design

### 1. Mobile key bar

- Shown only on touch devices: gated by `@media (pointer: coarse)` (plus a
  `hidden` fallback class so it never renders on desktop).
- One row of buttons: `Esc` `Tab` `Ctrl` `↑` `↓` `←` `→` `|` `-`.
  `|` and `-` are included because they are buried behind iOS symbol layers.
- Docked at the bottom of the **visible** viewport — directly above the soft
  keyboard when it is open (positioning driven by the visualViewport logic in
  §3), at screen bottom otherwise.
- Key behavior: each key sends its byte sequence through the active session's
  existing input path (same as `term.onData`): Esc = `\x1b`, Tab = `\t`,
  arrows = `\x1b[A/B/C/D`, `|` and `-` literal.
- `Ctrl` is a one-shot sticky modifier: tap → highlighted/armed; the next
  keystroke (from the soft keyboard or a bar key) is translated to its control
  code (`c` → 0x03, etc.) and the modifier disarms. Tapping Ctrl again while
  armed disarms it. Translation happens in the input path shared by
  `term.onData` so it applies to soft-keyboard input. Only a single-character
  chunk is translated; a multi-character chunk (paste, swipe-typed word)
  disarms the modifier and is sent unmodified.
- Bar buttons use `pointerdown` + `preventDefault` so tapping never steals
  focus from the terminal — the soft keyboard stays up.
- Read-only mode: bar input is dropped, same as typed input today.
- The pane area shrinks by the bar height (no overlap with terminal content).

### 2. Compact top bar

- At `max-width: 640px` (existing breakpoint): the bar shows only the slot
  buttons, the status text, and a `⋯` button. Read-only toggle, share, reset,
  ⚙ display settings, and log out move into a call-out popover anchored under
  `⋯`, styled like the existing cog panel.
- The cog panel itself remains a separate popover; the `⋯` menu's "display
  settings" entry opens it.
- Bar is always a single line; the `#panes { top: 76px }` wrap hack is
  deleted. Pane top derives from the actual bar height.
- Desktop (`> 640px`) keeps the current inline layout — the menu button is
  hidden, the inline controls shown, no behavior change.
- Implementation note: the controls exist once in the DOM and are re-slotted
  (moved) between the inline bar and the popover on breakpoint change, so all
  existing event listeners keep working unchanged.

### 3. Keyboard-aware layout (visualViewport)

- If `window.visualViewport` exists, listen to its `resize` and `scroll`
  events. On change: set the app container height to
  `visualViewport.height`, offset by `visualViewport.offsetTop`, pin
  `window.scrollTo(0, 0)`, reposition the key bar to the bottom of the visible
  rect, and refit the active terminal (`fitAndResize` + full-row `refresh`).
- Rapid event bursts are coalesced through `requestAnimationFrame`.
- If `visualViewport` is unavailable, current behavior (window `resize`
  listener) remains the fallback; the key bar docks with `position: fixed;
  bottom: 0`.

### 4. Foreground fast-reconnect

- On `visibilitychange` → `document.visibilityState === "visible"`: for every
  opened session whose socket is not OPEN/CONNECTING, reset
  `reconnectDelay` to the initial 500 ms and call `reconnect()` immediately
  (clearing any pending backoff timer). Existing generation logic already
  guards against double sockets.

## Error handling

- All new input paths respect `readOnly` and closed-socket states (drop
  silently, same as today).
- visualViewport handlers are wrapped defensively; a failure degrades to the
  pre-existing resize behavior, never a blank terminal.

## Testing

- `node --check` on the extracted inline script.
- Desktop regression check: bar layout, popovers, switching, resize.
- Manual on-device verification (iPhone Chrome primarily, Android Chrome
  secondarily): key bar sends sequences (vim, Ctrl+C), bar stays above the
  keyboard, terminal refits when keyboard opens/closes, top bar stays one
  line, backgrounding + returning reconnects promptly.
- iOS WebKit keyboard behavior cannot be reproduced headlessly; on-device
  confirmation by the user is the acceptance gate.

## Addendum (2026-07-31, post-deploy): shift key, touch scrollback, zoom-pan fix

User feedback after first deploy. All client-only (`static/terminal.html`).

### 5. Sticky Shift key

- New `shift` bar key, one-shot sticky like Ctrl (highlight while armed).
- `shift`+`tab` → back-tab `\x1b[Z` (primary use: Claude Code mode switch).
- Armed modifiers apply xterm CSI encoding to arrows: `\x1b[1;{1+shift+4*ctrl}{A|B|C|D}`
  (shift+arrow = `1;2`, ctrl+arrow = `1;5` word-jump, both = `1;6`). This also
  fixes the prior gap where armed Ctrl + arrow sent a plain arrow.
- Keys with no shifted form (esc, `|`, `-`) and typed characters send unchanged
  and consume the armed modifiers (native keyboard shift owns typed letters).

### 6. Touch scrollback scrolling

- One-finger vertical drag on the terminal pane scrolls history via
  `term.scrollLines()`, one line per cell-height of movement, accumulated.
- `preventDefault` on handled moves so the page never pans.
- Skipped when the alternate screen is active (`term.buffer.active.type ===
  "alternate"`) — vim/less own the screen there; and skipped for multi-touch
  so pinch-zoom still works.

### 7. Zoom-pan fix

- The `window.scrollTo(0, 0)` keyboard pin in `layoutViewport()` is gated on
  `vv.scale <= 1.01` (same guard as occlusion) so panning while pinch-zoomed
  is not fought by the layout code.

## Addendum 2 (2026-07-31): keyboard shift-up, pixel-smooth scroll with momentum

User feedback from on-device testing. Client-only (`static/terminal.html`).

### 8. Keyboard = shift, not resize

- Problem: every keyboard open/close refits the terminal → cols/rows change →
  PTY resize (SIGWINCH) → full app reflow, twice per keyboard cycle. Heavy.
- On mobile the layout viewport never changes size except on orientation
  change, so the terminal keeps a FIXED size (full height minus top bar minus
  key bar) and the keyboard becomes a pure visual shift:
  `panesEl.style.transform = translateY(-occluded)` — the bottom rows
  (prompt/cursor) stay visible above the key bar, top rows slide behind the
  top bar. No fit, no PTY resize, no repaint of terminal content.
- `fitAndResize` on viewport events fires ONLY when `window.innerWidth/Height`
  actually changed (orientation, desktop window resize) — tracked via
  last-seen values. Slot activation and font-change fits are unchanged.
- The key bar keeps riding above the keyboard exactly as today.
- `#bar` gets `position: relative; z-index: 35` so shifted pane content
  slides underneath it.

### 9. Pixel-smooth touch scroll with momentum

- Problem: line-quantized `scrollLines(trunc(dy/lineH))` steps ~20px at a
  time and stops dead on finger lift.
- Drag now drives xterm's own scrollable viewport element
  (`.xterm-viewport`, captured once after `term.open`) by the raw pixel
  delta: `viewport.scrollTop -= dy` per move. xterm keeps the buffer in sync
  from its scroll listener; content tracks the finger 1:1.
- Momentum: velocity is low-passed during the drag (`v = 0.8*(dy/dt) +
  0.2*v`); on touchend with |v| > 0.05 px/ms a rAF loop continues
  `scrollTop -= v*dt` with exponential decay (×0.94 per 16.7ms) until
  |v| < 0.02 px/ms. Any new touch, or the alternate screen becoming active,
  stops the fling. `touchcancel` resets state without a fling.
- All existing gesture guards keep working: capture+stopPropagation
  ownership, one-finger only, zoomed → native pan, alternate screen → app
  owns gestures.

### 10. Trim the key bar

- Remove `|` and `-` keys (typeable on the soft keyboard; not worth the
  width). Bar becomes: `esc` `tab` `ctrl` `shift` `↑` `↓` `←` `→`.

### 11. Suppress keyboard autofill/suggestion clutter (best-effort)

- After `term.open()`, harden xterm's hidden textarea
  (`.xterm-helper-textarea`): `autocomplete=off`, `autocorrect=off`,
  `autocapitalize=none`, `spellcheck=false`, a non-form-like `name`, and
  password-manager opt-out data attributes.
- Goal: stop iPhone Chrome offering password/credit-card/address autofill for
  terminal input. Known limitation: the browser's keyboard accessory row is
  not fully page-controllable; attributes are the strongest available lever.
