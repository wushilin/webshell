# Mobile UX Addendum 2 Implementation Plan (shift-up keyboard, smooth scroll, bar trim, autofill hardening)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keyboard open/close becomes a pure visual shift (no PTY resize); touch scrolling becomes pixel-smooth with momentum; the key bar drops `|`/`-`; xterm's hidden textarea stops attracting iOS autofill suggestions.

**Architecture:** All in `static/terminal.html`. §8 rewrites `layoutViewport()` (transform instead of bottom-resize, fit only on real `innerWidth/Height` change). §9 rewrites the Session touch handlers (drive `.xterm-viewport.scrollTop` by pixel deltas + rAF momentum fling). §10/§11 are small edits to the KEYS table and Session constructor.

**Spec:** `docs/superpowers/specs/2026-07-31-mobile-ux-design.md` §8–§11

## Global Constraints

- Single file: only `static/terminal.html` changes.
- Keyboard open/close must NOT call `fitAndResize` (no PTY resize). Refit happens only when `window.innerWidth`/`innerHeight` actually changed (orientation, desktop resize), on slot activation, and on font change (latter two unchanged).
- Key bar keys become exactly: `esc` `tab` `ctrl` `shift` `↑` `↓` `←` `→`.
- Touch scroll: content tracks the finger 1:1 via `.xterm-viewport.scrollTop`; momentum fling on release (start when |v| > 0.05 px/ms, decay ×0.94 per 16.7 ms, stop below 0.02 px/ms or on new touch or alternate screen). All existing guards stay: capture+stopPropagation ownership, one-finger only, zoomed → native pan, alternate screen → app owns gestures.
- Test cycle (from repo root), expected `SYNTAX-OK`:

```bash
python3 -c "
import re
html = open('static/terminal.html').read()
open('/tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/term.js','w').write(re.findall(r'<script>(.*?)</script>', html, re.S)[0])
" && node --check /tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/term.js && echo SYNTAX-OK
```

Match code by content, not line numbers (file at commit `d102884`).

---

### Task 1: Keyboard shift-up layout

**Files:**
- Modify: `static/terminal.html` (CSS `#bar` rule ~line 12; `layoutViewport()` ~line 686)

- [ ] **Step 1: Raise the top bar above shifted pane content**

In the `#bar` CSS rule, add two properties so it reads:

```css
    #bar {
      display: flex; align-items: center; gap: .5rem; flex-wrap: wrap;
      padding: .4rem .6rem; background: #14171d;
      font: .8rem system-ui, sans-serif; box-sizing: border-box;
      border-bottom: 1px solid #23272f;
      position: relative; z-index: 35;
    }
```

- [ ] **Step 2: Replace `layoutViewport()`**

Replace the whole block from `let layoutQueued = false;` through the closing `}` of `function layoutViewport() {...}` with:

```js
    let layoutQueued = false;
    let lastW = 0, lastH = 0;
    function layoutViewport() {
      layoutQueued = false;
      const vv = window.visualViewport;
      let occluded = 0;
      if (vv && vv.scale <= 1.01) {
        if (window.scrollY) window.scrollTo(0, 0);
        // Pinch-zoom also shrinks vv.height/offsetTop; don't mistake that
        // for keyboard occlusion.
        occluded = Math.max(0, window.innerHeight - vv.height - vv.offsetTop);
      }
      const kb = keyBar.hidden ? 0 : keyBar.offsetHeight;
      keyBar.style.bottom = occluded + "px";
      panesEl.style.top = barEl.offsetHeight + "px";
      panesEl.style.bottom = kb + "px";
      // Keyboard = pure visual shift: slide the panes up so the prompt line
      // stays visible above the key bar. No fit, no cols/rows change, no
      // PTY-resize round-trip on keyboard open/close — the top rows just
      // slide behind the top bar until the keyboard goes away.
      panesEl.style.transform = occluded ? "translateY(-" + occluded + "px)" : "";
      // Refit only when the layout viewport really changed (orientation,
      // desktop window resize). The soft keyboard never alters
      // innerWidth/Height on iOS or modern Android, so it can't refit.
      if (window.innerWidth !== lastW || window.innerHeight !== lastH) {
        lastW = window.innerWidth; lastH = window.innerHeight;
        const s = sessions[active];
        if (s) s.fitAndResize();
      }
    }
```

(Leave `scheduleLayout()` and the listener wiring below it untouched. Also update the banner comment above the block: it now shifts instead of resizing.)

- [ ] **Step 3: Syntax check** — expected `SYNTAX-OK`.

- [ ] **Step 4: Commit**

```bash
git add static/terminal.html
git commit -m "Keyboard open/close shifts panes visually instead of refitting the PTY"
```

---

### Task 2: Pixel-smooth touch scroll with momentum

**Files:**
- Modify: `static/terminal.html` (`Session` constructor touch block ~lines 316–343; new `fling()` method after `sendResize()`)

- [ ] **Step 1: Replace the touch block**

Replace the whole block from the `// Touch scrollback:` comment through the `touchend` listener line with:

```js
        // Touch scrollback: one-finger drag drives xterm's own scrollable
        // viewport by raw pixel deltas — content tracks the finger 1:1 —
        // with a momentum fling on release. xterm 5.5 registers its own
        // touch handlers on term.element (a child of this.pane); capturing
        // here + stopPropagation on move keeps the pane the single owner of
        // the gesture so xterm's handler can't double-scroll or fight
        // zoom-pan.
        this.viewport = this.pane.querySelector(".xterm-viewport");
        this.touchY = null;
        this.touchT = 0;
        this.touchV = 0;          // px/ms, low-passed drag velocity
        this.flinging = false;
        this.pane.addEventListener("touchstart", (e) => {
          this.flinging = false;  // any touch stops a fling
          this.touchV = 0;
          this.touchT = e.timeStamp;
          this.touchY = e.touches.length === 1 ? e.touches[0].clientY : null;
        }, { passive: true, capture: true });
        this.pane.addEventListener("touchmove", (e) => {
          if (this.touchY === null || e.touches.length !== 1) return;
          e.stopPropagation();
          const vv = window.visualViewport;
          if (vv && vv.scale > 1.01) return;   // zoomed: finger pans the page
          // vim/less own the alternate screen; leave gestures to them
          if (this.term.buffer.active.type === "alternate") return;
          if (!this.viewport) return;
          const y = e.touches[0].clientY;
          const dy = y - this.touchY;
          const dt = Math.max(1, e.timeStamp - this.touchT);
          this.touchY = y;
          this.touchT = e.timeStamp;
          this.viewport.scrollTop -= dy;
          this.touchV = 0.8 * (dy / dt) + 0.2 * this.touchV;
          e.preventDefault();
        }, { passive: false, capture: true });
        this.pane.addEventListener("touchend", () => {
          if (this.touchY !== null && Math.abs(this.touchV) > 0.05) this.fling();
          this.touchY = null;
        }, { passive: true, capture: true });
        this.pane.addEventListener("touchcancel", () => {
          this.touchY = null; this.touchV = 0;
        }, { passive: true, capture: true });
```

- [ ] **Step 2: Add the `fling()` method**

Insert after the `sendResize()` method (before `fitAndResize()`):

```js
      // Momentum fling: keep scrolling after release with exponential decay
      // until the velocity fades or a new touch interrupts.
      fling() {
        if (this.flinging || !this.viewport) return;
        this.flinging = true;
        let last = performance.now();
        const step = (now) => {
          if (!this.flinging) return;
          const dt = now - last;
          last = now;
          this.touchV *= Math.pow(0.94, dt / 16.7);
          if (Math.abs(this.touchV) < 0.02 ||
              this.term.buffer.active.type === "alternate") {
            this.flinging = false;
            return;
          }
          this.viewport.scrollTop -= this.touchV * dt;
          requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      }
```

- [ ] **Step 3: Syntax check** — expected `SYNTAX-OK`.

- [ ] **Step 4: Commit**

```bash
git add static/terminal.html
git commit -m "Pixel-smooth touch scrolling with momentum via xterm viewport scrollTop"
```

---

### Task 3: Trim key bar; harden hidden textarea against autofill

**Files:**
- Modify: `static/terminal.html` (KEYS array ~line 500; `Session` constructor right after `this.term.open(this.pane);`)

- [ ] **Step 1: Remove `|` and `-` from KEYS**

The array becomes exactly:

```js
    const KEYS = [
      ["esc", "\x1b"], ["tab", "\t"], ["ctrl", "MOD_CTRL"], ["shift", "MOD_SHIFT"],
      ["↑", "\x1b[A"], ["↓", "\x1b[B"], ["←", "\x1b[D"], ["→", "\x1b[C"],
    ];
```

- [ ] **Step 2: Harden the hidden textarea**

Insert immediately after `this.term.open(this.pane);`:

```js
        // Best-effort: keep mobile autofill (passwords/cards/addresses) and
        // text suggestions away from xterm's hidden textarea. The browser's
        // keyboard accessory UI is not fully page-controllable.
        const ta = this.pane.querySelector(".xterm-helper-textarea");
        if (ta) {
          ta.setAttribute("autocomplete", "off");
          ta.setAttribute("autocorrect", "off");
          ta.setAttribute("autocapitalize", "none");
          ta.setAttribute("spellcheck", "false");
          ta.setAttribute("name", "xt-" + this.index);
          ta.setAttribute("data-form-type", "other");
          ta.setAttribute("data-lpignore", "true");
        }
```

- [ ] **Step 3: Syntax check** — expected `SYNTAX-OK`.

- [ ] **Step 4: Commit**

```bash
git add static/terminal.html
git commit -m "Trim | and - bar keys; harden hidden textarea against mobile autofill"
```

---

### Task 4: Final review, build, deploy, on-device verification

- [ ] Final range review (base = commit before Task 1), fix wave if needed.
- [ ] `git push` && `./build-x86_64.sh`
- [ ] Deploy (restart already approved for this batch):

```bash
scp target/x86_64-unknown-linux-gnu/release/webshell wushilin@gate.wushilin.net:/opt/processmaster/dropin/webshell/webshell.new
ssh wushilin@gate.wushilin.net 'pkill -x webshell; sleep 3; ps aux | grep "[w]ebshell"; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9193/webshell/login'
```

- [ ] On-device (user): keyboard opens → view shifts instantly, no reflow flash, prompt above key bar; close → shifts back; rotate phone → proper refit. Scroll tracks finger 1:1 and flings with momentum. Bar shows 8 keys. Autofill icons gone (or reported as browser-UI-limitation if not).

## Self-review notes

- §8→Task 1, §9→Task 2, §10/§11→Task 3. All addendum-2 spec lines covered.
- `lastW/lastH` start 0 → the initial `scheduleLayout()` performs the first fit.
- `activate()`'s per-switch `fitAndResize()` and the font-prefs fit path are untouched (both call it directly, not via `layoutViewport`).
- Fling reads `this.viewport` captured at construction; pane/term live for the session's lifetime, so no stale reference.
