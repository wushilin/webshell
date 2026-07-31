# Mobile UX Addendum Implementation Plan (shift key, touch scrollback, zoom-pan fix)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sticky Shift key (with proper CSI modifier encoding for arrows/tab), one-finger touch scrolling of terminal scrollback, and stop the keyboard-pin from fighting pinch-zoom panning.

**Architecture:** All changes in `static/terminal.html` (the whole frontend, inline JS/CSS). Extends the existing key-bar block (sticky-Ctrl pattern), the `Session` constructor (touch handlers per pane), and `layoutViewport()`.

**Tech Stack:** Vanilla JS, xterm.js 5.5 public API (`term.scrollLines`, `term.buffer.active.type`), visualViewport.

**Spec:** `docs/superpowers/specs/2026-07-31-mobile-ux-design.md` §5–§7 (Addendum)

## Global Constraints

- Single file: only `static/terminal.html` changes.
- Key bar keys become, exactly: `esc` `tab` `ctrl` `shift` `↑` `↓` `←` `→` `|` `-`.
- Shift and Ctrl are both one-shot sticky. Modifier encoding: arrows `\x1b[1;{1+shift+4*ctrl}{A|B|D|C}`; shift+tab `\x1b[Z`. Keys without modified forms and typed characters consume armed modifiers and send unchanged.
- Touch scrolling: one finger only, normal buffer only (skip alternate screen), skip while pinch-zoomed (`visualViewport.scale > 1.01`), `preventDefault` on handled moves.
- Keyboard pin `scrollTo(0,0)` only runs when `vv.scale <= 1.01`.
- Test cycle: extract + `node --check` (command below), expected `SYNTAX-OK`:

```bash
python3 -c "
import re
html = open('static/terminal.html').read()
open('/tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/term.js','w').write(re.findall(r'<script>(.*?)</script>', html, re.S)[0])
" && node --check /tmp/claude-1001/-home-code-workspace-webshell/fc588ed8-b320-457e-b81a-0b8c14cc16b7/scratchpad/term.js && echo SYNTAX-OK
```

Match code by content, not line numbers (file is at commit `2b4feb8`).

---

### Task 1: Sticky Shift key + modifier encoding for bar keys

**Files:**
- Modify: `static/terminal.html` (key-bar JS block, ~line 452; `Session.input()`, ~line 326)

**Interfaces:**
- Produces: `shiftArmed`, `setShift(on)` globals (mirroring `ctrlArmed`/`setCtrl`).

- [ ] **Step 1: Add shift state next to ctrl state**

In the key-bar block, replace:

```js
    let ctrlArmed = false;
    let ctrlBtn = null;

    function setCtrl(on) {
      ctrlArmed = on;
      if (ctrlBtn) ctrlBtn.classList.toggle("armed", on);
    }
```

with:

```js
    let ctrlArmed = false, shiftArmed = false;
    let ctrlBtn = null, shiftBtn = null;

    function setCtrl(on) {
      ctrlArmed = on;
      if (ctrlBtn) ctrlBtn.classList.toggle("armed", on);
    }
    function setShift(on) {
      shiftArmed = on;
      if (shiftBtn) shiftBtn.classList.toggle("armed", on);
    }
```

- [ ] **Step 2: Rebuild the KEYS table and pointerdown handler**

Replace the whole block from `const KEYS = [` through the end of the `KEYS.forEach(...)` call with:

```js
    // CSI final bytes for arrows, used for modifier encoding.
    const ARROWS = { "\x1b[A": "A", "\x1b[B": "B", "\x1b[D": "D", "\x1b[C": "C" };
    const KEYS = [
      ["esc", "\x1b"], ["tab", "\t"], ["ctrl", "MOD_CTRL"], ["shift", "MOD_SHIFT"],
      ["↑", "\x1b[A"], ["↓", "\x1b[B"], ["←", "\x1b[D"], ["→", "\x1b[C"],
      ["|", "|"], ["-", "-"],
    ];
    KEYS.forEach(([label, seq]) => {
      const b = document.createElement("button");
      b.textContent = label;
      // pointerdown + preventDefault: never move focus, so the soft
      // keyboard stays up while tapping bar keys.
      b.addEventListener("pointerdown", (e) => {
        e.preventDefault();
        if (seq === "MOD_CTRL") { setCtrl(!ctrlArmed); return; }
        if (seq === "MOD_SHIFT") { setShift(!shiftArmed); return; }
        const s = sessions[active];
        if (!s) return;
        let out = seq;
        // Armed modifiers give arrows/tab their CSI-modified forms here; the
        // generic one-shot consumption in input() covers every other key.
        const mod = 1 + (shiftArmed ? 1 : 0) + (ctrlArmed ? 4 : 0);
        if (ARROWS[seq] && mod > 1) {
          out = "\x1b[1;" + mod + ARROWS[seq];
          setCtrl(false); setShift(false);
        } else if (seq === "\t" && shiftArmed) {
          out = "\x1b[Z";
          setCtrl(false); setShift(false);
        }
        s.input(out);
      });
      if (seq === "MOD_CTRL") ctrlBtn = b;
      if (seq === "MOD_SHIFT") shiftBtn = b;
      keyBar.appendChild(b);
    });
```

- [ ] **Step 3: Consume shift in `Session.input()`**

In the `Session` class, replace:

```js
        if (ctrlArmed) {
          if (d.length === 1) d = ctrlTransform(d);
          setCtrl(false); // one-shot; multi-char chunks (paste) pass unmodified
        }
```

with:

```js
        if (ctrlArmed || shiftArmed) {
          if (ctrlArmed && d.length === 1) d = ctrlTransform(d);
          // One-shot: any chunk consumes both modifiers. Typed characters
          // have no bar-shift form — the native keyboard's shift owns them.
          setCtrl(false); setShift(false);
        }
```

- [ ] **Step 4: Syntax check** — run the Global Constraints command. Expected: `SYNTAX-OK`.

- [ ] **Step 5: Commit**

```bash
git add static/terminal.html
git commit -m "Add sticky shift bar key with CSI modifier encoding for arrows and tab"
```

---

### Task 2: Touch scrollback + zoom-pan pin fix

**Files:**
- Modify: `static/terminal.html` (`Session` constructor, after the `this.term.onResize(...)` line ~292; `layoutViewport()`, ~line 638)

**Interfaces:**
- Consumes: `this.pane`, `this.term` (existing Session members).

- [ ] **Step 1: Add touch-scroll handlers in the Session constructor**

Insert immediately after the `this.term.onResize(() => this.sendResize());` line:

```js
        // Touch scrollback: one-finger vertical drag scrolls history. The
        // renderer layers sit above xterm's viewport, so native touch
        // scrolling never engages — translate drags into scrollLines().
        this.touchY = null;
        this.pane.addEventListener("touchstart", (e) => {
          this.touchY = e.touches.length === 1 ? e.touches[0].clientY : null;
        }, { passive: true });
        this.pane.addEventListener("touchmove", (e) => {
          if (this.touchY === null || e.touches.length !== 1) return;
          const vv = window.visualViewport;
          if (vv && vv.scale > 1.01) return;   // zoomed: finger pans the page
          // vim/less own the alternate screen; leave gestures to them
          if (this.term.buffer.active.type === "alternate") return;
          const lineH = this.pane.clientHeight / this.term.rows;
          const dy = e.touches[0].clientY - this.touchY;
          const lines = Math.trunc(dy / lineH);
          if (lines !== 0) {
            this.term.scrollLines(-lines);
            this.touchY += lines * lineH;
          }
          e.preventDefault();
        }, { passive: false });
        this.pane.addEventListener("touchend", () => { this.touchY = null; }, { passive: true });
```

- [ ] **Step 2: Gate the keyboard pin on zoom**

In `layoutViewport()`, replace:

```js
      if (vv) {
        if (window.scrollY) window.scrollTo(0, 0);
```

and its zoom-guarded occlusion block, with:

```js
      if (vv && vv.scale <= 1.01) {
        if (window.scrollY) window.scrollTo(0, 0);
```

so that BOTH the `scrollTo` pin and the occlusion computation live inside the single `vv.scale <= 1.01` condition (keep the existing occlusion line and comments; remove the now-redundant inner `if (vv.scale <= 1.01)` wrapper if present).

- [ ] **Step 3: Syntax check** — run the Global Constraints command. Expected: `SYNTAX-OK`.

- [ ] **Step 4: Commit**

```bash
git add static/terminal.html
git commit -m "Add one-finger touch scrollback; stop keyboard pin fighting pinch-zoom pan"
```

---

### Task 3: Build, deploy, on-device verification

- [ ] **Step 1: Push** — `git push`
- [ ] **Step 2: Build** — `./build-x86_64.sh` (expect the ELF + PT_INTERP verification lines)
- [ ] **Step 3: Deploy** (user already approved the restart for this batch):

```bash
scp target/x86_64-unknown-linux-gnu/release/webshell wushilin@gate.wushilin.net:/opt/processmaster/dropin/webshell/webshell.new
ssh wushilin@gate.wushilin.net 'pkill -x webshell; sleep 3; ps aux | grep "[w]ebshell"; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9193/webshell/login'
```

- [ ] **Step 4: On-device acceptance (user, iPhone Chrome)**

- `shift` then `tab` in Claude Code → mode cycles (the original ask).
- `ctrl` then `→` in a shell prompt → jumps a word (bash/readline with default bindings may need `ctrl`+`f`-style alternatives; zsh/fish handle `1;5C` natively).
- One-finger drag on terminal output → history scrolls; in `less`/`vim` the drag does nothing (use keys there).
- Pinch-zoom in, pan around with one finger → page pans normally; zoom back out → layout snaps back correctly when the keyboard opens.

## Self-review notes

- §5 → Task 1, §6+§7 → Task 2, deploy → Task 3. All spec addendum lines covered.
- `setShift` is declared in the key-bar block, after the `Session` class but before any session exists (`activate(0)` runs last) — same closure pattern the ctrl key already relies on.
- Modified sequences disarm modifiers *before* `s.input(out)`, so `input()`'s generic consumption doesn't double-fire; unmodified keys fall through to `input()` which now consumes both modifiers.
