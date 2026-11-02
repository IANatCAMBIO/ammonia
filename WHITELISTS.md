# Ammonia injection gating: allowlists, blacklists, and per-tweak whitelists

This explains exactly where ammonia is allowed to inject code, how the
match-list files are parsed, and how to spot-check a live system to prove a
tweak is only running where it should be. It is written against the source in
this repo so the behaviour is checkable, not assumed.

## The two gating layers

Injection is gated in **two independent stages**. A tweak runs in a process
only if it passes *both*.

### Layer 1 — does `libopener` get injected at all? (global, per-process)

`liblibinfect.dylib` loads into every spawned process via the launchd/xpcproxy
hook, but it only pulls in `libopener.dylib` (the component that actually loads
tweaks) for processes that qualify. Two modes, decided by one file:

- **Strict allowlist mode** — active when
  `/private/var/ammonia/core/ammonia.allowlist` **exists**. `libopener` is
  injected **only** into executables named in that file. Everything else —
  GUI apps and daemons alike — runs untouched.
- **Default role-based mode** — active when that file is **absent**.
  `libopener` is injected into all GUI-role apps
  (`PRIO_DARWIN_ROLE_UI*`), minus anything listed in
  `ammonia.blacklist`.

The repo ships an `ammonia.allowlist` (strict list), but **installing it is a
separate step** — it only takes effect once it is copied to
`/private/var/ammonia/core/ammonia.allowlist`. If that path does not exist, you
are in role-based mode and Layer 1 is wide open to all GUI apps; the per-tweak
whitelists (Layer 2) are then the only thing deciding where tweak *code* runs.

### Layer 2 — should this specific tweak load into this process? (per-tweak)

For each file in `/private/var/ammonia/core/tweaks/`, `libopener` looks for a
sidecar match-list next to the dylib and consults it before `dlopen`
(`opener/opener.m:59`-`107`):

| Sidecar file                     | Meaning                                                        |
|----------------------------------|----------------------------------------------------------------|
| `<tweak>.dylib.whitelist`        | **Default-deny.** Load **only** into listed executables.       |
| `<tweak>.dylib.blacklist`        | Used **only if no whitelist exists.** Load everywhere *except* listed executables. |
| neither present                  | **Tweak is skipped entirely** (`opener/opener.m:103`).         |

Whitelist wins: if a `.whitelist` exists, the `.blacklist` is never read for
that tweak.

## The matching rule (both layers)

Both layers compare an entry to a process using the same function,
`ammonia_name_matches()` in `ammonia.h:31`:

- An entry matches if it equals the **full executable path**, *or* equals the
  path's **last component (basename)**.
- Comparison is **exact and case-sensitive** (`strcmp`). `Mail` matches
  `/Applications/Mail.app/Contents/MacOS/Mail` but not `MailChimp` and not
  `mail`.
- Matching is on the **executable name**, not the `.app` bundle name. If two
  different apps ship an executable with the same basename, one entry matches
  **both**. Example in this install: `Notes` matches both Apple's Notes and the
  user's own `Notes.app` because they share the executable name `Notes`.
- An **app-translocated** app has no stable path: Gatekeeper runs it from a
  per-launch `/private/var/folders/.../AppTranslocation/<uuid>/d/<App>.app`
  directory, so only a basename entry can ever match it. `MacPass` is the
  example in this install. Never give a translocated app a full-path entry.

## Parser quirks — the two layers do NOT parse identically

This asymmetry has bitten before; treat the per-tweak parser as the stricter,
dumber one.

**Global list** (`ammonia.allowlist` / `ammonia.blacklist`, parsed by
`load_name_list` in `libinfect/libinfect.m`):

- Leading and trailing whitespace is trimmed.
- Blank lines are skipped.
- Lines beginning with `#` are skipped — **comments work, own line only**
  (`libinfect/libinfect.m:125`).

**Per-tweak list** (`<tweak>.dylib.whitelist` / `.blacklist`, parsed inline in
`opener/opener.m` using `chomp_line`):

- Only trailing `CR`/`LF` is stripped. **Leading/trailing spaces are NOT
  trimmed** — `"  Finder"` is a dead entry that matches nothing.
- Empty lines are skipped (`opener/opener.m:65`).
- **`#` lines are NOT treated as comments.** A line like `# Apple apps` becomes
  a literal entry `"# Apple apps"` that simply never matches. Harmless, but do
  **not** rely on it to document the file, and never put an inline `#` after a
  real entry — it becomes part of the name.

So: comments and indentation are fine in the global allowlist, and should be
avoided in per-tweak whitelists. Keep per-tweak whitelist files to one bare
executable name per line.

## How to spot-check a live system

Goal: prove each tweak is loaded **only** into whitelisted processes, and that
non-whitelisted apps carry nothing.

1. **List installed tweaks and their whitelists:**

   ```sh
   ls -la /private/var/ammonia/core/tweaks/
   for w in /private/var/ammonia/core/tweaks/*.whitelist; do
       echo "=== $w ==="; cat "$w"
   done
   ```

   Also confirm which Layer-1 mode you are in:

   ```sh
   ls -l /private/var/ammonia/core/ammonia.allowlist 2>/dev/null \
       && echo "strict allowlist mode" || echo "role-based mode (all GUI apps)"
   ```

2. **Confirm actual injection** with `vmmap` (works without sudo for processes
   running as you; use `sudo` for others). This reads the real mapped images —
   it does not infer from the whitelist:

   ```sh
   # Positive: a whitelisted app should show the expected tweak(s)
   vmmap <pid> | grep ammonia/core/tweaks

   # Negative control: a running GUI app NOT on any whitelist must show none
   vmmap <pid-of-non-whitelisted-app> | grep ammonia/core/tweaks   # expect no output
   ```

   The strong test is **differential**: pick a process that one whitelist
   includes and another excludes (e.g. an app in `liquid_glass_off` but not in
   `ClassicTitlebar`) and confirm `vmmap` shows exactly the expected subset.

3. **Map a running process name to its executable path** (what the whitelist
   actually matches against):

   ```sh
   ps -axo pid=,comm= | grep -i <appname>
   ```

## What a clean result looks like

- Every tweak dylib mapped into a process corresponds to an entry in that
  tweak's `.whitelist` (matched by basename or full path).
- Apps a whitelist omits do **not** have that tweak mapped, even though
  `libopener` itself is present (in role-based mode) — Layer 2 did its job.
- The only "surprise" matches are intentional basename collisions (e.g.
  `Notes`), which should be called out in a comment in the *global* allowlist
  (where comments are honoured), not the per-tweak file.

## Temporarily disabling a tweak

A tweak with **neither** sidecar is skipped entirely (`opener/opener.m:103`),
so renaming its match-list out of the way disables it without touching the
dylib or the daemon:

```sh
cd /private/var/ammonia/core/tweaks
sudo mv ClassicTitlebar.dylib.whitelist ClassicTitlebar.dylib.whitelist.off
```

Relaunch an app and it comes up clean; rename the sidecar back and relaunch to
restore. Sidecars are read per process launch, so this takes effect on the next
launch with no daemon restart, and `ammonia` is a one-shot `RunAtLoad` job
anyway (`KeepAlive` is false) — there is no resident process to signal.

Two things to keep in mind:

- Processes **already running** keep whatever was injected at their launch.
  Only new launches see the change, in either direction.
- Every app launched while the sidecar is off also comes up untweaked, and
  needs its own relaunch after the sidecar goes back.

Renaming to `.off` is deliberate: any suffix works as long as the result is
neither `.whitelist` nor `.blacklist`, but a tweak left with no sidecar at all
is indistinguishable from one that was never configured.

## Last verified

2026-11-02 — three tweaks installed (`ClassicTitlebar.dylib`,
`firefox_titlebar.dylib`, `liquid_glass_off.dylib`), each with a
`.dylib.whitelist` and no `.dylib.blacklist`; role-based Layer-1 mode, as no
`ammonia.allowlist` is installed in `core/`. Live injection was read with
`lsof` on each tweak dylib and matched the per-tweak whitelists exactly, with
no over-injection: `ClassicTitlebar` and `liquid_glass_off` in Calendar,
Claude, Files (x2), MacPass, Mail, Notes (x2), Slack, Tasks and Terminal;
`firefox_titlebar` in firefox alone. Whitelisted apps that were not running
(Messages, Reminders, Activity Monitor, Connections, Finder) carried nothing,
as expected.

The two `Notes` processes are the documented basename collision — Apple's
Notes and `~/Applications/Notes.app` share the executable name — and both are
intended targets here.

The sidecar-rename disable path above was exercised end to end on the same
date: all three sidecars renamed to `.off`, Apple Notes relaunched clean, then
renamed back and relaunched to confirm both tweaks loaded into the new process.

`ammonia.allowlist` in this repo was reconciled with the installed whitelists
on the same date. It had drifted: `Activity Monitor`, `Claude`, `Connections`,
`MacPass`, `Reminders`, `Slack` and `Tasks` were all missing, so enabling
strict mode would have silently denied injection into seven apps that both
window-chrome tweaks target. `MacVim` was dropped — it was there for the
`apple_sharpener` tweak, which is no longer installed. Since the allowlist is
not installed in `core/`, none of this was active, but the file is the thing
you copy into place to turn strict mode on, so it has to be right before that
is a safe thing to do.
