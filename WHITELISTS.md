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

## The loader leaks into children of injected apps (but no tweak does)

Both gating layers decide where **tweak code** runs, and they do that job: no
tweak dylib is ever mapped into a process outside its own whitelist. But
`libopener.dylib` (the loader) and `fridagum.dylib` (its frida-gum runtime)
spread wider than the lists, by plain environment inheritance, and it is worth
understanding why — the gating is not broken, this is a layer below it.

How the env is actually set (verified live, strict mode):

- A GUI app the allowlist permits is launched by launchd through `xpcproxy`.
  `liblibinfect` runs in `xpcproxy`, and because `xpcproxy` sanitises its own
  environment before the exec, the app comes up with exactly
  `DYLD_INSERT_LIBRARIES=/private/var/ammonia/core/libopener.dylib` — **just
  the loader, not `liblibinfect`.** The app therefore has **no `posix_spawn`
  hook of its own** (that hook lives in `liblibinfect`, which is not present).
- When that app spawns a child itself — Electron helpers, a crashpad handler,
  or, for Terminal, every shell and every command you run — the child inherits
  the app's environment verbatim, including `DYLD_INSERT_LIBRARIES=…libopener`.
  Nothing rebuilds or strips it, because the gating hook is not in the app. So
  `libopener` + `fridagum` load into the child too. `libopener` then reads the
  per-tweak whitelists, finds the child's executable listed nowhere, and loads
  **no tweak** (`opener/opener.m:103`). Layer 2 does its job; the loader rode
  in regardless.

The contrast that proves the mechanism: a **launchd-spawned** child of the same
app (e.g. Mail's `maild` / `icloudmailagent` XPC agents) goes back through the
`xpcproxy` → `liblibinfect` path, where strict-mode gating applies and denies
them — those come up with **no ammonia images and no `DYLD` var at all**. Only
children spawned *directly by an injected GUI app* inherit the loader.

Consequences:

- **Tweak-injection correctness is unaffected** — the property "a tweak runs
  only in apps on its whitelist" holds.
- **Footprint / attack surface is wider than the lists** — frida-gum is mapped
  into app helper processes and into everything a listed app spawns. Terminal
  is the sharp edge: being allowlisted, it hands `libopener` + frida to every
  CLI process you launch from it.

If you want to close that gap, see the note under *Stripping the loader from
inherited environments* below before changing anything — a naive
`unsetenv("DYLD_INSERT_LIBRARIES")` can sever the injection chain.

### Stripping the loader from inherited environments

The fix cannot live in `liblibinfect`'s `build_spawn_env`: that hook is not
present in the injected GUI app, so it never runs for the app's own spawns. The
only process able to stop the inheritance is the one doing the leaking, so the
scrub belongs in **`libopener`'s constructor** — remove its own entry from
`environ` so children do not inherit it. This does not affect the current
process (dyld has already loaded `libopener` and its tweaks before the
constructor runs; `unsetenv` only changes what children inherit).

Two hazards to respect:

- **Remove only the `libopener.dylib` element, never the whole variable.** In
  the strict-mode GUI env observed, `DYLD_INSERT_LIBRARIES` holds *only*
  `libopener`, so a blanket `unsetenv` happens to be harmless there. But it is
  not safe in general: the append path in `build_spawn_env` can produce
  `liblibinfect:libopener`, and blanking the variable would drop
  `liblibinfect` too, **severing the infection-propagation chain** — GUI apps
  launched from that subtree would no longer be hooked or gated at all. Do
  colon-list surgery that preserves every other element (handle only / first /
  middle / last position, and avoid partial-string matches).
- **Do it in the earliest possible constructor,** before the ObjC runtime and
  frida spin up threads, so the `unsetenv` does not race a `getenv` on another
  thread.

What the correct (opener-only, in-constructor) strip changes:

- App helpers and everything a listed app spawns stop loading `libopener` +
  frida. None of them were getting a tweak, so nothing visible is lost; CLI
  commands launched from Terminal come up clean.
- Normal app launches are unaffected — they go through launchd/`xpcproxy`,
  which re-adds `libopener` for allowlisted targets independently of
  inheritance.

What to check before shipping it:

- **The loginwindow logout fix.** `loginwindow` carries `libopener`; if that
  fix depends on a *child* of `loginwindow` inheriting the loader rather than
  acting in `loginwindow` itself, the strip would break it. Verify against the
  tweak that implements it first.
- **Apps that re-exec themselves** (updaters, "relaunch" flows) would lose the
  loader on the re-exec and come up untweaked until launchd relaunches them.
  Minor and self-healing, but expect a one-launch gap.

An alternative to stripping is to inject `liblibinfect` into the GUI apps too,
so their spawns are gated like launchd's. That deliberately puts the frida
`posix_spawn` interceptor inside every GUI app — more invasive and more
stability risk than the loader-only design currently accepts, which is why the
constructor scrub is the lighter option.

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

2026-11-05 — **strict allowlist mode is now active.** `ammonia.allowlist` is
installed at `/private/var/ammonia/core/ammonia.allowlist` (`root:wheel`,
`0644`) and is byte-identical to the repo copy. It covers the union of all
three per-tweak whitelists exactly; the only entry not used by a tweak is
`loginwindow` (expected, for the logout fix). The source gating was
re-confirmed against this file: Layer 1 at `libinfect/libinfect.m:214`, Layer 2
at `opener/opener.m:59`-`107`, matching at `ammonia.h:31`.

Three tweaks installed (`ClassicTitlebar.dylib`, `firefox_titlebar.dylib`,
`liquid_glass_off.dylib`), each with a `.dylib.whitelist` and no
`.dylib.blacklist`; all three whitelist files are clean (no leading/trailing
whitespace, no `#` lines, no CRLF — i.e. no silent dead entries).

Live injection was read with `lsof`/`ps eww` and matched the whitelists exactly,
with **no tweak over-injection**: `ClassicTitlebar` and `liquid_glass_off` were
mapped into Finder, Files, Claude, Mail, Calendar, Slack, MacPass (app-
translocated path, basename-matched) and Terminal — the eight whitelisted apps
that were running. `firefox` was not running, so `firefox_titlebar` had no live
process. Whitelisted apps that were not running carried nothing. Mail's
launchd-spawned XPC agents (`maild`, `icloudmailagent`), which are not
allowlisted, carried no ammonia images and no `DYLD` var — the strict Layer-1
path gated them clean.

One behaviour was characterised in full and written up under *The loader leaks
into children of injected apps*: `libopener` + `fridagum` were mapped into 19
processes, but a tweak into only the 8 intended targets. The extra 11 are
children of injected GUI apps (Slack/Claude Electron helpers and their crashpad
handlers) that inherited `DYLD_INSERT_LIBRARIES=…libopener` from their parent
and loaded the loader but no tweak. This is footprint/surface, not a tweak
leak; the stripping options and their risks are documented in that section.

The `Notes` basename collision (Apple Notes and `~/Applications/Notes.app`
share the executable name) remains the one intentional double-match; neither
was running at this check.
