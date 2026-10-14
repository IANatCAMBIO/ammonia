# Release Notes

## Unreleased — bug-fix pass (security/robustness review)

A code review of this fork (full-system-access dylib loader) surfaced no
malicious behaviour but several correctness, memory, and robustness bugs. All
nine are fixed in this change. Each entry lists the symptom, the root cause, and
the fix.

### Fixed

1. **Env-buffer leak on every spawn** — `libinfect/libinfect.m`
   `SpawnNew()` allocated a mutable environment copy (`envbuf_mutcopy`) on every
   intercepted `posix_spawn`/`posix_spawnp` but never freed it. Because the hook
   runs for *every* process spawn system-wide, this leaked one full environment
   copy per spawn for the life of the host process (notably launchd).
   *Fix:* `envbuf_free(playground)` before both `return` paths.

2. **Crash in every GUI process when frida-gum is missing** — `opener/opener.m`
   `ctor_main()` used the result of `dlopen("…/fridagum.dylib")` and two `dlsym`
   lookups without NULL checks, then called through them unconditionally. A
   missing or unreadable `fridagum.dylib` caused a NULL-deref crash in every
   process the opener was injected into.
   *Fix:* NULL-check the `dlopen` handle and both symbols; log via `syslog` and
   return early on failure.

3. **Injection timeout reported as success** — `ammonia/main.m`
   `result` was initialised to `0`; if the 10-iteration poll never observed the
   `0x79616265` completion sentinel, `main()` fell through and returned success
   even though injection had not completed.
   *Fix:* initialise `result = 1` so only an explicit sentinel match reports
   success.

4. **Dead `pid` guard with misleading diagnostic** — `ammonia/main.m`
   `pid` was hardcoded to `1` (launchd), making `if (!pid)` unreachable, and its
   error string referred to "Dock.app", which is not the target.
   *Fix:* removed the dead block; annotated `pid = 1` as launchd.

5. **`IsForegroundProcess()` dead and logically wrong** — `opener/opener.m`
   Never called, and its return expression (`!(role & A) || !(role & B) || …`)
   evaluated to true for virtually any role, so it could not report "background"
   correctly.
   *Fix:* removed the function.

6. **`GetExePath()` leak per tweak** — `opener/opener.m`
   Returned a `malloc`'d buffer that the caller (`Open()`) never freed; leaked
   once per tweak file scanned.
   *Fix:* `free(exe_path)` at the `cleanup:` label, covering all paths.

7. **Misleading log message in the inject branch** — `libinfect/libinfect.m`
   The log read "skipping opener for blacklisted path" inside the branch that
   actually *adds* the opener — the opposite of what the code does.
   *Fix:* message now reads "injecting opener for path".

8. **Unchecked allocations in env helpers** — `libinfect/envbuf.c`
   `envbuf_mutcopy` ignored `malloc`/`strdup` failures; `envbuf_setenv` ignored
   `malloc`/`realloc` failures, risking NULL-deref or a corrupted/leaked env
   buffer in the spawn hot path.
   *Fix:* check every allocation; on failure, roll back partial work and leave
   the original buffer intact.

9. **Unchecked export lookups in the interceptor** — `libinfect/libinfect.m`
   `Infect()` passed `gum_module_find_export_by_name(...)` straight into
   `gum_interceptor_replace` without checking for NULL targets.
   *Fix:* resolve both targets first, install each hook only when found, and log
   when an export is missing.

### Fixed (second pass — hardening)

10. **`posix_spawnp` routed through `posix_spawn`, breaking PATH search** —
    `libinfect/libinfect.m`
    `SpawnPNew()` called `SpawnNew()`, which invoked the saved original
    `posix_spawn`. `posix_spawn` requires a full path, so a `posix_spawnp` of a
    bare filename (e.g. `"ls"`) lost its `$PATH` resolution.
    *Fix:* capture a separate original pointer `SpawnPOld` when hooking
    `posix_spawnp`, factor the environment construction into a shared
    `build_spawn_env()`, and call `SpawnPOld` from the `posix_spawnp` path.

11. **Blacklist/whitelist matching was substring-based and mis-parsed lines** —
    `libinfect/libinfect.m`, `opener/opener.m`, `ammonia.h`
    `is_path_blacklisted()` (libinfect) and the tweak whitelist/blacklist loops
    (opener) used `strstr` substring matching, so `"Mail"` also matched
    `"MailChimp"` / any path containing the text. The opener loops also stripped
    only a trailing `\n` (not `\r`, so CRLF files broke) and did not skip empty
    lines — an empty line made `strstr` match *every* process, silently
    whitelisting or blacklisting everything.
    *Fix:* added a shared `ammonia_name_matches()` in `ammonia.h` that matches
    the whole executable name (full path or basename); opener now trims CR/LF
    via `chomp_line()` and skips empty lines.
    *Behaviour change:* match-list entries are now whole names, not fragments —
    path-fragment entries that relied on substring matching must be updated to a
    full path or the executable's basename.

12. **Log file in world-writable `/tmp` (symlink-attack target)** —
    `libinfect/libinfect.m`
    `LogToFile()` wrote to `/tmp/infect.log` from a root context; any local user
    could pre-create that path as a symlink and redirect a privileged write.
    *Fix:* log to `SupportFolderP "infect.log"` (root-owned support folder) and
    open with `O_NOFOLLOW` so a symlinked final component is refused.

13. **World-writable load directories** — `package.sh`
    The installer created `tweaks/` and `gui/` as `chmod 777`, letting any local
    user drop a dylib that gets loaded into other processes (local privilege
    escalation).
    *Fix:* `package.sh` now creates both as `0755` (root-writable only).
    **Operators with an existing install must also tighten the live dirs:**
    `sudo chmod 755 /private/var/ammonia/core/tweaks /private/var/ammonia/core/gui`

### Security posture notes (unchanged — by design, flagged for operators)

These are inherent to how Ammonia operates and were **not** modified, but
operators should be aware:

- The installer (`package.sh`) disables **Library Validation system-wide** and
  enables the arm64e preview ABI. Combined with SIP-off, this removes the main
  barriers to loading unsigned code into signed Apple processes.
- The LaunchDaemon runs as **root** and injects into **launchd (pid 1)** — the
  maximum blast radius if a tweak misbehaves.
