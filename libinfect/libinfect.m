//
//  libinfect.c
//  libinfect
//
//  Created by bedtime on 11/19/23.
//

#include "ammonia.h"
#include "envbuf.h"
#include "frida-gum.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <ctype.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

void LogToFile(const char *format, ...) {
  // Log into the root-owned support folder, not world-writable /tmp.
  // O_NOFOLLOW refuses to open the final component if it is a symlink,
  // defeating symlink-swap attacks against a privileged writer.
  int fd = open(SupportFolderP "infect.log",
                O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
  if (fd < 0) {
    return;
  }

  FILE *file = fdopen(fd, "a");
  if (file == NULL) {
    close(fd);
    return;
  }

  // Initialize variable arguments
  va_list args;
  va_start(args, format);

  // Use vfprintf to write to the file
  vfprintf(file, format, args);

  // Clean up variable arguments
  va_end(args);

  // Close the file (also closes fd)
  fclose(file);
}

int (*SpawnOld)(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *ac,
                const posix_spawnattr_t *ab, char *const __argv[],
                char *const __envp[]);

int (*SpawnPOld)(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *ac,
                 const posix_spawnattr_t *ab, char *const __argv[],
                 char *const __envp[]);

bool PathDriver(const char *path) { return (strstr(path, "Driver") != NULL); }

int posix_spawnattr_get_darwin_role_np(const posix_spawnattr_t *__restrict attr,
                                       uint64_t *__restrict darwin_rolep);
#define PRIO_DARWIN_ROLE_UI_FOCAL 0x1     /* On  screen,     focal UI */
#define PRIO_DARWIN_ROLE_UI 0x2           /* On  screen UI,  focal unknown */
#define PRIO_DARWIN_ROLE_UI_NON_FOCAL 0x4 /* On  screen, non-focal UI */

/* --- match-list storage (ammonia.blacklist / ammonia.allowlist) --- */
static char **ammonia_blacklist = NULL;
static size_t ammonia_blacklist_count = 0;
static char **ammonia_allowlist = NULL;
static size_t ammonia_allowlist_count = 0;
static bool ammonia_allowlist_active = false;

/*
 * load_name_list — read a newline-delimited name list from the support folder.
 *
 * Lines are trimmed of surrounding whitespace and CR/LF; blank lines and lines
 * beginning with '#' are ignored. Each remaining line is stored verbatim for
 * whole-name matching by ammonia_name_matches().
 *
 * Inputs:
 *   filename  — leaf name under SupportFolderP (e.g. "ammonia.blacklist")
 *   out_list  — receives the malloc'd array of entries (caller retains it)
 *   out_count — receives the number of entries
 *
 * Output:
 *   true if the file existed and was opened (even with no usable entries),
 *   false if it was absent or its path overflowed. On an allocation failure the
 *   partial list built so far is kept.
 */
static bool load_name_list(const char *filename, char ***out_list,
                           size_t *out_count) {
  char pathbuf[PATH_MAX];
  if (snprintf(pathbuf, sizeof(pathbuf), "%s%s", SupportFolderP, filename) >=
      (int)sizeof(pathbuf)) {
    LogToFile("ammonia: %s path overflow\n", filename);
    return false;
  }

  FILE *f = fopen(pathbuf, "r");
  if (!f) {
    // list optional; silently continue
    return false;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  while ((read = getline(&line, &len, f)) != -1) {
    // strip trailing newline(s)
    while (read > 0 && (line[read - 1] == '\n' || line[read - 1] == '\r')) {
      line[--read] = '\0';
    }

    // skip leading whitespace
    char *start = line;
    while (*start && isspace((unsigned char)*start))
      start++;

    // skip comments and empty lines
    if (*start == '#' || *start == '\0')
      continue;

    // trim trailing whitespace
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end))
      *end-- = '\0';

    // duplicate and store
    char *entry = strdup(start);
    if (!entry)
      continue;

    char **tmp = realloc(*out_list, (*out_count + 1) * sizeof(char *));
    if (!tmp) {
      free(entry);
      continue;
    }
    *out_list = tmp;
    (*out_list)[(*out_count)++] = entry;
  }

  free(line);
  fclose(f);
  return true;
}

/*
 * list_contains_path — whole-name membership test against a loaded name list.
 *
 * Inputs:
 *   list  — array of trimmed entries (may be NULL)
 *   count — number of entries
 *   path  — executable path being tested (may be NULL)
 *
 * Output:
 *   true if any entry matches `path` via ammonia_name_matches(); else false.
 */
static bool list_contains_path(char **list, size_t count, const char *path) {
  if (!path || count == 0)
    return false;
  for (size_t i = 0; i < count; ++i) {
    if (ammonia_name_matches(path, list[i])) {
      return true;
    }
  }
  return false;
}

/*
 * build_spawn_env — produce the environment to hand the original spawn call.
 *
 * Decides, from the target path and its darwin role, whether to inject the
 * opener (GUI apps, loginwindow) or liblibinfect (xpcproxy), and appends the
 * appropriate DYLD_INSERT_LIBRARIES entry to a mutable copy of the caller's
 * environment. Shared by both the posix_spawn and posix_spawnp hooks.
 *
 * Inputs:
 *   path  — executable path/file being spawned (must not be NULL)
 *   ab    — spawn attributes, used to read the darwin role (may be NULL)
 *   __envp — caller's environment (may be NULL)
 *
 * Output:
 *   newly-allocated mutable environment (free with envbuf_free), or NULL if the
 *   caller's environment was NULL and nothing was injected.
 */
static char **build_spawn_env(const char *path, const posix_spawnattr_t *ab,
                              char *const __envp[]) {
  char **playground = envbuf_mutcopy((const char **)__envp);

  uint64_t darwin_rolep = 0;
  posix_spawnattr_get_darwin_role_np(ab, &darwin_rolep);

  bool inject_opener = false;

  if (strcmp(path, "/System/Library/CoreServices/loginwindow.app/Contents/"
                   "MacOS/loginwindow") == 0) {
    // loginwindow drives the logout fix; in allowlist mode it must be listed
    // explicitly like any other target.
    inject_opener =
        ammonia_allowlist_active
            ? list_contains_path(ammonia_allowlist, ammonia_allowlist_count,
                                  path)
            : true;
  } else if (strcmp(path, "/usr/libexec/xpcproxy") == 0) {
    envbuf_setenv(&playground, "DYLD_INSERT_LIBRARIES",
                  SupportFolderP "liblibinfect.dylib");
    return playground;
  } else if (!PathDriver(path)) {
    if (ammonia_allowlist_active) {
      // Default-deny: inject only into explicitly allowlisted executables,
      // regardless of darwin role.
      inject_opener =
          list_contains_path(ammonia_allowlist, ammonia_allowlist_count, path);
    } else if (darwin_rolep == PRIO_DARWIN_ROLE_UI_FOCAL ||
               darwin_rolep == PRIO_DARWIN_ROLE_UI ||
               darwin_rolep == PRIO_DARWIN_ROLE_UI_NON_FOCAL) {
      // Legacy mode: inject into GUI-role apps unless blacklisted.
      if (!list_contains_path(ammonia_blacklist, ammonia_blacklist_count,
                              path)) {
        inject_opener = true;
      }
    }
  }

  if (inject_opener) {
    // we are GUI
    LogToFile("ammonia: injecting opener for path '%s'\n", path);

    char *newlib = SupportFolderP "libopener.dylib";

    int idx = envbuf_find((const char **)playground, "DYLD_INSERT_LIBRARIES");
    if (idx >= 0) {
      const char *old = playground[idx] + strlen("DYLD_INSERT_LIBRARIES=");
      char *combined = NULL;
      if (asprintf(&combined, "%s:%s", old, newlib) != -1) {
        envbuf_setenv(&playground, "DYLD_INSERT_LIBRARIES", combined);
        free(combined);
      }
    } else {
      envbuf_setenv(&playground, "DYLD_INSERT_LIBRARIES", newlib);
    }
  }

  return playground;
}

int SpawnNew(pid_t *pid, const char *path, const posix_spawn_file_actions_t *ac,
             const posix_spawnattr_t *ab, char *const __argv[],
             char *const __envp[]) {
  char **playground = build_spawn_env(path, ab, __envp);
  int k = SpawnOld(pid, path, ac, ab, __argv, (char *const *)playground);
  envbuf_free(playground);
  return k;
}

int SpawnPNew(pid_t *restrict pid, const char *restrict path,
              const posix_spawn_file_actions_t *ac,
              const posix_spawnattr_t *restrict ab, char *const *restrict argv,
              char *const *restrict envp) {
  // Call the original posix_spawnp (not posix_spawn) so its PATH search for a
  // bare filename is preserved.
  char **playground = build_spawn_env(path, ab, (char *const *)envp);
  int k = SpawnPOld(pid, path, ac, ab, argv, (char *const *)playground);
  envbuf_free(playground);
  return k;
}

void __attribute__((constructor)) Infect(void) {
  load_name_list("ammonia.blacklist", &ammonia_blacklist,
                 &ammonia_blacklist_count);
  ammonia_allowlist_active = load_name_list(
      "ammonia.allowlist", &ammonia_allowlist, &ammonia_allowlist_count);

  gum_init_embedded();
  GumInterceptor *interceptor = gum_interceptor_obtain();
  gum_interceptor_begin_transaction(interceptor);

  gpointer spawn_target =
      (gpointer)gum_module_find_export_by_name(NULL, "posix_spawn");
  gpointer spawnp_target =
      (gpointer)gum_module_find_export_by_name(NULL, "posix_spawnp");

  if (spawn_target) {
    gum_interceptor_replace(interceptor, spawn_target, (gpointer)SpawnNew, NULL,
                            (gpointer *)&SpawnOld);
  } else {
    LogToFile("ammonia: could not find posix_spawn export; hook skipped\n");
  }

  if (spawnp_target) {
    gum_interceptor_replace(interceptor, spawnp_target, (gpointer)SpawnPNew,
                            NULL, (gpointer *)&SpawnPOld);
  } else {
    LogToFile("ammonia: could not find posix_spawnp export; hook skipped\n");
  }

  gum_interceptor_end_transaction(interceptor);
}
