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
  // Open the file in append mode
  FILE *file = fopen("/tmp/infect.log", "a");

  if (file == NULL) {
    // Failed to open the file
    perror("Error opening file");
    return;
  }

  // Initialize variable arguments
  va_list args;
  va_start(args, format);

  // Use vfprintf to write to the file
  vfprintf(file, format, args);

  // Clean up variable arguments
  va_end(args);

  // Close the file
  fclose(file);
}

int (*SpawnOld)(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *ac,
                const posix_spawnattr_t *ab, char *const __argv[],
                char *const __envp[]);

bool PathDriver(const char *path) { return (strstr(path, "Driver") != NULL); }

int posix_spawnattr_get_darwin_role_np(const posix_spawnattr_t *__restrict attr,
                                       uint64_t *__restrict darwin_rolep);
#define PRIO_DARWIN_ROLE_UI_FOCAL 0x1     /* On  screen,     focal UI */
#define PRIO_DARWIN_ROLE_UI 0x2           /* On  screen UI,  focal unknown */
#define PRIO_DARWIN_ROLE_UI_NON_FOCAL 0x4 /* On  screen, non-focal UI */

/* --- ammonia.blacklist storage --- */
static char **ammonia_blacklist = NULL;
static size_t ammonia_blacklist_count = 0;

/* load ammonia.blacklist (substring-match style like opener.c) */
static void load_ammonia_blacklist(void) {
  char pathbuf[PATH_MAX];
  if (snprintf(pathbuf, sizeof(pathbuf), "%s%s", SupportFolderP,
               "ammonia.blacklist") >= (int)sizeof(pathbuf)) {
    LogToFile("ammonia: blacklist path overflow\n");
    return;
  }

  FILE *f = fopen(pathbuf, "r");
  if (!f) {
    // blacklist optional; silently continue
    return;
  }

  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  while ((read = getline(&line, &len, f)) != -1) {
    // strip newline(s)
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

    char **tmp = realloc(ammonia_blacklist,
                         (ammonia_blacklist_count + 1) * sizeof(char *));
    if (!tmp) {
      free(entry);
      continue;
    }
    ammonia_blacklist = tmp;
    ammonia_blacklist[ammonia_blacklist_count++] = entry;
  }

  free(line);
  fclose(f);
}

/* returns true if `path` should be considered blacklisted (substring matching)
 */
static bool is_path_blacklisted(const char *path) {
  if (!path || ammonia_blacklist_count == 0)
    return false;
  for (size_t i = 0; i < ammonia_blacklist_count; ++i) {
    const char *entry = ammonia_blacklist[i];
    if (!entry || entry[0] == '\0')
      continue;
    if (strstr(path, entry) != NULL) {
      return true;
    }
  }
  return false;
}

int SpawnNew(pid_t *pid, const char *path, const posix_spawn_file_actions_t *ac,
             const posix_spawnattr_t *ab, char *const __argv[],
             char *const __envp[]) {
  char **playground = envbuf_mutcopy((const char **)__envp);

  uint64_t darwin_rolep = 0;
  posix_spawnattr_get_darwin_role_np(ab, &darwin_rolep);

  if (strcmp(path, "/System/Library/CoreServices/loginwindow.app/Contents/"
                   "MacOS/loginwindow") == 0) {
    goto SkipGuiCheck;
  }
  if (strcmp(path, "/usr/libexec/xpcproxy") == 0) {
    envbuf_setenv(&playground, "DYLD_INSERT_LIBRARIES",
                  SupportFolderP "liblibinfect.dylib");
  } else if (!PathDriver(path)) {
    if (darwin_rolep == PRIO_DARWIN_ROLE_UI_FOCAL ||
        darwin_rolep == PRIO_DARWIN_ROLE_UI ||
        darwin_rolep == PRIO_DARWIN_ROLE_UI_NON_FOCAL) {

      if (!is_path_blacklisted(path)) {

      SkipGuiCheck:
        // inject the opener into this GUI path
        LogToFile("ammonia: injecting opener for path '%s'\n", path);
        // we are GUI

        char *newlib = SupportFolderP "libopener.dylib";

        int idx =
            envbuf_find((const char **)playground, "DYLD_INSERT_LIBRARIES");
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

      int k = SpawnOld(pid, path, ac, ab, __argv, (char *const *)playground);
      envbuf_free(playground);
      return k;
    }
  }

  int k = SpawnOld(pid, path, ac, ab, __argv, (char *const *)playground);
  envbuf_free(playground);
  return k;
}

int SpawnPNew(pid_t *restrict pid, const char *restrict path,
              const posix_spawn_file_actions_t *ac,
              const posix_spawnattr_t *restrict ab, char *const *restrict argv,
              char *const *restrict envp) {
  return SpawnNew(pid, path, ac, ab, argv, envp);
}

void __attribute__((constructor)) Infect(void) {
  load_ammonia_blacklist();

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
                            NULL, (gpointer *)(NULL));
  } else {
    LogToFile("ammonia: could not find posix_spawnp export; hook skipped\n");
  }

  gum_interceptor_end_transaction(interceptor);
}
