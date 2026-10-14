//
//  rosetta.h
//  ammonia
//
//  Created by bedtime on 11/19/23.
//

#ifndef rosetta_h
#define rosetta_h

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SupportFolderP "/private/var/ammonia/core/"

/*
 * ammonia_name_matches — decide whether a match-list entry names an executable.
 *
 * Matches on the whole executable name rather than a substring, so an entry
 * "Mail" matches /Applications/Mail.app/Contents/MacOS/Mail but not "MailChimp".
 *
 * Inputs:
 *   path — full executable path being tested (may be NULL)
 *   name — match-list entry, already whitespace-trimmed (may be NULL/empty)
 *
 * Output:
 *   true if `name` equals `path` or equals its last path component; else false.
 */
static inline bool ammonia_name_matches(const char *path, const char *name) {
    if (!path || !name || name[0] == '\0')
        return false;
    if (strcmp(path, name) == 0)
        return true;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strcmp(base, name) == 0;
}

#endif /* rosetta_h */
