#!/bin/sh
#
# install.sh — in-place upgrade of an existing Ammonia installation.
#
# Copies the locally-built binaries from ./Build into the installed core
# directory, backing up the current install first. fridagum.dylib and any
# ammonia.blacklist / tweaks are left untouched. A reboot is required for
# launchd (pid 1) to load the new liblibinfect.dylib.
#
# Usage:
#   sh compile.sh          # produce ./Build (needs cmake), or build manually
#   sudo sh install.sh     # run this as root
#
set -eu

CORE=/private/var/ammonia/core
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$REPO_DIR/Build"
FILES="ammonia liblibinfect.dylib libopener.dylib"
CONFIGS="ammonia.allowlist ammonia.blacklist"

# Must run as root — the core directory is root-owned 0755.
if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root — sudo sh install.sh" >&2
    exit 1
fi

# Only upgrade an existing install; a fresh install goes through the .pkg.
if [ ! -d "$CORE" ]; then
    echo "error: $CORE not found — this upgrades an existing install." >&2
    echo "       for a fresh install build and run the .pkg (package.sh)." >&2
    exit 1
fi

# The built artifacts must exist.
for f in $FILES; do
    if [ ! -f "$SRC_DIR/$f" ]; then
        echo "error: missing $SRC_DIR/$f — build first (sh compile.sh)." >&2
        exit 1
    fi
done

# 1. Timestamped backup of the whole core directory.
BACKUP="$CORE.bak.$(date +%Y%m%d-%H%M%S)"
echo "backing up $CORE -> $BACKUP"
cp -a "$CORE" "$BACKUP"

# 2. Install the new binaries (fridagum.dylib and ammonia.blacklist untouched).
for f in $FILES; do
    echo "installing $f"
    cp "$SRC_DIR/$f" "$CORE/$f"
    chown root:wheel "$CORE/$f"
    chmod 755 "$CORE/$f"
done

# 3. Seed match-list config only if absent — never clobber a live copy.
for cfg in $CONFIGS; do
    if [ -f "$REPO_DIR/$cfg" ] && [ ! -f "$CORE/$cfg" ]; then
        echo "seeding $cfg (none installed yet)"
        cp "$REPO_DIR/$cfg" "$CORE/$cfg"
        chown root:wheel "$CORE/$cfg"
        chmod 644 "$CORE/$cfg"
    fi
done

echo
echo "upgrade staged. backup at: $BACKUP"
echo "a reboot is required for launchd to load the new liblibinfect.dylib."
echo
echo "recovery (from safe mode / Recovery if the desktop misbehaves):"
echo "  sudo rm -rf $CORE && sudo mv $BACKUP $CORE && sudo shutdown -r now"
echo

printf "reboot now? [y/N] "
read ans
case "$ans" in
    y | Y) shutdown -r now ;;
    *) echo "skipping reboot — run 'sudo shutdown -r now' when ready." ;;
esac
