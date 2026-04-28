#!/usr/bin/env bash
#
# Stop the AutoConvJmsSub launchd service and remove installed files.
# Asks before deleting config.yaml so subscription credentials aren't lost
# accidentally.

set -euo pipefail

LABEL="com.zfano.autoconvjmssub"
INSTALL_DIR="$HOME/Library/Application Support/AutoConvJmsSub"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
LOG_DIR="$HOME/Library/Logs"
DOMAIN="gui/$(id -u)"
JOB_TARGET="${DOMAIN}/${LABEL}"

log() { printf '\033[1;34m▸\033[0m %s\n' "$*"; }
ok() { printf '\033[1;32m✓\033[0m %s\n' "$*"; }

# 1. unload launchd job
if launchctl print "$JOB_TARGET" >/dev/null 2>&1; then
    log "Stopping and unloading launchd job ($JOB_TARGET)"
    launchctl bootout "$JOB_TARGET" || true
    ok "Service stopped"
else
    log "No active launchd job for $LABEL — skipping unload"
fi

# 2. remove plist
if [[ -f "$PLIST_PATH" ]]; then
    rm -f "$PLIST_PATH"
    ok "Removed $PLIST_PATH"
fi

# 3. remove binary
if [[ -f "$INSTALL_DIR/autoconv" ]]; then
    rm -f "$INSTALL_DIR/autoconv"
    ok "Removed $INSTALL_DIR/autoconv"
fi

# 4. ask before removing config (it has credentials)
if [[ -f "$INSTALL_DIR/config.yaml" ]]; then
    printf 'Delete config.yaml (contains your subscription URL)? [y/N] '
    read -r answer
    if [[ "$answer" =~ ^[yY]$ ]]; then
        rm -f "$INSTALL_DIR/config.yaml"
        ok "Removed $INSTALL_DIR/config.yaml"
    else
        log "Kept $INSTALL_DIR/config.yaml"
    fi
fi

# 5. clean up empty install dir
if [[ -d "$INSTALL_DIR" ]] && [[ -z "$(ls -A "$INSTALL_DIR")" ]]; then
    rmdir "$INSTALL_DIR"
    ok "Removed empty $INSTALL_DIR"
fi

# 6. logs left untouched (user may want to inspect post-uninstall)
if [[ -f "$LOG_DIR/AutoConvJmsSub.log" || -f "$LOG_DIR/AutoConvJmsSub.err.log" ]]; then
    log "Logs left at $LOG_DIR/AutoConvJmsSub*.log — delete manually if desired"
fi

ok "Uninstall complete"
