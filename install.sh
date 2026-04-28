#!/usr/bin/env bash
#
# Install (or upgrade) AutoConvJmsSub as a macOS launchd background service.
#
# What it does, in order:
#   1. Builds the autoconv binary from the current source tree.
#   2. Copies the binary into ~/Library/Application Support/AutoConvJmsSub/.
#   3. Copies config.yaml on first run only — never overwrites an existing one.
#   4. Writes a LaunchAgent plist into ~/Library/LaunchAgents/.
#   5. (Re)loads the launchd job. Service runs at login and auto-restarts on
#      crash. Logs go to ~/Library/Logs/AutoConvJmsSub.{log,err.log}.
#
# Safe to run repeatedly — it doubles as the upgrade procedure: after editing
# code, just `./install.sh` again and the running service is restarted with
# the new binary while config.yaml stays untouched.
#
# Requires Go 1.21+ on PATH.

set -euo pipefail

LABEL="com.zfano.autoconvjmssub"
INSTALL_DIR="$HOME/Library/Application Support/AutoConvJmsSub"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
LOG_DIR="$HOME/Library/Logs"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '\033[1;34m▸\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*"; }
ok() { printf '\033[1;32m✓\033[0m %s\n' "$*"; }

if [[ "$(uname)" != "Darwin" ]]; then
    warn "This installer is macOS-only (uses launchd). Detected: $(uname)"
    exit 1
fi

if ! command -v go >/dev/null 2>&1; then
    warn "Go toolchain not found on PATH. Install via: brew install go"
    exit 1
fi

# ---- 1. build -------------------------------------------------------------
log "Building autoconv from $SOURCE_DIR"
cd "$SOURCE_DIR"
go build -ldflags "-s -w" -o autoconv .
ok "Built $(ls -lh autoconv | awk '{print $5}') binary"

# ---- 2. deploy directory --------------------------------------------------
mkdir -p "$INSTALL_DIR" "$LOG_DIR"

log "Installing binary → $INSTALL_DIR/autoconv"
cp autoconv "$INSTALL_DIR/autoconv"
chmod 755 "$INSTALL_DIR/autoconv"

# ---- 3. config (preserve existing) ---------------------------------------
if [[ -f "$INSTALL_DIR/config.yaml" ]]; then
    ok "Existing config.yaml preserved at $INSTALL_DIR/config.yaml"
else
    if [[ -f "$SOURCE_DIR/config.yaml" ]]; then
        log "Seeding config.yaml from source tree (first install)"
        cp "$SOURCE_DIR/config.yaml" "$INSTALL_DIR/config.yaml"
    else
        log "No source config.yaml — autoconv will write a template on first run"
    fi
    chmod 600 "$INSTALL_DIR/config.yaml" 2>/dev/null || true
    ok "Config installed at $INSTALL_DIR/config.yaml — edit it to set your subscription URL"
fi

# ---- 4. LaunchAgent plist -------------------------------------------------
log "Writing LaunchAgent plist → $PLIST_PATH"
cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/autoconv</string>
        <string>-config</string>
        <string>${INSTALL_DIR}/config.yaml</string>
    </array>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>ProcessType</key>
    <string>Background</string>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/AutoConvJmsSub.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/AutoConvJmsSub.err.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
EOF

# ---- 5. (re)load launchd job ---------------------------------------------
DOMAIN="gui/$(id -u)"
JOB_TARGET="${DOMAIN}/${LABEL}"

if launchctl print "$JOB_TARGET" >/dev/null 2>&1; then
    log "Service already loaded — restarting with new binary/plist"
    launchctl bootout "$JOB_TARGET" 2>/dev/null || true
    # bootout is async; wait for the service to fully unload before
    # bootstrapping the new plist, otherwise we get
    # "Bootstrap failed: 5: Input/output error".
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        launchctl print "$JOB_TARGET" >/dev/null 2>&1 || break
        sleep 0.3
    done
fi

log "Loading service into launchd ($DOMAIN)"
launchctl bootstrap "$DOMAIN" "$PLIST_PATH"

# Give launchd a moment to spin up the process before probing.
sleep 1

if curl -fsS http://127.0.0.1:25500/health >/dev/null 2>&1; then
    ok "Service is healthy on http://127.0.0.1:25500"
else
    warn "Service started but /health did not respond — check log:"
    warn "  tail -f ${LOG_DIR}/AutoConvJmsSub.log"
    warn "  tail -f ${LOG_DIR}/AutoConvJmsSub.err.log"
fi

cat <<EOF

──────────────────────────────────────────────────────────────────────
 AutoConvJmsSub is installed and running.

 Endpoint for clash-verge-rev / Clash Meta:
     http://127.0.0.1:25500/sub

 Edit subscription URL or settings:
     ${INSTALL_DIR}/config.yaml
     (then: launchctl kickstart -k ${JOB_TARGET})

 Tail logs:
     tail -f ${LOG_DIR}/AutoConvJmsSub.log

 Uninstall:
     ${SOURCE_DIR}/uninstall.sh
──────────────────────────────────────────────────────────────────────
EOF
