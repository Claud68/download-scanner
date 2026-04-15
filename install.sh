#!/usr/bin/env bash
# One-shot installer for the download scanner.
# Run: curl -sSL https://raw.githubusercontent.com/Claud68/download-scanner/main/install.sh | bash
# Or:  bash install.sh    (when run from a clone)

set -e

BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; DIM=$'\033[2m'; RESET=$'\033[0m'
say()  { printf "%s\n" "$*"; }
step() { printf "\n${BOLD}▶ %s${RESET}\n" "$*"; }
ok()   { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}!${RESET} %s\n" "$*"; }
die()  { printf "${RED}✗ %s${RESET}\n" "$*" >&2; exit 1; }

[[ "$(uname)" == "Darwin" ]] || die "This installer only supports macOS."

INSTALL_DIR="$HOME/download-scanner"
PLIST="$HOME/Library/LaunchAgents/com.rl.download-scanner.plist"
REPO_RAW="https://raw.githubusercontent.com/Claud68/download-scanner/main"

step "Checking prerequisites"
command -v python3 >/dev/null || die "python3 not found. Install Xcode command-line tools: xcode-select --install"
ok "python3 found: $(python3 --version)"

step "Installing 'requests' library"
python3 -m pip install --user --quiet requests 2>&1 | grep -v "^WARNING" || true
python3 -c "import requests" 2>/dev/null || die "Failed to install 'requests'."
ok "requests installed"

step "Creating $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
touch "$INSTALL_DIR/scanned_hashes.txt" "$INSTALL_DIR/scan.log"

step "Fetching scanner.py"
if [[ -f "$(dirname "$0")/scanner.py" ]]; then
  cp "$(dirname "$0")/scanner.py" "$INSTALL_DIR/scanner.py"
  ok "Copied scanner.py from local clone"
else
  curl -sSL "$REPO_RAW/scanner.py" -o "$INSTALL_DIR/scanner.py"
  ok "Downloaded scanner.py"
fi
chmod +x "$INSTALL_DIR/scanner.py"

step "Configuring"
if [[ -f "$INSTALL_DIR/.env" ]] && grep -q "^VT_API_KEY=.\+" "$INSTALL_DIR/.env" && ! grep -q "PASTE_YOUR_KEY_HERE" "$INSTALL_DIR/.env"; then
  ok "Existing .env found with API key — keeping it"
else
  say ""
  say "Get a free VirusTotal API key: ${BOLD}https://www.virustotal.com/gui/my-apikey${RESET}"
  open "https://www.virustotal.com/gui/my-apikey" 2>/dev/null || true
  say ""
  printf "${BOLD}Paste VirusTotal API key:${RESET} "
  read -r VT_KEY < /dev/tty
  [[ -n "$VT_KEY" ]] || die "No key entered."

  printf "${BOLD}ntfy topic${RESET} ${DIM}[rl-downloads]${RESET}: "
  read -r TOPIC < /dev/tty
  TOPIC="${TOPIC:-rl-downloads}"

  cat > "$INSTALL_DIR/.env" <<EOF
VT_API_KEY=$VT_KEY
NTFY_TOPIC=$TOPIC
POLL_SECONDS=10
MIN_FLAGS_FOR_THREAT=3
EOF
  chmod 600 "$INSTALL_DIR/.env"
  ok "Wrote $INSTALL_DIR/.env (600)"
fi

step "Installing LaunchAgent"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.rl.download-scanner</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>$INSTALL_DIR/scanner.py</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>$INSTALL_DIR/scan.log</string>
    <key>StandardErrorPath</key><string>$INSTALL_DIR/scan.log</string>
    <key>WorkingDirectory</key><string>$INSTALL_DIR</string>
</dict>
</plist>
EOF
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"
ok "LaunchAgent loaded"

step "Opening Full Disk Access pane"
say ""
warn "macOS requires one manual click for privacy reasons — this is the ONLY step you need to do yourself."
say ""
say "  1. When System Settings opens, click ${BOLD}+${RESET} at the bottom of the list"
say "  2. Press ${BOLD}Cmd+Shift+G${RESET}, type ${BOLD}/usr/bin/python3${RESET}, hit Enter, click Open"
say "  3. Toggle the new ${BOLD}python3${RESET} entry ${BOLD}ON${RESET}"
say "  4. If prompted, click ${BOLD}Quit & Reopen${RESET}"
say ""
open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"

sleep 2
step "Done"
ok "Scanner installed. After granting Full Disk Access, it will start watching ~/Downloads automatically."
say ""
say "Subscribe on your phone (ntfy app) to topic: ${BOLD}$(grep NTFY_TOPIC "$INSTALL_DIR/.env" | cut -d= -f2)${RESET}"
say ""
say "Commands:"
say "  ${DIM}tail -f $INSTALL_DIR/scan.log${RESET}              # watch live"
say "  ${DIM}launchctl unload $PLIST${RESET}     # stop"
say "  ${DIM}launchctl load -w $PLIST${RESET}    # start"
say "  ${DIM}bash $INSTALL_DIR/uninstall.sh${RESET}                   # remove everything"
