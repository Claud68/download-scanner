#!/usr/bin/env bash
# Uninstall the download scanner.
set -e
PLIST="$HOME/Library/LaunchAgents/com.rl.download-scanner.plist"
DIR="$HOME/download-scanner"

launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
echo "✓ LaunchAgent removed"

read -r -p "Delete $DIR and all scanner data? [y/N] " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  rm -rf "$DIR"
  echo "✓ $DIR removed"
else
  echo "Kept $DIR (config/logs preserved)"
fi
echo "Done. You can still revoke python3's Full Disk Access in System Settings → Privacy & Security."
