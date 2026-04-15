# Download Scanner

Watches `~/Downloads` on macOS, scans every new file against [VirusTotal](https://www.virustotal.com) (70+ antivirus engines), and pushes notifications to your phone via [ntfy.sh](https://ntfy.sh).

- **Privacy-preserving**: only the SHA-256 hash is sent to VirusTotal — the file never leaves your Mac
- **Zero maintenance**: runs as a LaunchAgent, auto-starts at login
- **Four alert tiers**: ✅ clean, 🟡 low-confidence hit, ⚠️ threat (3+ engines), ❓ unknown to VT
- **No heavy dependencies**: Python 3 + `requests`

---

## Install (one command)

```bash
curl -sSL https://raw.githubusercontent.com/Claud68/download-scanner/main/install.sh | bash
```

The installer will:
1. Verify Python 3 and install `requests`
2. Ask for your VirusTotal API key (opens the signup page for you)
3. Ask for an ntfy topic name (defaults to `rl-downloads`)
4. Write `~/download-scanner/` and install the LaunchAgent
5. Open macOS Full Disk Access settings with instructions to toggle on `python3`

**You only need to do one manual step**: grant `/usr/bin/python3` Full Disk Access. macOS requires a human click for that — it's Apple's privacy model, not a choice.

Subscribe to the ntfy topic on your phone (install ntfy from the App Store, subscribe to the same topic name you chose during install) to receive alerts.

---

## Uninstall

```bash
bash ~/download-scanner/uninstall.sh
```

---

## Control

| Command | What it does |
|---|---|
| `tail -f ~/download-scanner/scan.log` | watch live |
| `launchctl unload ~/Library/LaunchAgents/com.rl.download-scanner.plist` | stop |
| `launchctl load -w ~/Library/LaunchAgents/com.rl.download-scanner.plist` | start |
| `launchctl kickstart -k gui/$(id -u)/com.rl.download-scanner` | restart |

---

## Config

Edit `~/download-scanner/.env`:

```
VT_API_KEY=your_key
NTFY_TOPIC=rl-downloads
POLL_SECONDS=10                 # how often to poll ~/Downloads
MIN_FLAGS_FOR_THREAT=3          # engine hits before a file is flagged as a threat
```

Restart after editing: `launchctl kickstart -k gui/$(id -u)/com.rl.download-scanner`

---

## Limits

VirusTotal free tier: 4 requests/minute, 500/day. The scanner backs off automatically if rate-limited. Plenty of headroom for normal download volume.
