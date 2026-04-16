# Daemon logging

`sandboxd` writes tracing output (`tracing_subscriber::fmt`) to either:

- **stderr (default)** — when run under an init system that captures stderr.
- **`--log-file <PATH>`** — appends to a file; stderr is skipped to avoid
  duplicate lines. Fails fast if the file can't be opened.

Level filter: `RUST_LOG` (default `info`).

## systemd (user unit)

```ini
# ~/.config/systemd/user/sandboxd.service
[Unit]
Description=Sandbox daemon
[Service]
ExecStart=%h/.local/bin/sandboxd
Restart=on-failure
Environment=RUST_LOG=info
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=default.target
```

Logs: `journalctl --user -u sandboxd -f`.

## launchd (macOS)

```xml
<!-- ~/Library/LaunchAgents/com.example.sandboxd.plist -->
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.sandboxd</string>
  <key>ProgramArguments</key>
  <array><string>/usr/local/bin/sandboxd</string></array>
  <key>StandardErrorPath</key><string>/tmp/sandboxd.log</string>
  <key>KeepAlive</key><true/>
</dict></plist>
```

## `--log-file` (no init supervisor)

Alternative when launching directly:

```sh
sandboxd --log-file ~/.local/share/sandboxd/sandboxd.log
```

Append-mode open; use `logrotate` with `copytruncate` to rotate.