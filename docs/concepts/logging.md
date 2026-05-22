---
title: Daemon logging
description: Where sandboxd writes tracing output, how to control the log level, and how to run it under systemd or launchd.
---

`sandboxd` emits structured tracing output via `tracing_subscriber::fmt`. You choose where that output goes; the daemon does not manage log rotation itself — hand that off to your init system or `logrotate`.

For the daemon config surface (flags and env vars), see the [config reference](/sandboxd/reference/config/).

## Where logs go

The daemon routes tracing output to exactly one of:

- **stderr** (default). Use this when you run `sandboxd` under an init system that captures stderr — systemd via `StandardError=journal`, launchd via `StandardErrorPath`, or your favorite supervisor.
- **A file**, via `--log-file <PATH>`. The daemon opens the file in append+create mode. When `--log-file` is set, stderr logging is skipped so you do not get duplicate lines under an init system that also captures stderr.

If `--log-file` points at a path the daemon cannot open, startup fails fast — you do not get a partially-running daemon silently dropping logs.

## Log level

The level filter comes from `RUST_LOG` (parsed by `tracing_subscriber::EnvFilter`). If `RUST_LOG` is unset, the default is `info`.

```bash
RUST_LOG=debug sandboxd
RUST_LOG=sandboxd=debug,sandbox_core=info sandboxd
```

Per-module filters work the usual `tracing` way: `crate=level`, comma-separated.

## systemd (user unit)

Put this at `~/.config/systemd/user/sandboxd.service`:

```ini
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

Tail the logs:

```bash
journalctl --user -u sandboxd -f
```

## launchd (macOS)

Put this at `~/Library/LaunchAgents/com.example.sandboxd.plist`:

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

launchd captures stderr to `StandardErrorPath`; the daemon itself stays in default (stderr) mode.

## `--log-file` without an init supervisor

When you launch the daemon directly and do not have systemd or launchd in the mix, write to a file:

```bash
sandboxd --log-file ~/.local/share/sandboxd/sandboxd.log
```

The file is opened in append mode. To rotate, use `logrotate` with `copytruncate`:

```
~/.local/share/sandboxd/sandboxd.log {
    daily
    rotate 7
    compress
    copytruncate
    missingok
}
```

`copytruncate` matters here: the daemon keeps an open file handle in append mode and does not reopen on `HUP`, so rename-based rotation would silently stop writing to the new file.

## What to read next

- [Daemon config reference](/sandboxd/reference/config/) — every flag and environment variable.
- [Troubleshooting](/sandboxd/guides/troubleshooting/) — debugging a daemon that will not start.
