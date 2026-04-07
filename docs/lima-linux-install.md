# Installing Lima on Linux

Lima's official docs gloss over Linux-specific setup. This guide covers the full process.

## Prerequisites

Install QEMU (required for the default VM driver on Linux):

```bash
# Ubuntu/Debian
sudo apt install -y qemu-system-x86 qemu-utils

# Fedora
sudo dnf install -y qemu-system-x86 qemu-img

# Arch
sudo pacman -S qemu-full
```

## Install Lima

Download the latest release and extract it into `~/.local`, which follows the standard XDG directory layout (`bin/`, `share/`, etc.):

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/lima-vm/lima/releases/latest | grep tag_name | cut -d'"' -f4)
curl -fsSL "https://github.com/lima-vm/lima/releases/download/${VERSION}/lima-${VERSION#v}-Linux-x86_64.tar.gz" \
  | tar xz -C ~/.local
```

For aarch64 hosts, replace `x86_64` with `aarch64` in the URL.

Verify the installation:

```bash
limactl --version
```

> If the command is not found, ensure `~/.local/bin` is in your `PATH`. Most Ubuntu/Fedora setups include it by default. If not, add to your shell profile:
> ```bash
> export PATH="$HOME/.local/bin:$PATH"
> ```

## Shell completion (optional)

### Zsh

Add to `~/.zshrc`:

```bash
eval "$(limactl completion zsh)"
```

### Bash

Add to `~/.bashrc`:

```bash
eval "$(limactl completion bash)"
```

### Fish

```fish
limactl completion fish | source
```

## Start a VM

```bash
limactl start
```

On first run, this creates a default Ubuntu VM, downloads the OS image and nerdctl. Subsequent starts reuse the existing instance.

Shell into the VM:

```bash
lima
```
