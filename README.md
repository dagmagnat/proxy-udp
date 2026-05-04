# Proxy UDP

[English](README.md) | [Русский](README.ru_RU.md)

`Proxy UDP` is an interactive TCP/UDP forwarding manager for Linux servers.

Despite the project name, the script is not limited to UDP. It can create forwarding rules for:

- UDP only;
- TCP only;
- both TCP and UDP.

This repository also includes a separate `mtproto-manager` script. MTProto Manager can be installed and launched independently from `proxy-udp`, without creating a separate repository.

---

## What is included in this repository?

```text
proxy-udp          # TCP/UDP forwarding manager
mtproto-manager    # MTProto Proxy Docker manager
README.md          # English documentation
README.ru_RU.md    # Russian documentation
```

---

## Quick installation

### Run Proxy UDP

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

Manual installation:

```bash
wget -O /root/proxy-udp "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)"
chmod +x /root/proxy-udp
sudo /root/proxy-udp
```

### Run MTProto Manager only

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

Manual installation:

```bash
wget -O /root/mtproto-manager "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)"
chmod +x /root/mtproto-manager
sudo /root/mtproto-manager
```

The `?$(date +%s)` suffix helps bypass possible GitHub Raw cache immediately after updating files in the repository.

---

## Fast local commands: `proxy-go` and `mtproto-go`

You do not need to open GitHub and copy the full installation command every time. Install a short local command once, then run the manager with one word.

### Install or update `proxy-go`

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)") install-go
```

After that, launch Proxy UDP anytime with:

```bash
sudo proxy-go
```

You can also install it from the Proxy UDP menu:

```text
8) Install/update proxy-go quick command and auto-apply service
```

This also creates a systemd service for restoring Proxy UDP rules after reboot:

```bash
sudo systemctl status proxy-go.service
```

Apply saved forwarding rules manually:

```bash
sudo proxy-go apply
```

Show status:

```bash
sudo proxy-go status
```

Apply network tuning:

```bash
sudo proxy-go tune
```

### Install or update `mtproto-go`

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)") install-go
```

After that, launch MTProto Manager anytime with:

```bash
sudo mtproto-go
```

You can also install it from the MTProto Manager menu:

```text
13) Install/update mtproto-go quick command
```

Useful MTProto quick subcommands:

```bash
sudo mtproto-go status
sudo mtproto-go logs
sudo mtproto-go restart
sudo mtproto-go stop
```

To update the local quick command later, run the same `install-go` command again or choose the install/update item in the menu.

---

## Language selection

On first launch, both scripts ask which language to use:

```text
1) English
2) Русский
0) Exit
```

The selected language is saved and used on the next launches.

Configuration files:

```text
/etc/proxy-udp.conf
/etc/mtproto_manager.conf
```

You can change the language later from the menu:

- Proxy UDP: `High-load tuning and diagnostics` -> `Change language`;
- MTProto Manager: `Change language`.

---

## Proxy UDP features

- Create TCP/UDP forwarding rules.
- Separate modes for `UDP`, `TCP`, and `UDP + TCP`.
- `AntizapretVPN by GubernievS` preset without ports `80` and `443`.
- Remove selected rules.
- Remove all rules managed by the script.
- View current rules.
- Check port availability.
- Clear the terminal screen when switching menu sections.
- Colored terminal interface with a soft green accent.
- Navigation in menu sections:
  - `0` — go back;
  - `00` — return to the main menu.
- English and Russian interface.
- High-load tuning and diagnostics for NAT/conntrack.
- NAT mode selection:
  - `SNAT` — recommended for a static external IPv4 address;
  - `MASQUERADE` — recommended for a dynamic external IPv4 address.
- Optional installation of the `proxy-go` command and a systemd service for automatic rule re-application after reboot.

---

## Proxy UDP main menu

```text
1) Create proxy / forwarding rule
2) AntizapretVPN by GubernievS - port preset without 80/443
3) Delete selected rules
4) Delete all rules
5) Show rules
6) Port check
7) High-load tuning and diagnostics
8) Install/update proxy-go quick command and auto-apply service
0) Exit
```

---

## AntizapretVPN by GubernievS preset

The preset includes these ports:

```text
504 508 540 580 50080 50443 51080 51443 52080 52443
```

Ports `80` and `443` are intentionally not included in the default preset. If you need ports `80` and `443`, add them manually through:

```text
1) Create proxy / forwarding rule
```

Available preset modes:

1. Recommended mode:
   - OpenVPN: `504`, `508`, `50080`, `50443` over TCP and UDP;
   - WireGuard / AmneziaWG: `540`, `580`, `51080`, `51443`, `52080`, `52443` over UDP.
2. All preset ports over TCP + UDP.
3. All preset ports over UDP only.
4. All preset ports over TCP only.

---

## Using Proxy UDP with GubernievS/AntiZapret-VPN

This section is for users of the `GubernievS/AntiZapret-VPN` project who want to use a separate proxy server in front of their AntiZapret VPN server.

Typical scheme:

```text
Client device -> Proxy UDP server -> AntiZapret VPN server
```

### 1. Install AntiZapret-VPN on the VPN server

On the AntiZapret VPN server, use the official installation command from the AntiZapret-VPN project:

```bash
bash <(wget -qO- --no-hsts --inet4-only https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/install.sh)
```

### 2. Install Proxy UDP on the proxy server

On the proxy server, run:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

Or install the fast command once:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)") install-go
sudo proxy-go
```

In the menu, select:

```text
2) AntizapretVPN by GubernievS - port preset without 80/443
```

Then enter the IPv4 address of your AntiZapret VPN server.

### 3. Replace the server address in client profiles

In your OpenVPN, WireGuard, or AmneziaWG client profiles, replace the AntiZapret VPN server IP/domain with the IP/domain of the proxy server.

### 4. Allow the proxy server on the AntiZapret VPN server

On the AntiZapret VPN server, add the IPv4 address of the proxy server to:

```text
/root/antizapret/config/allow-ips.txt
```

Then run:

```bash
/root/antizapret/parse.sh ip
```

### 5. MTU note

If the proxy server has MTU lower than `1500`, reduce MTU in OpenVPN and WireGuard configuration files on the AntiZapret VPN server. This can help avoid packet fragmentation and unstable UDP behavior.

---

## How Proxy UDP works

The script creates its own iptables chains:

- `PROXY_UDP_NAT` in the `nat` table for DNAT;
- `PROXY_UDP_POST` in the `nat` table for SNAT/MASQUERADE;
- `PROXY_UDP_FWD` in the `filter` table for FORWARD allow rules.

Rules are stored in:

```text
/etc/proxy-udp.rules
```

Rule format:

```text
proto source_port target_ip target_port
```

Example:

```text
udp 50080 203.0.113.10 50080
tcp 50443 203.0.113.10 50443
```

The script manages only its own `PROXY_UDP_*` chains and does not intentionally delete unrelated firewall rules.

---

## High load and UDP freezes

If UDP traffic starts freezing or lagging at high speed, the problem is usually not the Bash menu itself. In most cases, the bottleneck is Linux NAT/conntrack.

The menu section `7) High-load tuning and diagnostics` includes:

- system tuning;
- viewing `nf_conntrack_count` and `nf_conntrack_max`;
- choosing between `SNAT` and `MASQUERADE`;
- basic diagnostics for high traffic scenarios.

For a static external IPv4 address, `SNAT` is usually the better choice. For a dynamic external IPv4 address, `MASQUERADE` is usually more convenient.

---

## Port checking

The menu section `6) Port check` can check:

- existing forwarding rules;
- manually entered IP address and port list.

Important: TCP can be checked fairly reliably. UDP cannot be checked with 100% accuracy without an application-level response. If a UDP service does not reply to a probe, it does not always mean the port is closed.

For better UDP checks, installing `netcat` is recommended:

```bash
apt-get update
apt-get install -y netcat-openbsd
```

---

## MTProto Manager

`mtproto-manager` is a separate interactive manager for launching MTProto Proxy in Docker.

Run MTProto Manager:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

Install the fast `mtproto-go` command:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)") install-go
sudo mtproto-go
```

Main features:

- create and start MTProto Proxy;
- stop and restart the container;
- show proxy status;
- show the Telegram connection link;
- change the external port;
- regenerate the proxy secret/key;
- change workers;
- show Docker logs;
- update the Docker image;
- remove the container and configuration;
- English and Russian interface.

MTProto Manager uses Docker. If Docker is missing, the script can try to install it automatically on Debian/Ubuntu.

---

## Requirements

### For Proxy UDP

- Debian/Ubuntu or another Linux distribution with `iptables`.
- Root access.
- IPv4 forwarding.
- For extended diagnostics: `conntrack-tools`.
- For UDP checks: `netcat-openbsd`.

### For MTProto Manager

- Debian/Ubuntu recommended.
- Root access.
- Docker.
- If Docker is missing, the manager will try to install it on Debian/Ubuntu.

---

## Safety note

Before using firewall/NAT scripts on a production server, it is recommended to have emergency access through your hosting provider's rescue console, VNC, or serial console. This helps avoid losing access if a firewall rule is configured incorrectly.
