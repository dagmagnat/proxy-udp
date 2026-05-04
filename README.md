# Proxy UDP

[English](README.md) | [Русский](README.ru_RU.md)

`Proxy UDP` is an interactive TCP/UDP forwarding manager based on Linux `iptables` NAT.

Despite the name, the script is not limited to UDP. It can create forwarding rules for:

- UDP only;
- TCP only;
- both TCP and UDP.

The script is useful when you have an intermediate proxy/forwarding server and need to redirect traffic to another server, for example to a VPN server.

## Quick install

### Proxy UDP

One-command launch:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

Manual install:

```bash
wget -O /root/proxy-udp "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)"
chmod +x /root/proxy-udp
sudo /root/proxy-udp
```

### MTProto Manager

One-command launch:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

Manual install:

```bash
wget -O /root/mtproto-manager "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)"
chmod +x /root/mtproto-manager
sudo /root/mtproto-manager
```

The `?$(date +%s)` suffix is used to bypass a possible GitHub Raw cache immediately after updating a file.

## Features

- Create TCP/UDP forwarding rules.
- Separate modes for `UDP`, `TCP`, and `UDP + TCP`.
- `AntizapretVPN by GubernievS` preset without ports `80` and `443`.
- Remove selected rules.
- Remove all rules managed by the script.
- View current rules.
- Port availability checks.
- Screen clearing when switching menu sections.
- Colored terminal interface with a soft green accent.
- Navigation in the main sections:
  - `0` — go back;
  - `00` — return to the main menu.
- High-load tuning: `conntrack`, UDP timeouts, backlog, BBR/fq.
- NAT mode selection:
  - `SNAT` — better for a static external IPv4 address;
  - `MASQUERADE` — better for a dynamic external IPv4 address.
- Optional installation of the `proxy-udp` command and a systemd service for automatic rule re-application after reboot.

## Main menu

```text
1) Create proxy / forwarding rule
2) AntizapretVPN by GubernievS — port preset without 80/443
3) Delete selected rules
4) Delete all rules
5) Show rules
6) Port check
7) High-load tuning and diagnostics
8) Install proxy-udp command and auto-apply rules after reboot
0) Exit
```

## AntizapretVPN by GubernievS preset

The preset includes these ports:

```text
504 508 540 580 50080 50443 51080 51443 52080 52443
```

Ports `80` and `443` are intentionally not included in the default preset.

Available modes:

1. Recommended mode:
   - OpenVPN: `504`, `508`, `50080`, `50443` over TCP and UDP;
   - WireGuard / AmneziaWG: `540`, `580`, `51080`, `51443`, `52080`, `52443` over UDP.
2. All preset ports over TCP+UDP.
3. All preset ports over UDP only.
4. All preset ports over TCP only.

## How Proxy UDP works

The script creates its own chains:

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

## High load and UDP freezes

If UDP starts freezing or lagging at high traffic rates, the problem is usually not the Bash menu itself. In most cases, the bottleneck is Linux NAT/conntrack.

The menu section `7) High-load tuning and diagnostics` includes:

- system tuning;
- viewing `nf_conntrack_count` and `nf_conntrack_max`;
- choosing `SNAT` or `MASQUERADE`.

For a static IP address, `SNAT` is usually the better choice. For a dynamic IP address, `MASQUERADE` is usually more convenient.

## Port checking

The menu section `6) Port check` can check:

- existing rules;
- a manually entered IP address and a list of ports.

Important: TCP can be checked fairly reliably. UDP cannot be checked with 100% accuracy without an application-level response. If a UDP service does not reply to a probe, it does not always mean the port is closed.

For UDP checks, installing `netcat` is recommended:

```bash
apt-get update
apt-get install -y netcat-openbsd
```

## MTProto Manager

The repository also includes `mtproto-manager`, an interactive manager for launching MTProto Proxy in Docker.

Main features:

- create and start MTProto Proxy;
- stop and restart the container;
- show proxy status;
- show the Telegram connection link;
- change the external port;
- regenerate the proxy secret;
- show Docker logs;
- update the Docker image;
- remove the container and configuration.

## Auto-apply Proxy UDP rules after reboot

In the main menu, select:

```text
8) Install proxy-udp command and auto-apply rules after reboot
```

This creates the command:

```bash
proxy-udp
```

And the systemd service:

```bash
systemctl status proxy-udp.service
```

Apply rules manually:

```bash
sudo proxy-udp apply
```

Show status:

```bash
sudo proxy-udp status
```

Apply network tuning:

```bash
sudo proxy-udp tune
```

## Requirements

- Debian/Ubuntu or another Linux distribution with `iptables`.
- Root access.
- IPv4 forwarding.
- For extended diagnostics: `conntrack-tools`.
- For UDP checks: `netcat-openbsd`.
- For MTProto Manager: Docker. If Docker is missing, the manager will try to install it on Debian/Ubuntu.

## Important notes

The script does not flush all server firewall rules. It manages only its own `PROXY_UDP_*` chains and does not directly modify unrelated rules.

Before using the script on a production server, it is recommended to have rescue console/VNC access from your hosting provider, so you do not lose access if a firewall configuration mistake is made.
