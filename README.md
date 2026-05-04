# Proxy UDP

[English](README.md) | [Русский](README.ru_RU.md)

`Proxy UDP` is an interactive TCP/UDP forwarding manager for Linux servers.

Despite the project name, the script is not limited to UDP. It can create forwarding rules for:

- UDP only;
- TCP only;
- both TCP and UDP.

The repository also includes a separate `mtproto-manager` script. It can be installed and launched independently from `proxy-udp`, without creating a separate repository.

---

## Quick installation

### Install Proxy UDP

Use this command if you want to manage TCP/UDP forwarding rules:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

Manual installation:

```bash
wget -O /root/proxy-udp "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)"
chmod +x /root/proxy-udp
sudo /root/proxy-udp
```

### Install MTProto Manager only

Use this command if you only need the MTProto Proxy manager:

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
- High-load tuning and diagnostics for NAT/conntrack.
- NAT mode selection:
  - `SNAT` — recommended for a static external IPv4 address;
  - `MASQUERADE` — recommended for a dynamic external IPv4 address.
- Optional installation of the `proxy-udp` command and a systemd service for automatic rule re-application after reboot.

---

## Proxy UDP main menu

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

---

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
2. All preset ports over TCP + UDP.
3. All preset ports over UDP only.
4. All preset ports over TCP only.

---

## Using Proxy UDP with GubernievS/AntiZapret-VPN

This section is for users of [GubernievS/AntiZapret-VPN](https://github.com/GubernievS/AntiZapret-VPN) who want to place a separate proxy server between their clients and the main AntiZapret VPN server.

Use this when your main AntiZapret VPN server is located outside Russia and its IP address or domain becomes blocked. In this setup, users connect to the proxy server, and the proxy server forwards traffic to the original AntiZapret VPN server.

### Recommended topology

```text
Client device -> Proxy UDP server -> AntiZapret VPN server
```

The proxy server should usually be located in the country or network from which your users can still connect to it. The AntiZapret VPN server remains the real VPN server with OpenVPN, WireGuard, or AmneziaWG installed.

### Step 1. Install AntiZapret-VPN on the main VPN server

On the main AntiZapret VPN server, install GubernievS/AntiZapret-VPN using the official installer:

```bash
bash <(wget -qO- --no-hsts --inet4-only https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup.sh)
```

During setup, enable the protocols and reserve ports you need. In AntiZapret-VPN, OpenVPN supports UDP and TCP and uses ports `50080` and `50443`, with reserve ports `80`, `443`, `504`, and `508`. WireGuard uses UDP ports `51080` and `51443`, with reserve ports `540` and `580`. AmneziaWG uses UDP ports `52080` and `52443`.

### Step 2. Install Proxy UDP on the proxy server

On the separate proxy server, run:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

Then select:

```text
2) AntizapretVPN by GubernievS — port preset without 80/443
```

Enter the IPv4 address of your main AntiZapret VPN server.

The preset forwards these ports:

```text
504 508 540 580 50080 50443 51080 51443 52080 52443
```

Ports `80` and `443` are not added by this preset intentionally. If you really need them, add them manually from:

```text
1) Create proxy / forwarding rule
```

### Step 3. Choose the correct preset mode

Recommended mode:

```text
OpenVPN: 504, 508, 50080, 50443 over TCP and UDP
WireGuard / AmneziaWG: 540, 580, 51080, 51443, 52080, 52443 over UDP
```

Use `TCP + UDP for all preset ports` only if you intentionally want every listed port to be forwarded through both protocols.

### Step 4. Replace the server address in client profiles

In your AntiZapret client profiles, replace the old AntiZapret VPN server IP address or domain with the new proxy server IP address or domain.

Examples:

- in OpenVPN `.ovpn` files, change the `remote` address;
- in WireGuard / AmneziaWG `.conf` files, change the `Endpoint` address.

Keep the port unchanged unless you intentionally changed ports on the proxy server.

### Step 5. Allow the proxy server on the AntiZapret server

On the main AntiZapret VPN server, add the proxy server IPv4 address to:

```text
/root/antizapret/config/allow-ips.txt
```

Then run:

```bash
/root/antizapret/parse.sh ip
```

### Step 6. Check ports

On the proxy server, open:

```text
6) Port check
```

You can check the preset ports against the main AntiZapret VPN server. TCP checks are usually reliable. UDP checks are only indicative because UDP services may not respond to a probe even when forwarding works.

### MTU note

If the proxy server has MTU lower than `1500`, reduce the MTU value in OpenVPN and WireGuard/AmneziaWG configuration files on the AntiZapret VPN server. A common rule is to reduce the VPN MTU by the difference between `1500` and the actual proxy server MTU.

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

Install and launch MTProto Manager:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

Main features:

- create and start MTProto Proxy;
- stop and restart the container;
- show proxy status;
- show the Telegram connection link;
- change the external port;
- regenerate the proxy secret/key;
- show Docker logs;
- update the Docker image;
- remove the container and configuration.

MTProto Manager uses Docker. If Docker is missing, the script can try to install it automatically on Debian/Ubuntu.

---

## Auto-apply Proxy UDP rules after reboot

In the Proxy UDP main menu, select:

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
