# Proxy UDP

[English](README.md) | [Русский](README.ru_RU.md)

**GitHub owner:** `dagmagnat`  
**Repository:** `proxy-udp`

`Proxy UDP` is an interactive TCP/UDP forwarding manager for Linux servers.

Despite the project name, the script is not limited to UDP. It can create forwarding rules for:

- UDP only;
- TCP only;
- both TCP and UDP.

The same repository also includes a separate `mtproto-manager` script. You do **not** need a separate repository for MTProto Manager.

---

## Contents

```text
proxy-udp          # TCP/UDP forwarding manager
mtproto-manager    # MTProto Proxy Docker manager
README.md          # English documentation
README.ru_RU.md    # Russian documentation
```

---

## Quick start

### Run Proxy UDP once

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

### Run MTProto Manager once

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

The `?$(date +%s)` suffix helps bypass GitHub Raw cache right after repository updates.

---

## Install quick commands

Use this if you do not want to open GitHub and copy the full command every time.

### Install `proxy-go`

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)") install-go
```

After that, run Proxy UDP with:

```bash
sudo proxy-go
```

Useful quick commands:

```bash
sudo proxy-go apply
sudo proxy-go status
sudo proxy-go tune
```

### Install `mtproto-go`

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)") install-go
```

After that, run MTProto Manager with:

```bash
sudo mtproto-go
```

Useful quick commands:

```bash
sudo mtproto-go start
sudo mtproto-go stop
sudo mtproto-go restart
sudo mtproto-go status
sudo mtproto-go logs
sudo mtproto-go link
```

---

## Manual installation

### Proxy UDP

```bash
wget -O /root/proxy-udp "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)"
chmod +x /root/proxy-udp
sudo /root/proxy-udp
```

### MTProto Manager

```bash
wget -O /root/mtproto-manager "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)"
chmod +x /root/mtproto-manager
sudo /root/mtproto-manager
```

---

## Language selection

On the first launch, both scripts ask which language to use:

```text
1) English
2) Русский
0) Exit
```

After selection, the interface continues in the chosen language.

The language can also be changed later from the script menu.

---

## Proxy UDP features

- Create TCP/UDP forwarding rules.
- Separate modes for `UDP`, `TCP`, and `UDP + TCP`.
- `AntizapretVPN by GubernievS` preset without ports `80` and `443`.
- Delete selected forwarding rules.
- Delete all forwarding rules managed by the script.
- View current forwarding rules.
- Check port availability.
- Clear screen during menu transitions.
- Colored terminal interface with a soft green accent.
- Menu navigation:
  - `0` — back;
  - `00` — main menu.
- NAT/conntrack diagnostics for high-load scenarios.
- NAT mode selection:
  - `SNAT` — recommended for static public IPv4;
  - `MASQUERADE` — recommended for dynamic public IPv4.
- Optional quick command installation: `proxy-go`.

---

## Proxy UDP main menu

```text
1) Create proxy / forwarding rule
2) AntizapretVPN by GubernievS preset without 80/443
3) Delete selected rules
4) Delete all rules
5) Show rules
6) Port check
7) Settings and high-load diagnostics
8) Install/update proxy-go quick command and auto-apply service
0) Exit
```

---

## AntizapretVPN by GubernievS preset

The preset contains these ports:

```text
504 508 540 580 50080 50443 51080 51443 52080 52443
```

Ports `80` and `443` are intentionally **not** included in the preset by default. If you need them, add them manually through:

```text
1) Create proxy / forwarding rule
```

Preset modes:

1. Recommended mode:
   - OpenVPN: `504`, `508`, `50080`, `50443` over TCP and UDP;
   - WireGuard / AmneziaWG: `540`, `580`, `51080`, `51443`, `52080`, `52443` over UDP.
2. All preset ports over TCP + UDP.
3. All preset ports over UDP only.
4. All preset ports over TCP only.

---

## Using Proxy UDP with GubernievS/AntiZapret-VPN

This section is for users who already use the `GubernievS/AntiZapret-VPN` project and want to connect to a blocked AntiZapret server through an additional proxy server.

General scheme:

```text
Client device -> Proxy UDP server -> AntiZapret VPN server
```

### 1. Install AntiZapret-VPN on the AntiZapret server

Run the official installation command on the AntiZapret VPN server:

```bash
bash <(wget -qO- --no-hsts --inet4-only https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup.sh)
```

### 2. Install Proxy UDP on the proxy server

Run this on the proxy server:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

Or install the short command:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)") install-go
sudo proxy-go
```

### 3. Use the preset

In Proxy UDP, choose:

```text
2) AntizapretVPN by GubernievS preset without 80/443
```

Enter the IPv4 address of your AntiZapret VPN server when requested.

### 4. Change client profiles

In OpenVPN, WireGuard and AmneziaWG client profiles, replace the original AntiZapret VPN server IP/domain with the new proxy server IP/domain.

Examples:

```text
remote OLD_ANTIZAPRET_IP 50080
remote NEW_PROXY_IP 50080
```

```text
Endpoint = OLD_ANTIZAPRET_IP:51080
Endpoint = NEW_PROXY_IP:51080
```

### 5. Allow the proxy server on the AntiZapret server

On the AntiZapret server, add the IPv4 address of the proxy server to:

```text
/root/antizapret/config/allow-ips.txt
```

Then run:

```bash
/root/antizapret/parse.sh ip
```

### 6. MTU note

If the proxy server interface MTU is lower than `1500`, reduce MTU in the OpenVPN and WireGuard/AmneziaWG configs accordingly.

---

## High load and UDP freezes

If UDP starts freezing under high speed, the problem is usually not the bash menu itself. The bottleneck is often Linux NAT/conntrack.

In Proxy UDP, open:

```text
7) Settings and high-load diagnostics
```

Useful checks:

```text
nf_conntrack_count
nf_conntrack_max
udp_timeout
udp_timeout_stream
```

For a normal VPS with static public IPv4, `SNAT` with automatic IP detection is usually the preferred mode.

---

## MTProto Manager

`mtproto-manager` is a separate interactive manager for running MTProto Proxy in Docker.

Features:

- create/start MTProto Proxy;
- stop/restart the container;
- show status;
- show Telegram proxy link;
- change external port;
- recreate secret;
- change workers count;
- view Docker logs;
- view stats endpoint if available;
- remove container, volume and config;
- install quick command `mtproto-go`.

Installation:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

Install quick command:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)") install-go
sudo mtproto-go
```

---

## Requirements

Recommended OS:

- Ubuntu 22.04 / 24.04;
- Debian 12 / 13.

Proxy UDP requires:

- `bash`;
- `iptables`;
- `iproute2`;
- `awk`;
- `grep`;
- `sysctl`.

MTProto Manager additionally requires Docker. If Docker is missing, the script can try to install it automatically on Debian/Ubuntu.

---

## Important notes

- Run scripts as `root` or with `sudo`.
- Test changes on a separate VPS before production use.
- `Proxy UDP` manages only its own iptables chains.
- UDP port checks are not always 100% reliable because UDP may not return a response even when traffic is allowed.
