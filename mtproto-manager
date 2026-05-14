#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="MT Photo Manager (MTProto/FakeTLS)"
VERSION="2026.05.14"
CONF_DIR="/etc/mt-photo-manager"
CONF_FILE="$CONF_DIR/manager.env"
MTG_CONFIG="$CONF_DIR/mtg.toml"
FORWARD_DIR="$CONF_DIR/forwards"
BIN_PATH="/usr/local/bin/mtpm"
CONTAINER_NAME="mt-photo-manager-mtg"
DEFAULT_IMAGE="nineseconds/mtg:2.2.8"
DEFAULT_PUBLIC_PORT="443"
DEFAULT_INTERNAL_PORT="3128"
DEFAULT_METRICS_PORT="3129"
DEFAULT_CONCURRENCY="8192"
DEFAULT_DOMAIN="www.google.com"
DEFAULT_DNS="https://1.1.1.1"

SOFT_GREEN='\033[38;5;114m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

MSG_BACK="__BACK__"
MSG_MAIN="__MAIN__"

PUBLIC_PORT="$DEFAULT_PUBLIC_PORT"
INTERNAL_PORT="$DEFAULT_INTERNAL_PORT"
METRICS_PORT="$DEFAULT_METRICS_PORT"
IMAGE="$DEFAULT_IMAGE"
SECRET=""
DOMAIN="$DEFAULT_DOMAIN"
DOMAIN_FRONTING_HOST=""
CONCURRENCY="$DEFAULT_CONCURRENCY"
PREFER_IP="prefer-ipv4"
DNS_RESOLVER="$DEFAULT_DNS"
OUTBOUND_PROXY=""
DEBUG="false"
DOPPELGANGER_URLS=""
BLOCKLIST_ENABLED="false"
AUTO_UPDATE="true"

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

trim() {
  local s="${1//$'\r'/}"
  s="$(printf "%s" "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  printf "%s" "$s"
}

q() { printf '%q' "$1"; }

cls() { printf '\033[H\033[2J\033[3J'; }
ok() { echo -e "${SOFT_GREEN}$*${RESET}"; }
warn() { echo -e "${YELLOW}$*${RESET}" >&2; }
err() { echo -e "${RED}$*${RESET}" >&2; }
info() { echo -e "${CYAN}$*${RESET}"; }

pause() {
  echo >&2
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    read -r -p "Нажмите Enter чтобы продолжить... " _ < /dev/tty || true
  else
    read -r -p "Нажмите Enter чтобы продолжить... " _ || true
  fi
}

header() {
  cls
  echo -e "${SOFT_GREEN}${BOLD}========== ${APP_NAME} v${VERSION} ==========${RESET}"
  echo -e "${DIM}0 — назад/выход, 00 — главное меню${RESET}"
  echo
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Запустите от root: sudo bash $0"
    exit 1
  fi
}

read_nav() {
  local prompt="$1" value
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    printf "%s" "$prompt" > /dev/tty
    IFS= read -r value < /dev/tty || return 1
  else
    read -r -p "$prompt" value || return 1
  fi
  value="$(trim "$value")"
  case "$value" in
    0) echo "$MSG_BACK" ;;
    00) echo "$MSG_MAIN" ;;
    *) echo "$value" ;;
  esac
}

is_nav_back() { [[ "${1:-}" == "$MSG_BACK" ]]; }
is_nav_main() { [[ "${1:-}" == "$MSG_MAIN" ]]; }

valid_port() {
  local p="$(trim "${1:-}")"
  [[ -n "$p" && "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 )) || return 1
}

valid_number_range() {
  local v="$(trim "${1:-}")" min="$2" max="$3"
  [[ -n "$v" && "$v" =~ ^[0-9]+$ ]] || return 1
  (( v >= min && v <= max )) || return 1
}

valid_domain() {
  local d="$(trim "${1:-}")"
  [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || return 1
  [[ "$d" != *".."* ]] || return 1
}

valid_ipv4() {
  local ip="$(trim "${1:-}")" IFS=.
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  read -r a b c d <<< "$ip"
  for o in "$a" "$b" "$c" "$d"; do (( o >= 0 && o <= 255 )) || return 1; done
}

valid_secret() {
  local s="$(trim "${1:-}")"
  [[ "$s" =~ ^ee[0-9a-fA-F]{32}[0-9a-fA-F]+$ ]] || return 1
}

port_free() {
  local p="$1"
  if cmd_exists ss; then
    ! ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
  elif cmd_exists netstat; then
    ! netstat -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
  else
    return 0
  fi
}

rand_hex_16bytes() {
  if cmd_exists openssl; then
    openssl rand -hex 16
  else
    head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

hex_encode() {
  printf '%s' "$1" | od -An -tx1 | tr -d ' \n'
}

make_secret_for_domain() {
  local domain="$1"
  printf 'ee%s%s' "$(rand_hex_16bytes)" "$(hex_encode "$domain")"
}

secret_domain() {
  local s="${1:-}"
  [[ "$s" =~ ^ee[0-9a-fA-F]{32}([0-9a-fA-F]+)$ ]] || return 1
  local hex="${BASH_REMATCH[1]}"
  if cmd_exists xxd; then
    printf '%s' "$hex" | xxd -r -p 2>/dev/null || true
  else
    printf '%s' "$hex" | sed 's/../\\x&/g' | xargs printf 2>/dev/null || true
  fi
}

urlencode() {
  local s="$1" out="" i c
  for (( i=0; i<${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) printf -v c '%%%02X' "'${c}"; out+="$c" ;;
    esac
  done
  printf '%s' "$out"
}

ensure_dirs() {
  mkdir -p "$CONF_DIR" "$FORWARD_DIR"
  chmod 700 "$CONF_DIR"
}

conf_defaults() {
  PUBLIC_PORT="$DEFAULT_PUBLIC_PORT"
  INTERNAL_PORT="$DEFAULT_INTERNAL_PORT"
  METRICS_PORT="$DEFAULT_METRICS_PORT"
  IMAGE="$DEFAULT_IMAGE"
  SECRET=""
  DOMAIN="$DEFAULT_DOMAIN"
  DOMAIN_FRONTING_HOST=""
  CONCURRENCY="$DEFAULT_CONCURRENCY"
  PREFER_IP="prefer-ipv4"
  DNS_RESOLVER="$DEFAULT_DNS"
  OUTBOUND_PROXY=""
  DEBUG="false"
  DOPPELGANGER_URLS=""
  BLOCKLIST_ENABLED="false"
  AUTO_UPDATE="true"
}

conf_load() {
  conf_defaults
  [[ -f "$CONF_FILE" ]] || return 0
  # shellcheck disable=SC1090
  source "$CONF_FILE" || true
  valid_port "$PUBLIC_PORT" || PUBLIC_PORT="$DEFAULT_PUBLIC_PORT"
  valid_port "$INTERNAL_PORT" || INTERNAL_PORT="$DEFAULT_INTERNAL_PORT"
  valid_port "$METRICS_PORT" || METRICS_PORT="$DEFAULT_METRICS_PORT"
  valid_number_range "$CONCURRENCY" 16 2000000 || CONCURRENCY="$DEFAULT_CONCURRENCY"
  [[ -n "$IMAGE" ]] || IMAGE="$DEFAULT_IMAGE"
  valid_domain "$DOMAIN" || DOMAIN="$DEFAULT_DOMAIN"
  if [[ -n "$SECRET" ]] && ! valid_secret "$SECRET"; then SECRET=""; fi
  case "$PREFER_IP" in prefer-ipv4|prefer-ipv6|only-ipv4|only-ipv6) : ;; *) PREFER_IP="prefer-ipv4" ;; esac
  [[ "$DEBUG" == "true" || "$DEBUG" == "false" ]] || DEBUG="false"
  [[ "$BLOCKLIST_ENABLED" == "true" || "$BLOCKLIST_ENABLED" == "false" ]] || BLOCKLIST_ENABLED="false"
  [[ "$AUTO_UPDATE" == "true" || "$AUTO_UPDATE" == "false" ]] || AUTO_UPDATE="true"
}

conf_save() {
  ensure_dirs
  cat > "$CONF_FILE" <<EOF_CONF
# ${APP_NAME} config
PUBLIC_PORT=$(q "$PUBLIC_PORT")
INTERNAL_PORT=$(q "$INTERNAL_PORT")
METRICS_PORT=$(q "$METRICS_PORT")
IMAGE=$(q "$IMAGE")
SECRET=$(q "$SECRET")
DOMAIN=$(q "$DOMAIN")
DOMAIN_FRONTING_HOST=$(q "$DOMAIN_FRONTING_HOST")
CONCURRENCY=$(q "$CONCURRENCY")
PREFER_IP=$(q "$PREFER_IP")
DNS_RESOLVER=$(q "$DNS_RESOLVER")
OUTBOUND_PROXY=$(q "$OUTBOUND_PROXY")
DEBUG=$(q "$DEBUG")
DOPPELGANGER_URLS=$(q "$DOPPELGANGER_URLS")
BLOCKLIST_ENABLED=$(q "$BLOCKLIST_ENABLED")
AUTO_UPDATE=$(q "$AUTO_UPDATE")
EOF_CONF
  chmod 600 "$CONF_FILE"
}

toml_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

write_mtg_config() {
  ensure_dirs
  conf_load
  if [[ -z "$SECRET" ]]; then
    SECRET="$(make_secret_for_domain "$DOMAIN")"
    conf_save
  fi
  local fronting_block=""
  if [[ -n "$DOMAIN_FRONTING_HOST" ]]; then
    fronting_block="host = \"$(toml_escape "$DOMAIN_FRONTING_HOST")\""
  fi

  local proxies_block=""
  if [[ -n "$OUTBOUND_PROXY" ]]; then
    proxies_block="  \"$(toml_escape "$OUTBOUND_PROXY")\""
  fi

  local doppel_block=""
  if [[ -n "$DOPPELGANGER_URLS" ]]; then
    local IFS=',' url first=1
    for url in $DOPPELGANGER_URLS; do
      url="$(trim "$url")"
      [[ -z "$url" ]] && continue
      if [[ "$first" -eq 1 ]]; then
        doppel_block="  \"$(toml_escape "$url")\""
        first=0
      else
        doppel_block+=$',\n  '"\"$(toml_escape "$url")\""
      fi
    done
  fi

  cat > "$MTG_CONFIG" <<EOF_TOML
# Generated by ${APP_NAME}. Edit via mtpm menu when possible.
debug = ${DEBUG}
secret = "$(toml_escape "$SECRET")"
bind-to = "0.0.0.0:${INTERNAL_PORT}"
concurrency = ${CONCURRENCY}
prefer-ip = "$(toml_escape "$PREFER_IP")"
auto-update = ${AUTO_UPDATE}
tolerate-time-skewness = "10s"
allow-fallback-on-unknown-dc = true

[domain-fronting]
${fronting_block}
port = 443
proxy-protocol = false

[network]
dns = "$(toml_escape "$DNS_RESOLVER")"
proxies = [
${proxies_block}
]

[network.timeout]
tcp = "7s"
http = "12s"
idle = "5m"
handshake = "10s"

[network.keep-alive]
disabled = false
idle = "15s"
interval = "15s"
count = 9

[defense.doppelganger]
urls = [
${doppel_block}
]
repeats-per-raid = 5
raid-each = "6h"
drs = false

[defense.anti-replay]
enabled = true
max-size = "2mib"
error-rate = 0.001

[defense.blocklist]
enabled = ${BLOCKLIST_ENABLED}
download-concurrency = 2
urls = [
  "https://iplists.firehol.org/files/firehol_abusers_1d.netset"
]
update-each = "24h"

[defense.allowlist]
enabled = false
urls = []

[stats.prometheus]
enabled = true
bind-to = "0.0.0.0:${METRICS_PORT}"
http-path = "/"
metric-prefix = "mtg"
EOF_TOML
  chmod 600 "$MTG_CONFIG"
}

pkg_update_once="false"
pkg_install() {
  local packages=("$@")
  if cmd_exists apt-get; then
    if [[ "$pkg_update_once" != "true" ]]; then apt-get update -y; pkg_update_once="true"; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
  elif cmd_exists dnf; then
    dnf install -y "${packages[@]}"
  elif cmd_exists yum; then
    yum install -y "${packages[@]}"
  else
    err "Не найден apt-get/dnf/yum. Установите вручную: ${packages[*]}"
    return 1
  fi
}

ensure_base_tools() {
  local missing=()
  for c in curl sed awk grep od; do cmd_exists "$c" || missing+=("$c"); done
  if ((${#missing[@]})); then
    warn "Ставлю базовые утилиты: ${missing[*]}"
    pkg_install ca-certificates curl coreutils gawk grep sed || true
  fi
  cmd_exists openssl || pkg_install openssl || true
  cmd_exists ss || pkg_install iproute2 || true
}

ensure_docker() {
  if cmd_exists docker; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    return 0
  fi
  warn "Docker не найден. Устанавливаю Docker из репозитория ОС."
  if cmd_exists apt-get; then
    pkg_install ca-certificates curl gnupg lsb-release docker.io
  elif cmd_exists dnf; then
    pkg_install docker
  elif cmd_exists yum; then
    pkg_install docker
  else
    err "Автоустановка Docker невозможна. Установите Docker вручную."
    return 1
  fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  cmd_exists docker || { err "Docker не установился."; return 1; }
}

open_firewall() {
  local port="$1"
  if cmd_exists ufw; then
    ufw allow "${port}/tcp" >/dev/null 2>&1 || true
  fi
  if cmd_exists firewall-cmd && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
  if cmd_exists iptables; then
    iptables -w -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
      iptables -w -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
  fi
}

close_firewall_iptables_only() {
  local port="$1"
  if cmd_exists iptables; then
    while iptables -w -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; do :; done
  fi
}

container_exists() { docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; }
container_running() { docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; }

get_public_ip() {
  local ip=""
  if cmd_exists curl; then
    ip="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    [[ -z "$ip" ]] && ip="$(curl -4fsS --max-time 5 https://ifconfig.co/ip 2>/dev/null | tr -d '[:space:]' || true)"
  elif cmd_exists wget; then
    ip="$(wget -qO- --timeout=5 https://api.ipify.org 2>/dev/null || true)"
  fi
  printf '%s' "$ip"
}

pick_domain_interactive() {
  local c d
  while true; do
    echo "Выберите домен для FakeTLS/SNI:"
    echo "1) www.google.com"
    echo "2) www.youtube.com"
    echo "3) www.microsoft.com"
    echo "4) www.cloudflare.com"
    echo "5) ya.ru"
    echo "6) yandex.ru"
    echo "7) Свой домен"
    echo
    c="$(read_nav "Ваш выбор [1]: ")"
    is_nav_back "$c" && return 1
    is_nav_main "$c" && return 10
    [[ -z "$c" ]] && c="1"
    case "$c" in
      1) DOMAIN="www.google.com"; break ;;
      2) DOMAIN="www.youtube.com"; break ;;
      3) DOMAIN="www.microsoft.com"; break ;;
      4) DOMAIN="www.cloudflare.com"; break ;;
      5) DOMAIN="ya.ru"; break ;;
      6) DOMAIN="yandex.ru"; break ;;
      7)
        d="$(read_nav "Введите домен без https://: ")"
        is_nav_back "$d" && return 1
        is_nav_main "$d" && return 10
        if valid_domain "$d"; then DOMAIN="$d"; break; else warn "Неверный домен."; fi
        ;;
      *) warn "Неверный выбор." ;;
    esac
  done
}

ensure_config_interactive() {
  conf_load
  local value ans

  value="$(read_nav "Публичный порт [Enter = ${PUBLIC_PORT:-$DEFAULT_PUBLIC_PORT}]: ")"
  is_nav_back "$value" && return 1
  is_nav_main "$value" && return 10
  [[ -n "$value" ]] && PUBLIC_PORT="$value"
  if ! valid_port "$PUBLIC_PORT"; then warn "Неверный порт."; return 1; fi
  if ! port_free "$PUBLIC_PORT"; then warn "Порт $PUBLIC_PORT уже слушает другой процесс. Docker может не стартовать."; fi

  value="$(read_nav "Внутренний порт контейнера [Enter = ${INTERNAL_PORT:-$DEFAULT_INTERNAL_PORT}]: ")"
  is_nav_back "$value" && return 1
  is_nav_main "$value" && return 10
  [[ -n "$value" ]] && INTERNAL_PORT="$value"
  valid_port "$INTERNAL_PORT" || { warn "Неверный внутренний порт."; return 1; }

  value="$(read_nav "Concurrency [Enter = ${CONCURRENCY:-$DEFAULT_CONCURRENCY}]: ")"
  is_nav_back "$value" && return 1
  is_nav_main "$value" && return 10
  [[ -n "$value" ]] && CONCURRENCY="$value"
  valid_number_range "$CONCURRENCY" 16 2000000 || { warn "Concurrency должен быть числом от 16 до 2000000."; return 1; }

  pick_domain_interactive || return $?
  SECRET="$(make_secret_for_domain "$DOMAIN")"

  echo
  echo "Domain-fronting fallback host обычно оставляют пустым."
  echo "Если DNS домена ведёт обратно на этот сервер или нужен отдельный backend, укажите host/IP."
  value="$(read_nav "Fallback host [Enter = пусто]: ")"
  is_nav_back "$value" && return 1
  is_nav_main "$value" && return 10
  DOMAIN_FRONTING_HOST="$value"

  echo
  echo "Outbound SOCKS5 chain — если нужно отправлять исходящие подключения mtg через другой SOCKS5."
  echo "Формат: socks5://user:pass@host:port или socks5://host:port"
  value="$(read_nav "Outbound SOCKS5 [Enter = нет]: ")"
  is_nav_back "$value" && return 1
  is_nav_main "$value" && return 10
  OUTBOUND_PROXY="$value"

  ans="$(read_nav "Включить внешний blocklist FireHOL? Может мешать тестам из LAN. [y/N]: ")"
  is_nav_back "$ans" && return 1
  is_nav_main "$ans" && return 10
  case "${ans,,}" in y|yes|д|да) BLOCKLIST_ENABLED="true" ;; *) BLOCKLIST_ENABLED="false" ;; esac

  DEBUG="false"
  IMAGE="${IMAGE:-$DEFAULT_IMAGE}"
  conf_save
  write_mtg_config
}

start_proxy() {
  require_root
  ensure_base_tools
  ensure_docker
  header
  ensure_config_interactive || return $?
  conf_load
  write_mtg_config

  if container_exists; then
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi

  info "Скачиваю Docker-образ: $IMAGE"
  docker pull "$IMAGE"

  docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${PUBLIC_PORT}:${INTERNAL_PORT}/tcp" \
    -p "127.0.0.1:${METRICS_PORT}:${METRICS_PORT}/tcp" \
    -v "${MTG_CONFIG}:/config.toml:ro" \
    --log-opt max-size=20m \
    --log-opt max-file=3 \
    "$IMAGE" run /config.toml >/dev/null

  open_firewall "$PUBLIC_PORT"
  ok "MTProto/FakeTLS proxy запущен."
  show_link
  pause
}

restart_proxy() {
  require_root
  ensure_docker
  header
  conf_load
  if [[ -z "$SECRET" ]]; then
    warn "Конфиг не найден. Сначала создайте прокси."
    pause
    return 0
  fi
  write_mtg_config
  if container_exists; then docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true; fi
  docker pull "$IMAGE" >/dev/null || true
  docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${PUBLIC_PORT}:${INTERNAL_PORT}/tcp" \
    -p "127.0.0.1:${METRICS_PORT}:${METRICS_PORT}/tcp" \
    -v "${MTG_CONFIG}:/config.toml:ro" \
    --log-opt max-size=20m \
    --log-opt max-file=3 \
    "$IMAGE" run /config.toml >/dev/null
  open_firewall "$PUBLIC_PORT"
  ok "Прокси перезапущен."
  show_link
  pause
}

stop_proxy() {
  require_root
  ensure_docker
  header
  if container_running; then
    docker stop "$CONTAINER_NAME" >/dev/null
    ok "Контейнер остановлен."
  else
    warn "Контейнер не запущен."
  fi
  pause
}

show_link() {
  conf_load
  if [[ -z "$SECRET" ]]; then
    warn "Прокси ещё не настроен."
    return 0
  fi
  local ip="$(get_public_ip)"
  local server="${ip:-ВАШ_IP}"
  local enc_secret="$(urlencode "$SECRET")"
  echo
  echo "Данные подключения Telegram MTProto:"
  echo "Server : $server"
  echo "Port   : $PUBLIC_PORT"
  echo "Secret : $SECRET"
  echo "SNI    : ${DOMAIN:-$(secret_domain "$SECRET" || true)}"
  [[ -n "$DOMAIN_FRONTING_HOST" ]] && echo "Fallback host: $DOMAIN_FRONTING_HOST"
  [[ -n "$OUTBOUND_PROXY" ]] && echo "Outbound chain: $OUTBOUND_PROXY"
  echo
  echo "tg:// link:"
  echo "tg://proxy?server=${server}&port=${PUBLIC_PORT}&secret=${enc_secret}"
  echo
  echo "t.me link:"
  echo "https://t.me/proxy?server=${server}&port=${PUBLIC_PORT}&secret=${enc_secret}"
  echo
  if container_running; then
    echo "mtg access output:"
    docker exec "$CONTAINER_NAME" /mtg access -p "$PUBLIC_PORT" -i "$server" /config.toml 2>/dev/null || true
  fi
}

status_proxy() {
  require_root
  ensure_docker
  header
  conf_load
  echo "Container:"
  docker ps -a --filter "name=^/${CONTAINER_NAME}$" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || true
  echo
  echo "Config: $CONF_FILE"
  echo "MTG TOML: $MTG_CONFIG"
  echo "IMAGE=$IMAGE"
  echo "PUBLIC_PORT=$PUBLIC_PORT"
  echo "INTERNAL_PORT=$INTERNAL_PORT"
  echo "METRICS_PORT=$METRICS_PORT"
  echo "DOMAIN=$DOMAIN"
  echo "CONCURRENCY=$CONCURRENCY"
  echo "PREFER_IP=$PREFER_IP"
  [[ -n "$OUTBOUND_PROXY" ]] && echo "OUTBOUND_PROXY=$OUTBOUND_PROXY"
  echo
  if container_running; then
    info "Prometheus metrics sample:"
    curl -fsS --max-time 3 "http://127.0.0.1:${METRICS_PORT}/" 2>/dev/null | head -n 30 || warn "Метрики не ответили."
  fi
  pause
}

logs_proxy() {
  require_root
  ensure_docker
  header
  if container_exists; then
    docker logs --tail=160 "$CONTAINER_NAME" || true
  else
    warn "Контейнер не найден."
  fi
  pause
}

change_domain_secret() {
  require_root
  header
  conf_load
  pick_domain_interactive || return $?
  SECRET="$(make_secret_for_domain "$DOMAIN")"
  conf_save
  write_mtg_config
  ok "Домен и secret обновлены. Ссылка изменилась — старую нужно заменить в Telegram."
  restart_proxy
}

change_ports() {
  require_root
  header
  conf_load
  local old_port="$PUBLIC_PORT" value
  value="$(read_nav "Новый публичный порт [текущий ${PUBLIC_PORT}]: ")"
  is_nav_back "$value" && return 0
  is_nav_main "$value" && return 10
  [[ -n "$value" ]] && PUBLIC_PORT="$value"
  valid_port "$PUBLIC_PORT" || { warn "Неверный порт."; pause; return 0; }

  value="$(read_nav "Новый metrics port localhost [текущий ${METRICS_PORT}]: ")"
  is_nav_back "$value" && return 0
  is_nav_main "$value" && return 10
  [[ -n "$value" ]] && METRICS_PORT="$value"
  valid_port "$METRICS_PORT" || { warn "Неверный metrics port."; pause; return 0; }

  close_firewall_iptables_only "$old_port"
  conf_save
  write_mtg_config
  ok "Порты сохранены. Выполняю перезапуск."
  restart_proxy
}

set_outbound_chain() {
  require_root
  header
  conf_load
  echo "Текущий outbound SOCKS5: ${OUTBOUND_PROXY:-нет}"
  echo "Формат: socks5://user:pass@host:port или socks5://host:port"
  local value="$(read_nav "Новый outbound SOCKS5 [пусто = отключить]: ")"
  is_nav_back "$value" && return 0
  is_nav_main "$value" && return 10
  OUTBOUND_PROXY="$value"
  conf_save
  write_mtg_config
  ok "Настройка сохранена. Перезапустите прокси для применения."
  pause
}

update_image() {
  require_root
  ensure_docker
  header
  conf_load
  echo "Текущий образ: $IMAGE"
  echo "1) Оставить текущий и docker pull"
  echo "2) nineseconds/mtg:2.2.8 (пин стабильной версии)"
  echo "3) nineseconds/mtg:stable"
  echo "4) nineseconds/mtg:latest"
  echo "5) Ввести свой образ"
  local c="$(read_nav "Ваш выбор [1]: ")"
  is_nav_back "$c" && return 0
  is_nav_main "$c" && return 10
  [[ -z "$c" ]] && c=1
  case "$c" in
    1) : ;;
    2) IMAGE="nineseconds/mtg:2.2.8" ;;
    3) IMAGE="nineseconds/mtg:stable" ;;
    4) IMAGE="nineseconds/mtg:latest" ;;
    5) IMAGE="$(read_nav "Docker image: ")" ;;
    *) warn "Неверный выбор."; pause; return 0 ;;
  esac
  conf_save
  docker pull "$IMAGE"
  ok "Образ обновлён/сохранён. Для применения выполните перезапуск."
  pause
}

doctor() {
  require_root
  header
  conf_load
  echo "1) ОС и ядро"
  uname -a || true
  echo
  echo "2) Время"
  date -u || true
  timedatectl 2>/dev/null | sed -n '1,8p' || true
  echo
  echo "3) Публичный IP"
  echo "$(get_public_ip)"
  echo
  echo "4) Слушающие TCP-порты"
  ss -lntp 2>/dev/null | grep -E "(:${PUBLIC_PORT}|:${METRICS_PORT}|:${INTERNAL_PORT})" || true
  echo
  echo "5) Docker"
  docker --version 2>/dev/null || true
  docker ps -a --filter "name=^/${CONTAINER_NAME}$" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true
  echo
  echo "6) Проверка TOML через контейнер"
  if [[ -f "$MTG_CONFIG" ]]; then
    docker run --rm -v "${MTG_CONFIG}:/config.toml:ro" "$IMAGE" check /config.toml 2>&1 || true
  else
    warn "Файл $MTG_CONFIG не найден."
  fi
  echo
  echo "7) Последние логи"
  docker logs --tail=80 "$CONTAINER_NAME" 2>/dev/null || true
  pause
}

install_shortcut() {
  require_root
  local src
  src="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  cp "$src" "$BIN_PATH"
  chmod +x "$BIN_PATH"
  ok "Команда установлена: mtpm"
  pause
}

uninstall_all() {
  require_root
  ensure_docker
  header
  warn "Будут удалены контейнер, конфиг, forwarding services и shortcut mtpm. Docker-образ не удаляется."
  local ans="$(read_nav "Введите YES для подтверждения: ")"
  is_nav_back "$ans" && return 0
  is_nav_main "$ans" && return 10
  if [[ "$ans" == "YES" ]]; then
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    if [[ -d "$FORWARD_DIR" ]]; then
      for f in "$FORWARD_DIR"/*.env; do
        [[ -e "$f" ]] || continue
        # shellcheck disable=SC1090
        source "$f" || true
        [[ -n "${LOCAL_PORT:-}" ]] && systemctl disable --now "mtpm-forward-${LOCAL_PORT}.service" >/dev/null 2>&1 || true
        [[ -n "${LOCAL_PORT:-}" ]] && rm -f "/etc/systemd/system/mtpm-forward-${LOCAL_PORT}.service"
      done
    fi
    rm -f /etc/systemd/system/mtpm-iptables-forward.service "$CONF_DIR/iptables-forward.sh"
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf "$CONF_DIR" "$BIN_PATH"
    ok "Удалено."
  else
    warn "Отменено."
  fi
  pause
}

ensure_socat() {
  cmd_exists socat && return 0
  warn "socat не найден. Устанавливаю."
  pkg_install socat
}

create_socat_forward() {
  require_root
  ensure_base_tools
  ensure_socat
  header
  local lport rhost rport unit envf
  lport="$(read_nav "Локальный порт на этом сервере [443]: ")"
  is_nav_back "$lport" && return 0
  is_nav_main "$lport" && return 10
  [[ -z "$lport" ]] && lport=443
  valid_port "$lport" || { warn "Неверный локальный порт."; pause; return 0; }

  rhost="$(read_nav "IP/домен сервера назначения (например, Германия): ")"
  is_nav_back "$rhost" && return 0
  is_nav_main "$rhost" && return 10
  [[ -n "$rhost" ]] || { warn "Назначение не задано."; pause; return 0; }

  rport="$(read_nav "Порт назначения [443]: ")"
  is_nav_back "$rport" && return 0
  is_nav_main "$rport" && return 10
  [[ -z "$rport" ]] && rport=443
  valid_port "$rport" || { warn "Неверный порт назначения."; pause; return 0; }

  ensure_dirs
  unit="/etc/systemd/system/mtpm-forward-${lport}.service"
  envf="$FORWARD_DIR/${lport}.env"
  cat > "$envf" <<EOF_ENV
TYPE=socat
LOCAL_PORT=$(q "$lport")
REMOTE_HOST=$(q "$rhost")
REMOTE_PORT=$(q "$rport")
EOF_ENV
  chmod 600 "$envf"

  cat > "$unit" <<EOF_UNIT
[Unit]
Description=MT Photo Manager TCP forward ${lport} to ${rhost}:${rport}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/socat -d -d TCP-LISTEN:${lport},fork,reuseaddr,bind=0.0.0.0 TCP:${rhost}:${rport}
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF_UNIT
  systemctl daemon-reload
  systemctl enable --now "mtpm-forward-${lport}.service"
  open_firewall "$lport"
  ok "TCP forward включён: 0.0.0.0:${lport} -> ${rhost}:${rport}"
  pause
}

list_forwards() {
  require_root
  header
  echo "socat/systemd forwards:"
  if [[ -d "$FORWARD_DIR" ]]; then
    for f in "$FORWARD_DIR"/*.env; do
      [[ -e "$f" ]] || continue
      TYPE="" LOCAL_PORT="" REMOTE_HOST="" REMOTE_PORT=""
      # shellcheck disable=SC1090
      source "$f" || true
      [[ "${TYPE:-}" == "socat" ]] || continue
      printf '%s -> %s:%s  ' "$LOCAL_PORT" "$REMOTE_HOST" "$REMOTE_PORT"
      systemctl is-active "mtpm-forward-${LOCAL_PORT}.service" 2>/dev/null || true
    done
  fi
  echo
  echo "iptables DNAT rules managed by mtpm:"
  [[ -f "$CONF_DIR/iptables-rules.env" ]] && cat "$CONF_DIR/iptables-rules.env" || echo "нет"
  echo
  systemctl status mtpm-iptables-forward.service --no-pager 2>/dev/null | sed -n '1,12p' || true
  pause
}

remove_socat_forward() {
  require_root
  header
  local lport="$(read_nav "Какой локальный порт удалить: ")"
  is_nav_back "$lport" && return 0
  is_nav_main "$lport" && return 10
  valid_port "$lport" || { warn "Неверный порт."; pause; return 0; }
  systemctl disable --now "mtpm-forward-${lport}.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/mtpm-forward-${lport}.service" "$FORWARD_DIR/${lport}.env"
  systemctl daemon-reload >/dev/null 2>&1 || true
  ok "Forward на порту ${lport} удалён."
  pause
}

ensure_iptables() {
  cmd_exists iptables && return 0
  warn "iptables не найден. Устанавливаю."
  pkg_install iptables
}

write_iptables_forward_script() {
  ensure_dirs
  cat > "$CONF_DIR/iptables-forward.sh" <<'EOF_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
CONF_DIR="/etc/mt-photo-manager"
RULES="$CONF_DIR/iptables-rules.env"
ACTION="${1:-start}"
[[ -f "$RULES" ]] || exit 0
while IFS='|' read -r lport rip rport; do
  [[ -z "${lport:-}" || "${lport:0:1}" == "#" ]] && continue
  case "$ACTION" in
    start)
      sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
      iptables -w -t nat -C PREROUTING -p tcp --dport "$lport" -j DNAT --to-destination "${rip}:${rport}" 2>/dev/null || iptables -w -t nat -A PREROUTING -p tcp --dport "$lport" -j DNAT --to-destination "${rip}:${rport}"
      iptables -w -t nat -C POSTROUTING -p tcp -d "$rip" --dport "$rport" -j MASQUERADE 2>/dev/null || iptables -w -t nat -A POSTROUTING -p tcp -d "$rip" --dport "$rport" -j MASQUERADE
      iptables -w -C FORWARD -p tcp -d "$rip" --dport "$rport" -j ACCEPT 2>/dev/null || iptables -w -A FORWARD -p tcp -d "$rip" --dport "$rport" -j ACCEPT
      iptables -w -C FORWARD -p tcp -s "$rip" --sport "$rport" -j ACCEPT 2>/dev/null || iptables -w -A FORWARD -p tcp -s "$rip" --sport "$rport" -j ACCEPT
      ;;
    stop)
      while iptables -w -t nat -D PREROUTING -p tcp --dport "$lport" -j DNAT --to-destination "${rip}:${rport}" 2>/dev/null; do :; done
      while iptables -w -t nat -D POSTROUTING -p tcp -d "$rip" --dport "$rport" -j MASQUERADE 2>/dev/null; do :; done
      while iptables -w -D FORWARD -p tcp -d "$rip" --dport "$rport" -j ACCEPT 2>/dev/null; do :; done
      while iptables -w -D FORWARD -p tcp -s "$rip" --sport "$rport" -j ACCEPT 2>/dev/null; do :; done
      ;;
  esac
done < "$RULES"
EOF_SCRIPT
  chmod +x "$CONF_DIR/iptables-forward.sh"
}

create_iptables_service() {
  cat > /etc/systemd/system/mtpm-iptables-forward.service <<EOF_UNIT
[Unit]
Description=MT Photo Manager iptables TCP forwarding
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${CONF_DIR}/iptables-forward.sh start
ExecStop=${CONF_DIR}/iptables-forward.sh stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_UNIT
  systemctl daemon-reload
  systemctl enable mtpm-iptables-forward.service >/dev/null 2>&1 || true
}

create_iptables_forward() {
  require_root
  ensure_base_tools
  ensure_iptables
  header
  warn "iptables DNAT быстрее socat, но требует IPv4-адрес назначения и может конфликтовать с UFW/панелью хостера."
  local lport rip rport
  lport="$(read_nav "Локальный порт на этом сервере [443]: ")"
  is_nav_back "$lport" && return 0
  is_nav_main "$lport" && return 10
  [[ -z "$lport" ]] && lport=443
  valid_port "$lport" || { warn "Неверный локальный порт."; pause; return 0; }

  rip="$(read_nav "IPv4 сервера назначения: ")"
  is_nav_back "$rip" && return 0
  is_nav_main "$rip" && return 10
  valid_ipv4 "$rip" || { warn "Нужен именно IPv4, не домен."; pause; return 0; }

  rport="$(read_nav "Порт назначения [443]: ")"
  is_nav_back "$rport" && return 0
  is_nav_main "$rport" && return 10
  [[ -z "$rport" ]] && rport=443
  valid_port "$rport" || { warn "Неверный порт назначения."; pause; return 0; }

  ensure_dirs
  touch "$CONF_DIR/iptables-rules.env"
  grep -vE "^${lport}\|" "$CONF_DIR/iptables-rules.env" > "$CONF_DIR/iptables-rules.env.tmp" || true
  mv "$CONF_DIR/iptables-rules.env.tmp" "$CONF_DIR/iptables-rules.env"
  echo "${lport}|${rip}|${rport}" >> "$CONF_DIR/iptables-rules.env"
  chmod 600 "$CONF_DIR/iptables-rules.env"
  write_iptables_forward_script
  create_iptables_service
  systemctl restart mtpm-iptables-forward.service
  open_firewall "$lport"
  ok "iptables DNAT включён: 0.0.0.0:${lport} -> ${rip}:${rport}"
  pause
}

remove_iptables_forward() {
  require_root
  header
  local lport="$(read_nav "Какой локальный порт удалить из iptables DNAT: ")"
  is_nav_back "$lport" && return 0
  is_nav_main "$lport" && return 10
  valid_port "$lport" || { warn "Неверный порт."; pause; return 0; }
  if [[ -f "$CONF_DIR/iptables-rules.env" ]]; then
    systemctl stop mtpm-iptables-forward.service >/dev/null 2>&1 || true
    grep -vE "^${lport}\|" "$CONF_DIR/iptables-rules.env" > "$CONF_DIR/iptables-rules.env.tmp" || true
    mv "$CONF_DIR/iptables-rules.env.tmp" "$CONF_DIR/iptables-rules.env"
    write_iptables_forward_script
    systemctl start mtpm-iptables-forward.service >/dev/null 2>&1 || true
  fi
  ok "iptables DNAT для порта ${lport} удалён."
  pause
}

forward_menu() {
  local c rc
  while true; do
    header
    echo "Раздел перенаправления TCP"
    echo "1) Создать простое перенаправление через socat (надёжный вариант)"
    echo "2) Создать iptables DNAT forwarding (быстрее, IPv4 only)"
    echo "3) Показать forwarding rules"
    echo "4) Удалить socat forwarding"
    echo "5) Удалить iptables DNAT forwarding"
    echo "0) Назад"
    echo
    c="$(read_nav "Ваш выбор: ")"
    c="$(trim "$c")"
    rc=0
    case "$c" in
      1) create_socat_forward || rc=$? ;;
      2) create_iptables_forward || rc=$? ;;
      3) list_forwards || rc=$? ;;
      4) remove_socat_forward || rc=$? ;;
      5) remove_iptables_forward || rc=$? ;;
      0|"$MSG_BACK") return 0 ;;
      "$MSG_MAIN") return 10 ;;
      *) warn "Неверный выбор."; pause ;;
    esac
    [[ "$rc" -eq 10 ]] && return 10
  done
}

main_menu() {
  require_root
  local c rc
  while true; do
    header
    conf_load
    echo "1) Создать/запустить MTProto Proxy с FakeTLS"
    echo "2) Остановить"
    echo "3) Перезапустить"
    echo "4) Статус и метрики"
    echo "5) Показать ссылку для Telegram"
    echo "6) Сменить FakeTLS домен и secret"
    echo "7) Изменить порты"
    echo "8) Настроить outbound SOCKS5 chain"
    echo "9) Логи"
    echo "10) Обновить/сменить Docker-образ"
    echo "11) Диагностика"
    echo "12) Перенаправление TCP: РФ сервер -> Германия/другой сервер"
    echo "13) Установить команду mtpm"
    echo "14) Удалить всё"
    echo "0) Выход"
    echo
    echo -e "${DIM}Порт: ${PUBLIC_PORT:-не задан}, домен: ${DOMAIN:-не задан}, image: ${IMAGE:-$DEFAULT_IMAGE}${RESET}"
    echo
    c="$(read_nav "Ваш выбор: ")"
    c="$(trim "$c")"
    rc=0
    case "$c" in
      1) start_proxy || rc=$? ;;
      2) stop_proxy || rc=$? ;;
      3) restart_proxy || rc=$? ;;
      4) status_proxy || rc=$? ;;
      5) header; show_link; pause ;;
      6) change_domain_secret || rc=$? ;;
      7) change_ports || rc=$? ;;
      8) set_outbound_chain || rc=$? ;;
      9) logs_proxy || rc=$? ;;
      10) update_image || rc=$? ;;
      11) doctor || rc=$? ;;
      12) forward_menu || rc=$? ;;
      13) install_shortcut || rc=$? ;;
      14) uninstall_all || rc=$? ;;
      0|"$MSG_BACK") exit 0 ;;
      "$MSG_MAIN") continue ;;
      *) warn "Неверный выбор."; pause ;;
    esac
    [[ "$rc" -eq 10 ]] && continue
  done
}

case "${1:-}" in
  start) start_proxy ;;
  restart) restart_proxy ;;
  stop) stop_proxy ;;
  status) status_proxy ;;
  link) require_root; show_link ;;
  logs) logs_proxy ;;
  doctor) doctor ;;
  forward) forward_menu ;;
  install) install_shortcut ;;
  *) main_menu ;;
esac
