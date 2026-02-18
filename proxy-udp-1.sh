#!/usr/bin/env bash
set -euo pipefail

# ===== Pretty UI (ASCII) =====
# Стиль как на скрине: пунктирные линии, розовый заголовок, подсветка пунктов.
# Работает в "кривых" веб-консолях (без unicode рамок).

# Цвета (ANSI)
CLR_RESET=$'\033[0m'
CLR_BOLD=$'\033[1m'
CLR_DIM=$'\033[2m'

CLR_RED=$'\033[31m'
CLR_GREEN=$'\033[32m'
CLR_YELLOW=$'\033[33m'
CLR_BLUE=$'\033[34m'
CLR_MAG=$'\033[35m'   # розово-фиолетовый
CLR_CYAN=$'\033[36m'
CLR_GRAY=$'\033[90m'

# Если нет TTY — отключаем цвета
if [[ ! -t 1 ]]; then
  CLR_RESET=""; CLR_BOLD=""; CLR_DIM=""
  CLR_RED=""; CLR_GREEN=""; CLR_YELLOW=""; CLR_BLUE=""; CLR_MAG=""; CLR_CYAN=""; CLR_GRAY=""
fi

ui_cols() { tput cols 2>/dev/null || echo 80; }

ui_repeat() { local ch="$1" n="$2"; printf "%*s" "$n" "" | tr " " "$ch"; }

ui_line_dashed() {
  # "=-" повторяется по ширине — выглядит как пунктир
  local w; w="$(ui_cols)"
  local pattern="=-"
  local out=""
  while ((${#out} < w)); do out+="$pattern"; done
  echo "${out:0:w}"
}

ui_clear() { command -v clear >/dev/null 2>&1 && clear || printf "\n"; }

ui_center() {
  local text="$1"
  local w; w="$(ui_cols)"
  local len=${#text}
  if (( len >= w )); then
    echo "$text"
  else
    local pad=$(( (w - len) / 2 ))
    printf "%*s%s\n" "$pad" "" "$text"
  fi
}

ui_header() {
  local title="$1"
  ui_clear
  echo "${CLR_MAG}$(ui_line_dashed)${CLR_RESET}"
  ui_center "${CLR_BOLD}${CLR_MAG}${title}${CLR_RESET}"
  echo "${CLR_MAG}$(ui_line_dashed)${CLR_RESET}"
  echo
}

ui_item() {
  # ui_item "1" "Текст" "accent"
  local key="$1"; shift
  local text="$1"; shift || true
  local accent="${1:-mag}"

  local color="$CLR_MAG"
  [[ "$accent" == "yellow" ]] && color="$CLR_YELLOW"
  [[ "$accent" == "green"  ]] && color="$CLR_GREEN"
  [[ "$accent" == "cyan"   ]] && color="$CLR_CYAN"
  [[ "$accent" == "red"    ]] && color="$CLR_RED"

  printf " %s) %s%s%s\n" \
    "${CLR_BOLD}${color}${key}${CLR_RESET}" \
    "${color}" "$text" "${CLR_RESET}"
}

ui_tip() {
  echo
  echo "${CLR_DIM}${CLR_GRAY}$*${CLR_RESET}"
}

ui_prompt() {
  local varname="$1"
  local ans=""
  printf "\n${CLR_BOLD}${CLR_MAG}Ваш выбор:${CLR_RESET} "
  read -r ans || ans=""
  printf -v "$varname" "%s" "$ans"
}

ui_ok()   { echo "${CLR_GREEN}${CLR_BOLD}[OK]${CLR_RESET} $*"; }
ui_warn() { echo "${CLR_YELLOW}${CLR_BOLD}[!]${CLR_RESET} $*"; }
ui_err()  { echo "${CLR_RED}${CLR_BOLD}[X]${CLR_RESET} $*" >&2; }

STATE_FILE="/etc/redirect_manager.rules"
CHAIN_NAT="REDIR_MGR"
CHAIN_FWD="REDIR_MGR_FWD"

DEFAULT_PORTS=(1234 5959 35756 35757 56123 56124 50080 50443 51080 51443 52080 52443)

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Запустите скрипт от root: sudo $0" >&2
    exit 1
  fi
}

ensure_prereqs() {
  command -v iptables >/dev/null 2>&1 || { echo "Не найден iptables. Установите iptables." >&2; exit 1; }
  command -v ip >/dev/null 2>&1 || { echo "Не найден ip (iproute2)." >&2; exit 1; }
  command -v sysctl >/dev/null 2>&1 || { echo "Не найден sysctl." >&2; exit 1; }
  command -v awk >/dev/null 2>&1 || { echo "Не найден awk." >&2; exit 1; }
  command -v nl >/dev/null 2>&1 || { echo "Не найден nl (coreutils)." >&2; exit 1; }
  command -v grep >/dev/null 2>&1 || { echo "Не найден grep." >&2; exit 1; }
}

init_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    touch "$STATE_FILE"
    chmod 600 "$STATE_FILE"
  fi
}

detect_wan_if() {
  local ifn
  ifn="$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)"
  if [[ -n "${ifn:-}" ]]; then
    echo "$ifn"
  else
    ip -br link | awk '$1 !~ /lo/ {print $1; exit}'
  fi
}

enable_ip_forward() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  fi
}

valid_ip() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o1 o2 o3 o4
  IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    ((o >= 0 && o <= 255)) || return 1
  done
  return 0
}

valid_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  ((p >= 1 && p <= 65535)) || return 1
  return 0
}

uniq_ports() {
  local in="$1"
  awk '
    {
      for(i=1;i<=NF;i++){
        if(!seen[$i]++){
          out = out (out?OFS:"") $i
        }
      }
    }
    END{ print out }
  ' <<< "$in"
}

apply_rules() {
  local WAN_IF="$1"

  enable_ip_forward

  iptables -t nat -N "$CHAIN_NAT" 2>/dev/null || true
  iptables -t nat -F "$CHAIN_NAT"

  iptables -N "$CHAIN_FWD" 2>/dev/null || true
  iptables -F "$CHAIN_FWD"

  iptables -t nat -D PREROUTING -i "$WAN_IF" -j "$CHAIN_NAT" 2>/dev/null || true
  iptables -t nat -A PREROUTING -i "$WAN_IF" -j "$CHAIN_NAT"

  iptables -D FORWARD -j "$CHAIN_FWD" 2>/dev/null || true
  iptables -A FORWARD -j "$CHAIN_FWD"

  iptables -t nat -C POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE

  while read -r proto port tip; do
    [[ -z "${proto:-}" || "${proto:0:1}" == "#" ]] && continue
    [[ -z "${port:-}" || -z "${tip:-}" ]] && continue

    iptables -t nat -A "$CHAIN_NAT" -p "$proto" --dport "$port" -j DNAT --to-destination "${tip}:${port}"

    iptables -A "$CHAIN_FWD" -p "$proto" -d "$tip" --dport "$port" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -A "$CHAIN_FWD" -p "$proto" -s "$tip" --sport "$port" -m state --state ESTABLISHED,RELATED -j ACCEPT
  done < "$STATE_FILE"
}

print_rules() {
  if [[ ! -s "$STATE_FILE" ]]; then
    echo "Правил нет."
    return
  fi
  echo "Текущие правила (proto port -> target):"
  nl -w2 -s') ' "$STATE_FILE"
}

choose_protocol_menu() {
  while true; do
    echo "" >&2
    echo "Выберите протокол:" >&2
    echo "1) UDP" >&2
    echo "2) TCP" >&2
    echo "3) UDP и TCP" >&2
    echo "0) Назад" >&2
    echo "" >&2
    read -r -p "Ваш выбор: " sel >&2

    case "$sel" in
      1) echo "udp";  return 0 ;;
      2) echo "tcp";  return 0 ;;
      3) echo "both"; return 0 ;;
      0) echo "back"; return 0 ;;
      *) echo "Неверный выбор, попробуйте снова." >&2 ;;
    esac
  done
}

add_rule() {
  local WAN_IF="$1"

  echo
  read -r -p "IP сервера назначения (куда перенаправлять) или 0 (назад): " target_ip
  [[ "$target_ip" == "0" ]] && return 0
  if ! valid_ip "$target_ip"; then
    echo "Неверный IP."
    return 0
  fi

  local proto_choice
  proto_choice="$(choose_protocol_menu)"
  [[ "$proto_choice" == "back" ]] && return 0

  local protos=()
  case "$proto_choice" in
    udp)  protos=("udp") ;;
    tcp)  protos=("tcp") ;;
    both) protos=("udp" "tcp") ;;
  esac

  echo
  echo "Порты по умолчанию:"
  echo "${DEFAULT_PORTS[*]}"
  echo

  echo "Логика:"
  echo "- Нажмите Enter: будут использованы ТОЛЬКО порты по умолчанию"
  echo "- Введите свои порты: будут использованы ТОЛЬКО ваши порты (дефолт НЕ добавляется)"
  echo
  read -r -p "Порты (через пробел) или Enter (дефолт), 0 (назад): " ports_in
  [[ "$ports_in" == "0" ]] && return 0

  local selected_ports=""
  if [[ -z "${ports_in// }" ]]; then
    selected_ports="${DEFAULT_PORTS[*]}"
  else
    selected_ports="$ports_in"
  fi

  local cleaned=""
  for p in $selected_ports; do
    if valid_port "$p"; then
      cleaned="$cleaned $p"
    else
      echo "Пропускаю некорректный порт: $p"
    fi
  done
  cleaned="${cleaned# }"

  if [[ -z "${cleaned// }" ]]; then
    echo "Не осталось валидных портов — отмена."
    return 0
  fi

  local final_ports
  final_ports="$(uniq_ports "$cleaned")"

  local added_any=0
  for p in $final_ports; do
    for pr in "${protos[@]}"; do
      if grep -qE "^${pr}[[:space:]]+${p}[[:space:]]+${target_ip}$" "$STATE_FILE"; then
        echo "Уже есть: $pr $p -> $target_ip"
      else
        echo "${pr} ${p} ${target_ip}" >> "$STATE_FILE"
        echo "Добавлено: $pr $p -> $target_ip"
        added_any=1
      fi
    done
  done

  if [[ "$added_any" -eq 1 ]]; then
    apply_rules "$WAN_IF"
    echo "Готово."
  else
    echo "Ничего не добавлено (возможно, все правила уже существовали)."
  fi
}

delete_rule() {
  local WAN_IF="$1"

  if [[ ! -s "$STATE_FILE" ]]; then
    echo "Удалять нечего — правил нет."
    return 0
  fi

  echo
  print_rules
  echo
  echo "0) Назад"
  read -r -p "Введите номер правила для удаления (можно несколько через пробел): " nums
  [[ "$nums" == "0" ]] && return 0
  [[ -z "${nums// }" ]] && { echo "Номера не указаны."; return 0; }

  local filtered=""
  for n in $nums; do
    if [[ "$n" =~ ^[0-9]+$ ]]; then
      filtered="$filtered $n"
    else
      echo "Пропускаю некорректный номер: $n"
    fi
  done
  filtered="${filtered# }"
  [[ -z "${filtered// }" ]] && { echo "Нет валидных номеров."; return 0; }

  local tmp
  tmp="$(mktemp)"
  cp "$STATE_FILE" "$tmp"

  awk -v nums="$filtered" '
    BEGIN{
      split(nums,a," ");
      for(i in a) del[a[i]]=1
    }
    { if(!del[NR]) print $0 }
  ' "$tmp" > "$STATE_FILE"

  rm -f "$tmp"

  apply_rules "$WAN_IF"
  echo "Удаление выполнено."
}

# =========================
# Pretty UI (colors + boxes)
# =========================

# =========================
# Pretty UI (colors + boxes) — UTF8/ASCII fallback
# =========================

# ANSI цвета
C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_DIM=$'\033[2m'

C_RED=$'\033[31m'
C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'
C_BLUE=$'\033[34m'
C_MAG=$'\033[35m'
C_CYAN=$'\033[36m'
C_GRAY=$'\033[90m'

# если нет TTY — отключаем цвета
if [[ ! -t 1 ]]; then
  C_RESET=""; C_BOLD=""; C_DIM=""
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAG=""; C_CYAN=""; C_GRAY=""
fi

# --- Detect UTF-8 support
is_utf8() {
  local cm=""
  cm="$(LC_ALL=${LC_ALL:-} LANG=${LANG:-} locale charmap 2>/dev/null || true)"
  [[ "${cm^^}" == *"UTF-8"* || "${cm^^}" == *"UTF8"* ]]
}

UI_UTF8=0
if is_utf8; then UI_UTF8=1; fi

# --- Charset (box drawing)
# Unicode (если терминал норм) / ASCII (если в web-консоли квадраты/▒)
if (( UI_UTF8 == 1 )); then
  B_TL="┌"; B_TR="┐"; B_BL="└"; B_BR="┘"
  B_V="│"; B_H="─"
  B_LJ="├"; B_RJ="┤"; B_TJ="┬"; B_BJ="┴"; B_X="┼"
  HR_THICK="═"
  EMOJI_OK="✔"; EMOJI_WARN="⚠"; EMOJI_ERR="✖"; EMOJI_INFO="ℹ"
  ICON_ADD="➕"; ICON_DEL="🗑"; ICON_LIST="📋"; ICON_APPLY="🔄"; ICON_EXIT="🚪"
else
  B_TL="+"; B_TR="+"; B_BL="+"; B_BR="+"
  B_V="|"; B_H="-"
  B_LJ="+"; B_RJ="+"; B_TJ="+"; B_BJ="+"; B_X="+"
  HR_THICK="="
  EMOJI_OK="OK"; EMOJI_WARN="WARN"; EMOJI_ERR="ERR"; EMOJI_INFO="INFO"
  ICON_ADD="+"; ICON_DEL="x"; ICON_LIST="*"; ICON_APPLY="~"; ICON_EXIT=">"
fi

term_cols() {
  local c
  c="$(tput cols 2>/dev/null || echo 80)"
  (( c < 60 )) && c=60
  echo "$c"
}

repeat_char() {
  local ch="$1" n="$2"
  printf "%*s" "$n" "" | tr " " "$ch"
}

line_hr() {
  local ch="${1:-$B_H}"
  repeat_char "$ch" "$(term_cols)"
  echo
}

center_text() {
  local text="$1"
  local w; w="$(term_cols)"
  local len=${#text}
  if (( len >= w )); then
    echo "$text"
  else
    local pad=$(( (w - len) / 2 ))
    printf "%*s%s\n" "$pad" "" "$text"
  fi
}

clear_ui() {
  command -v clear >/dev/null 2>&1 && clear || printf "\n\n"
}

ok()    { echo "${C_GREEN}${C_BOLD}${EMOJI_OK}${C_RESET} $*"; }
warn()  { echo "${C_YELLOW}${C_BOLD}${EMOJI_WARN}${C_RESET} $*"; }
err()   { echo "${C_RED}${C_BOLD}${EMOJI_ERR}${C_RESET} $*" >&2; }
info()  { echo "${C_CYAN}${C_BOLD}${EMOJI_INFO}${C_RESET} $*"; }

pause_ui() {
  echo
  read -r -p "${C_DIM}Нажмите Enter чтобы продолжить...${C_RESET} " _ || true
}

safe_read_ui() {
  local prompt="$1" var="$2" ans=""
  read -r -p "$prompt" ans || ans=""
  printf -v "$var" "%s" "$ans"
}

count_rules() {
  [[ -f "$STATE_FILE" ]] || { echo 0; return; }
  awk 'NF && $1 !~ /^#/' "$STATE_FILE" 2>/dev/null | wc -l | tr -d ' '
}

ui_header() {
  local title="$1"
  clear_ui
  line_hr "$HR_THICK"
  center_text "${C_BOLD}${C_MAG}${title}${C_RESET}"
  line_hr "$HR_THICK"
}

ui_box() {
  local title="$1"; shift
  local w; w="$(term_cols)"
  local inner=$(( w - 4 ))
  (( inner < 20 )) && inner=20

  echo "${C_GRAY}${B_TL}$(repeat_char "$B_H" $((w-2)))${B_TR}${C_RESET}"
  printf "${C_GRAY}${B_V}${C_RESET} ${C_BOLD}${C_CYAN}%-*s${C_RESET} ${C_GRAY}${B_V}${C_RESET}\n" "$inner" "$title"
  echo "${C_GRAY}${B_LJ}$(repeat_char "$B_H" $((w-2)))${B_RJ}${C_RESET}"

  while IFS= read -r line; do
    printf "${C_GRAY}${B_V}${C_RESET} %-*s ${C_GRAY}${B_V}${C_RESET}\n" "$inner" "$line"
  done < <(printf "%s\n" "$*")

  echo "${C_GRAY}${B_BL}$(repeat_char "$B_H" $((w-2)))${B_BR}${C_RESET}"
}

ui_status() {
  local wan="$1"
  local rules; rules="$(count_rules)"
  local now; now="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)"

  local s1="WAN: ${C_BOLD}${C_CYAN}${wan}${C_RESET}   Rules: ${C_BOLD}${C_GREEN}${rules}${C_RESET}"
  local s2="State: ${STATE_FILE}"
  local s3="Chains: nat/${CHAIN_NAT}  filter/${CHAIN_FWD}"
  local s4="Time: ${C_DIM}${now}${C_RESET}"

  ui_box "STATUS" "$s1" "$s2" "$s3" "$s4"
}

ui_menu() {
  ui_box "MENU" \
"  ${C_BOLD}${C_CYAN}1${C_RESET}) ${ICON_ADD} Add rule" \
"  ${C_BOLD}${C_CYAN}2${C_RESET}) ${ICON_DEL} Delete rule" \
"  ${C_BOLD}${C_CYAN}3${C_RESET}) ${ICON_LIST} Show rules" \
"  ${C_BOLD}${C_CYAN}4${C_RESET}) ${ICON_APPLY} Re-apply iptables" \
"  ${C_BOLD}${C_CYAN}0${C_RESET}) ${ICON_EXIT} Exit"
}

ui_section() {
  local t="$1"
  echo
  line_hr
  echo "${C_BOLD}${C_BLUE}> ${t}${C_RESET}"
  line_hr
}

main_menu() {
  require_root
  ensure_prereqs
  init_state

  local WAN_IF
  WAN_IF="$(detect_wan_if)"

  trap 'echo; warn "Остановлено пользователем (Ctrl+C)."; exit 0' INT

  if apply_rules "$WAN_IF"; then
    :
  else
    err "Не удалось применить правила при старте."
  fi

  while true; do
    ui_header "Redirect Manager — DNAT/Forward"
    ui_status "$WAN_IF"
    ui_menu

    local c
    safe_read_ui "${C_BOLD}Выберите пункт (0-4): ${C_RESET}" c
    c="${c//[[:space:]]/}"

    case "$c" in
      1)
        ui_header "Add rule"
        ui_status "$WAN_IF"
        ui_section "Добавление правила"
        add_rule "$WAN_IF"
        ok "Готово."
        pause_ui
        ;;
      2)
        ui_header "Delete rule"
        ui_status "$WAN_IF"
        ui_section "Удаление правила"
        delete_rule "$WAN_IF"
        ok "Удаление завершено."
        pause_ui
        ;;
      3)
        ui_header "Rules"
        ui_status "$WAN_IF"
        ui_section "Список правил"
        print_rules
        pause_ui
        ;;
      4)
        ui_header "Apply"
        ui_status "$WAN_IF"
        ui_section "Применение iptables"
        if apply_rules "$WAN_IF"; then
          ok "Правила применены успешно."
        else
          err "Ошибка применения iptables. Проверь iptables/nftables."
        fi
        pause_ui
        ;;
      0)
        ui_header "Exit"
        info "Выход."
        exit 0
        ;;
      "")
        warn "Пустой ввод. Выберите 0-4."
        pause_ui
        ;;
      *)
        err "Неверный пункт: '${c}'. Введите 0-4."
        pause_ui
        ;;
    esac
  done
}

main_menu
