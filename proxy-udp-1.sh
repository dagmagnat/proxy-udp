#!/usr/bin/env bash
set -euo pipefail

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
  command -v mktemp >/dev/null 2>&1 || { echo "Не найден mktemp." >&2; exit 1; }
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

# меню в stderr, результат в stdout
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

# выбор фильтра удаления по протоколу
choose_delete_filter() {
  while true; do
    echo
    echo "Удалять какие правила?"
    echo "1) Только UDP"
    echo "2) Только TCP"
    echo "3) UDP и TCP (все)"
    echo "0) Назад"
    read -r -p "Ваш выбор: " sel
    case "$sel" in
      1) echo "udp"; return 0 ;;
      2) echo "tcp"; return 0 ;;
      3) echo "all"; return 0 ;;
      0) echo "back"; return 0 ;;
      *) echo "Неверный выбор." ;;
    esac
  done
}

delete_rule() {
  local WAN_IF="$1"

  if [[ ! -s "$STATE_FILE" ]]; then
    echo "Удалять нечего — правил нет."
    return 0
  fi

  # СРАЗУ: выбираем фильтр (не нужно второй раз заходить)
  local filt
  filt="$(choose_delete_filter)"
  [[ "$filt" == "back" ]] && return 0

  echo
  print_rules
  echo
  echo "0) Назад"
  echo "00) Удалить ВСЕ правила (с учетом выбранного фильтра выше)"
  echo
  read -r -p "Введите номер(а) для удаления (через пробел), или 00: " nums

  [[ "$nums" == "0" ]] && return 0

  # УДАЛИТЬ ВСЕ (00)
  if [[ "$nums" == "00" ]]; then
    if [[ "$filt" == "all" ]]; then
      : > "$STATE_FILE"
      apply_rules "$WAN_IF"
      echo "Удалены ВСЕ правила."
      return 0
    else
      # удалить только udp или только tcp
      local tmp_all
      tmp_all="$(mktemp)"
      awk -v f="$filt" '$1 != f {print $0}' "$STATE_FILE" > "$tmp_all"
      cat "$tmp_all" > "$STATE_FILE"
      rm -f "$tmp_all"
      apply_rules "$WAN_IF"
      echo "Удалены ВСЕ правила протокола: $filt"
      return 0
    fi
  fi

  [[ -z "${nums// }" ]] && { echo "Номера не указаны."; return 0; }

  # список номеров
  local filtered_nums=""
  for n in $nums; do
    if [[ "$n" =~ ^[0-9]+$ ]]; then
      filtered_nums="$filtered_nums $n"
    else
      echo "Пропускаю некорректный номер: $n"
    fi
  done
  filtered_nums="${filtered_nums# }"
  [[ -z "${filtered_nums// }" ]] && { echo "Нет валидных номеров."; return 0; }

  # удаление по номерам + фильтр
  local tmp
  tmp="$(mktemp)"
  cp "$STATE_FILE" "$tmp"

  awk -v nums="$filtered_nums" -v filt="$filt" '
    BEGIN{
      split(nums,a," ");
      for(i in a) del[a[i]]=1
    }
    {
      if(del[NR]){
        if(filt=="all"){ next }
        if($1==filt){ next }
        print $0
        next
      }
      print $0
    }
  ' "$tmp" > "$STATE_FILE"

  rm -f "$tmp"

  apply_rules "$WAN_IF"
  echo "Удаление выполнено."
}

main_menu() {
  require_root
  ensure_prereqs
  init_state

  local WAN_IF
  WAN_IF="$(detect_wan_if)"

  echo "Интерфейс (WAN): $WAN_IF"
  echo "Файл правил: $STATE_FILE"
  echo

  apply_rules "$WAN_IF"

  while true; do
    echo
    echo "Меню:"
    echo "1) Добавить"
    echo "2) Удалить"
    echo "3) Посмотреть какие есть"
    echo "0) Выход"
    read -r -p "Выберите пункт: " c

    case "$c" in
      1) add_rule "$WAN_IF" ;;
      2) delete_rule "$WAN_IF" ;;
      3) print_rules ;;
      0) exit 0 ;;
      *) echo "Неверный выбор." ;;
    esac
  done
}

main_menu
