# ====== Pretty UI helpers ======
# (терминал может быть без цветов — тогда будет просто текст)

supports_color() {
  [[ -t 1 ]] || return 1
  command -v tput >/dev/null 2>&1 || return 1
  [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]
}

init_colors() {
  if supports_color; then
    BOLD="$(tput bold)"
    DIM="$(tput dim)"
    RESET="$(tput sgr0)"
    RED="$(tput setaf 1)"
    GREEN="$(tput setaf 2)"
    YELLOW="$(tput setaf 3)"
    BLUE="$(tput setaf 4)"
    MAGENTA="$(tput setaf 5)"
    CYAN="$(tput setaf 6)"
    GRAY="$(tput setaf 7)"
  else
    BOLD=""; DIM=""; RESET=""
    RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; GRAY=""
  fi
}

term_width() {
  local w
  w="$(tput cols 2>/dev/null || echo 80)"
  (( w < 60 )) && w=60
  echo "$w"
}

hr() {
  local w ch
  w="$(term_width)"
  ch="${1:-─}"
  printf "%*s\n" "$w" "" | tr " " "$ch"
}

center() {
  local w text
  w="$(term_width)"
  text="$1"
  # центрируем по ширине, без учета цвета (окей для простых заголовков)
  local len=${#text}
  if (( len >= w )); then
    echo "$text"
  else
    local pad=$(( (w - len) / 2 ))
    printf "%*s%s\n" "$pad" "" "$text"
  fi
}

clear_screen() {
  command -v clear >/dev/null 2>&1 && clear || printf "\n\n"
}

pause() {
  echo
  read -r -p "Нажмите Enter чтобы продолжить... " _ 2>/dev/null || true
}

safe_read() {
  # safe_read "prompt" varname
  local prompt="$1"
  local __var="$2"
  local ans=""
  read -r -p "$prompt" ans 2>/dev/null || ans=""
  printf -v "$__var" "%s" "$ans"
}

status_block() {
  local WAN_IF="$1"
  local rules_count="0"
  if [[ -f "$STATE_FILE" ]]; then
    # считаем только "валидные" строки (не пустые и не комментарии)
    rules_count="$(awk 'NF && $1 !~ /^#/' "$STATE_FILE" 2>/dev/null | wc -l | tr -d ' ')"
  fi

  echo "${DIM}Интерфейс WAN:${RESET} ${BOLD}${CYAN}${WAN_IF}${RESET}"
  echo "${DIM}Файл правил:${RESET} ${BOLD}${STATE_FILE}${RESET}"
  echo "${DIM}Цепочки:${RESET} nat/${BOLD}${CHAIN_NAT}${RESET}, filter/${BOLD}${CHAIN_FWD}${RESET}"
  echo "${DIM}Правил в состоянии:${RESET} ${BOLD}${GREEN}${rules_count}${RESET}"
}

header() {
  local title="$1"
  clear_screen
  hr "═"
  center "${BOLD}${MAGENTA}${title}${RESET}"
  hr "═"
}

menu_box() {
  # просто красивое меню
  echo
  echo "${BOLD}Выберите действие:${RESET}"
  echo "  ${BOLD}${CYAN}1${RESET}) ➕ Добавить правило"
  echo "  ${BOLD}${CYAN}2${RESET}) 🗑  Удалить правило"
  echo "  ${BOLD}${CYAN}3${RESET}) 📋 Показать правила"
  echo "  ${BOLD}${CYAN}4${RESET}) 🔄 Применить правила заново"
  echo "  ${BOLD}${CYAN}0${RESET}) 🚪 Выход"
  echo
}

error_msg() { echo "${RED}Ошибка:${RESET} $*" >&2; }
ok_msg()    { echo "${GREEN}OK:${RESET} $*"; }
info_msg()  { echo "${CYAN}ℹ${RESET} $*"; }

# ====== Replace main_menu with this ======
main_menu() {
  require_root
  ensure_prereqs
  init_state
  init_colors

  local WAN_IF
  WAN_IF="$(detect_wan_if)"

  # применим правила при старте (как и было)
  apply_rules "$WAN_IF" >/dev/null 2>&1 || true

  # ловим Ctrl+C чтобы не вылетать “грязно”
  trap 'echo; info_msg "Выход."; exit 0' INT

  while true; do
    header "Redirect Manager"
    status_block "$WAN_IF"
    hr "─"

    menu_box
    local c
    safe_read "Введите пункт (0-4): " c
    c="${c//[[:space:]]/}"

    case "$c" in
      1)
        header "Добавление правила"
        status_block "$WAN_IF"
        hr "─"
        add_rule "$WAN_IF"
        pause
        ;;
      2)
        header "Удаление правила"
        status_block "$WAN_IF"
        hr "─"
        delete_rule "$WAN_IF"
        pause
        ;;
      3)
        header "Список правил"
        status_block "$WAN_IF"
        hr "─"
        print_rules
        pause
        ;;
      4)
        header "Применение правил"
        status_block "$WAN_IF"
        hr "─"
        if apply_rules "$WAN_IF"; then
          ok_msg "Правила применены."
        else
          error_msg "Не удалось применить правила (проверь iptables)."
        fi
        pause
        ;;
      0|"")
        info_msg "Выход."
        exit 0
        ;;
      *)
        error_msg "Неверный пункт: '$c'"
        pause
        ;;
    esac
  done
}
