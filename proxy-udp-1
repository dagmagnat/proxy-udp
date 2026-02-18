#!/bin/bash

# --- ЦВЕТА ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BLUE='\033[0;34m'
NC='\033[0m'

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR] Запустите скрипт с правами root!${NC}"
        exit 1
    fi
}

# --- ПОДГОТОВКА СИСТЕМЫ ---
prepare_system() {
    # IP Forwarding
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    else
        sed -i 's/^#\?net\.ipv4\.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    fi

    # BBR (как в исходнике)
    if ! grep -q "^net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    fi
    if ! grep -q "^net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi
    sysctl -p > /dev/null

    # Зависимости
    export DEBIAN_FRONTEND=noninteractive
    if ! dpkg -s iptables-persistent >/dev/null 2>&1; then
        apt-get update -y > /dev/null
        apt-get install -y iptables-persistent netfilter-persistent > /dev/null
    fi
}

get_iface() {
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -n1)
    if [[ -z "$iface" ]]; then
        echo -e "${RED}[ERROR] Не удалось определить внешний интерфейс!${NC}"
        exit 1
    fi
    echo "$iface"
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    for o in "$o1" "$o2" "$o3" "$o4"; do
        if (( o < 0 || o > 255 )); then return 1; fi
    done
    return 0
}

# --- ИНСТРУКЦИЯ ---
show_instructions() {
    clear
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║                 📚 ИНСТРУКЦИЯ: КАК ПОЛЬЗОВАТЬСЯ              ║${NC}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Скрипт делает порт-форвардинг (DNAT) через этот VPS:${NC}"
    echo -e "Клиент -> ${YELLOW}Этот VPS${NC} -> Назначение (${YELLOW}TARGET_IP${NC})"
    echo ""
    echo -e "${CYAN}Обычный режим:${NC}"
    echo -e "1) Выберите пункт (UDP или TCP)."
    echo -e "2) Введите IP назначения (или 0 назад)."
    echo -e "3) Введите один или несколько портов через пробел (или 0 назад)."
    echo -e "   Пример: ${YELLOW}51820 443${NC}"
    echo ""
    echo -e "${CYAN}AntiZapret:${NC}"
    echo -e "Вводите IP назначения (или 0 назад), выбираете UDP/TCP — порты добавятся автоматически."
    echo ""
    read -p "Нажмите Enter, чтобы вернуться в меню..."
}

# --- ЯДРО: применить правила на набор портов ---
apply_forward_ports() {
    local PROTO="$1"
    local TARGET_IP="$2"
    local PORTS_RAW="$3"

    local IFACE
    IFACE=$(get_iface)

    # MASQUERADE (один раз)
    if ! iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
    fi

    for PORT in $PORTS_RAW; do
        # удалить возможные дубли
        iptables -t nat -D PREROUTING -p "$PROTO" --dport "$PORT" -j DNAT --to-destination "$TARGET_IP:$PORT" 2>/dev/null
        iptables -D INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT 2>/dev/null
        iptables -D FORWARD -p "$PROTO" -d "$TARGET_IP" --dport "$PORT" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
        iptables -D FORWARD -p "$PROTO" -s "$TARGET_IP" --sport "$PORT" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

        # добавить
        iptables -A INPUT -p "$PROTO" --dport "$PORT" -j ACCEPT
        iptables -t nat -A PREROUTING -p "$PROTO" --dport "$PORT" -j DNAT --to-destination "$TARGET_IP:$PORT"
        iptables -A FORWARD -p "$PROTO" -d "$TARGET_IP" --dport "$PORT" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -p "$PROTO" -s "$TARGET_IP" --sport "$PORT" -m state --state ESTABLISHED,RELATED -j ACCEPT

        # ufw (если активен)
        if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
            ufw allow "$PORT"/"$PROTO" >/dev/null
            sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
            ufw reload >/dev/null
        fi

        echo -e "${GREEN}[OK]${NC} $PROTO: $PORT -> $TARGET_IP:$PORT"
    done

    netfilter-persistent save > /dev/null
}

# --- Обычная настройка с вводом портов через пробел + 0 назад ---
configure_rule_multiports() {
    local PROTO="$1"
    local NAME="$2"

    echo -e "\n${CYAN}--- Настройка: $NAME ($PROTO) ---${NC}"
    echo -e "${YELLOW}Подсказка:${NC} введите ${WHITE}0${NC} чтобы вернуться назад."

    # IP назначения
    while true; do
        echo -e "Введите IP адрес назначения (куда пересылать) или 0 назад:"
        read -p "> " TARGET_IP

        if [[ "$TARGET_IP" == "0" ]]; then
            return
        fi

        if [[ -n "$TARGET_IP" ]] && validate_ip "$TARGET_IP"; then
            break
        fi
        echo -e "${RED}Ошибка: введите корректный IPv4 адрес.${NC}"
    done

    # Порты
    while true; do
        echo -e "Введите Порт(ы) через пробел (пример: 51820 443) или 0 назад:"
        read -p "> " PORTS_RAW

        if [[ "$PORTS_RAW" == "0" ]]; then
            return
        fi

        PORTS_RAW=$(echo "$PORTS_RAW" | xargs)
        if [[ -z "$PORTS_RAW" ]]; then
            echo -e "${RED}Ошибка: порты не указаны.${NC}"
            continue
        fi

        valid=1
        for p in $PORTS_RAW; do
            if [[ ! "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
                valid=0
                break
            fi
        done

        if (( valid == 1 )); then
            break
        else
            echo -e "${RED}Ошибка: порты должны быть числами 1..65535.${NC}"
        fi
    done

    echo -e "${YELLOW}[*] Применение правил...${NC}"
    apply_forward_ports "$PROTO" "$TARGET_IP" "$PORTS_RAW"

    echo -e "\n${GREEN}[SUCCESS] Готово! Настроено портов:$(echo " $PORTS_RAW")${NC}"
    read -p "Нажмите Enter для возврата в меню..."
}

# --- AntiZapret: IP + выбор UDP/TCP + 0 назад, порты авто ---
configure_antizapret() {
    local NAME="AmneziaWG/WireGuard AntiZapret"
    local PORTS_PRESET="50080 50443 51080 51443 52080 52443 1234 5959 35756 35757 56123 56124 5050"

    echo -e "\n${CYAN}--- Настройка: $NAME ---${NC}"
    echo -e "${YELLOW}Подсказка:${NC} введите ${WHITE}0${NC} чтобы вернуться назад."

    while true; do
        echo -e "Введите IP адрес назначения (сервер) или 0 назад:"
        read -p "> " TARGET_IP

        if [[ "$TARGET_IP" == "0" ]]; then
            return
        fi

        if [[ -n "$TARGET_IP" ]] && validate_ip "$TARGET_IP"; then
            break
        fi
        echo -e "${RED}Ошибка: введите корректный IPv4 адрес.${NC}"
    done

    local PROTO=""
    while true; do
        echo -e "Выберите протокол: 1) UDP  2) TCP  (0 назад)"
        read -p "> " pch

        case "$pch" in
            0) return ;;
            1) PROTO="udp"; break ;;
            2) PROTO="tcp"; break ;;
            *) echo -e "${RED}Введите 1, 2 или 0.${NC}" ;;
        esac
    done

    echo -e "${YELLOW}[*] Порты будут добавлены автоматически:${NC}"
    echo -e "${WHITE}$PORTS_PRESET${NC}"
    echo -e "${YELLOW}[*] Применение правил...${NC}"

    apply_forward_ports "$PROTO" "$TARGET_IP" "$PORTS_PRESET"

    echo -e "\n${GREEN}[SUCCESS] AntiZapret настроен!${NC}"
    echo -e "${GREEN}Протокол: ${WHITE}$PROTO${NC}"
    echo -e "${GREEN}Цель: ${WHITE}$TARGET_IP${NC}"
    echo -e "${GREEN}Порты: ${WHITE}$PORTS_PRESET${NC}"
    read -p "Нажмите Enter для возврата в меню..."
}

# --- СПИСОК ПРАВИЛ ---
list_active_rules() {
    echo -e "\n${CYAN}--- Активные переадресации (DNAT) ---${NC}"
    echo -e "${MAGENTA}ПОРТ\tПРОТОКОЛ\tЦЕЛЬ${NC}"

    iptables -t nat -S PREROUTING | grep "DNAT" | while read -r line ; do
        l_port=$(echo "$line" | grep -oP '(?<=--dport )\d+')
        l_proto=$(echo "$line" | grep -oP '(?<=-p )\w+')
        l_dest=$(echo "$line" | grep -oP '(?<=--to-destination )[\d\.:]+')
        if [[ -n "$l_port" ]]; then
            echo -e "$l_port\t$l_proto\t\t$l_dest"
        fi
    done

    echo ""
    read -p "Нажмите Enter..."
}

# --- УДАЛЕНИЕ ОДНОГО ПРАВИЛА ---
delete_single_rule() {
    echo -e "\n${CYAN}--- Удаление правила ---${NC}"
    declare -a RULES_LIST
    local i=1

    while read -r line; do
        l_port=$(echo "$line" | grep -oP '(?<=--dport )\d+')
        l_proto=$(echo "$line" | grep -oP '(?<=-p )\w+')
        l_dest=$(echo "$line" | grep -oP '(?<=--to-destination )[\d\.:]+')
        if [[ -n "$l_port" ]]; then
            RULES_LIST[$i]="$l_port:$l_proto:$l_dest"
            echo -e "${YELLOW}[$i]${NC} Порт: $l_port ($l_proto) -> $l_dest"
            ((i++))
        fi
    done < <(iptables -t nat -S PREROUTING | grep "DNAT")

    if [ ${#RULES_LIST[@]} -eq 0 ]; then
        echo -e "${RED}Нет активных правил.${NC}"
        read -p "Нажмите Enter..."
        return
    fi

    echo ""
    read -p "Номер правила для удаления (0 отмена): " rule_num
    if [[ "$rule_num" == "0" || -z "${RULES_LIST[$rule_num]}" ]]; then
        return
    fi

    IFS=':' read -r d_port d_proto d_dest <<< "${RULES_LIST[$rule_num]}"
    local d_ip="${d_dest%:*}"

    iptables -t nat -D PREROUTING -p "$d_proto" --dport "$d_port" -j DNAT --to-destination "$d_dest" 2>/dev/null
    iptables -D INPUT -p "$d_proto" --dport "$d_port" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -p "$d_proto" -d "$d_ip" --dport "$d_port" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -D FORWARD -p "$d_proto" -s "$d_ip" --sport "$d_port" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

    netfilter-persistent save > /dev/null
    echo -e "${GREEN}[OK] Удалено.${NC}"
    read -p "Нажмите Enter..."
}

# --- ПОЛНАЯ ОЧИСТКА ---
flush_rules() {
    echo -e "\n${RED}!!! ВНИМАНИЕ !!!${NC}"
    echo "Сброс ВСЕХ настроек iptables."
    read -p "Вы уверены? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -t nat -F
        iptables -t mangle -F
        iptables -F
        iptables -X
        netfilter-persistent save > /dev/null
        echo -e "${GREEN}[OK] Очищено.${NC}"
    fi
    read -p "Нажмите Enter..."
}

# --- МЕНЮ ---
show_menu() {
    while true; do
        clear
        echo -e "${MAGENTA}==============================================${NC}"
        echo -e "${MAGENTA}                 PROXY / DNAT                 ${NC}"
        echo -e "${MAGENTA}==============================================${NC}"
        echo ""
        echo -e "1) Настроить ${CYAN}AmneziaWG / WireGuard${NC} (UDP)"
        echo -e "2) Настроить ${CYAN}AmneziaWG / WireGuard${NC} (TCP)"
        echo -e "3) Настроить ${CYAN}VLESS / XRay${NC} (TCP)"
        echo -e "4) Настроить ${CYAN}VLESS / XRay${NC} (UDP)"
        echo -e "5) ${YELLOW}AmneziaWG/WireGuard AntiZapret${NC} (выбор UDP/TCP, порты авто)"
        echo -e "6) Посмотреть активные правила"
        echo -e "7) ${RED}Удалить одно правило${NC}"
        echo -e "8) ${RED}Сбросить ВСЕ настройки${NC}"
        echo -e "9) ${MAGENTA}📚 Инструкция${NC}"
        echo -e "0) Выход"
        echo -e "${MAGENTA}----------------------------------------------${NC}"
        read -p "Ваш выбор: " choice

        case $choice in
            1) configure_rule_multiports "udp" "AmneziaWG/WireGuard" ;;
            2) configure_rule_multiports "tcp" "AmneziaWG/WireGuard" ;;
            3) configure_rule_multiports "tcp" "VLESS/XRay" ;;
            4) configure_rule_multiports "udp" "VLESS/XRay" ;;
            5) configure_antizapret ;;
            6) list_active_rules ;;
            7) delete_single_rule ;;
            8) flush_rules ;;
            9) show_instructions ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

# --- ЗАПУСК ---
check_root
prepare_system
show_menu
