# Proxy UDP

[English](README.md) | [Русский](README.ru_RU.md)

**GitHub-логин:** `dagmagnat`  
**Репозиторий:** `proxy-udp`

`Proxy UDP` — интерактивный менеджер TCP/UDP-перенаправлений для Linux-серверов.

Несмотря на название проекта, скрипт работает не только с UDP. Он умеет создавать перенаправления для:

- только UDP;
- только TCP;
- TCP и UDP одновременно.

В этом же репозитории находится отдельный скрипт `mtproto-manager`. Для него **не нужно создавать отдельный репозиторий**.

---

## Что входит в репозиторий

```text
proxy-udp          # менеджер TCP/UDP-перенаправлений
mtproto-manager    # менеджер MTProto Proxy через Docker
README.md          # английская документация
README.ru_RU.md    # русская документация
```

---

## Быстрый запуск

### Запустить Proxy UDP один раз

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

### Запустить MTProto Manager один раз

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

Параметр `?$(date +%s)` помогает обойти кеш GitHub Raw сразу после обновления файлов в репозитории.

---

## Быстрые команды

Используйте этот вариант, если не хотите каждый раз заходить на GitHub и копировать длинную команду.

### Установить `proxy-go`

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)") install-go
```

После этого Proxy UDP можно запускать короткой командой:

```bash
sudo proxy-go
```

Полезные быстрые команды:

```bash
sudo proxy-go apply
sudo proxy-go status
sudo proxy-go tune
```

### Установить `mtproto-go`

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)") install-go
```

После этого MTProto Manager можно запускать короткой командой:

```bash
sudo mtproto-go
```

Полезные быстрые команды:

```bash
sudo mtproto-go start
sudo mtproto-go stop
sudo mtproto-go restart
sudo mtproto-go status
sudo mtproto-go logs
sudo mtproto-go link
```

---

## Ручная установка

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

## Выбор языка

При первом запуске оба скрипта предлагают выбрать язык:

```text
1) English
2) Русский
0) Выход
```

После выбора интерфейс будет работать на выбранном языке.

Язык можно изменить позже из меню скрипта.

---

## Возможности Proxy UDP

- Создание TCP/UDP-перенаправлений.
- Отдельные режимы `UDP`, `TCP` и `UDP + TCP`.
- Preset `AntizapretVPN by GubernievS` без портов `80` и `443`.
- Удаление выбранных правил.
- Удаление всех правил, которыми управляет скрипт.
- Просмотр текущих правил.
- Проверка доступности портов.
- Очистка экрана при переходах по меню.
- Цветной терминальный интерфейс с мягким зеленым акцентом.
- Навигация в меню:
  - `0` — назад;
  - `00` — главное меню.
- Настройки и диагностика высокой нагрузки для NAT/conntrack.
- Выбор NAT-режима:
  - `SNAT` — рекомендуется для статического публичного IPv4;
  - `MASQUERADE` — рекомендуется для динамического публичного IPv4.
- Установка быстрой команды `proxy-go`.

---

## Главное меню Proxy UDP

```text
1) Создать прокси / перенаправление
2) AntizapretVPN by GubernievS — preset без 80/443
3) Удалить выбранные правила
4) Удалить все правила
5) Посмотреть правила
6) Проверка портов
7) Настройки и диагностика высокой нагрузки
8) Установить/обновить proxy-go и автоприменение
0) Выход
```

---

## Preset AntizapretVPN by GubernievS

В preset добавлены порты:

```text
504 508 540 580 50080 50443 51080 51443 52080 52443
```

Порты `80` и `443` специально **не добавляются** в preset по умолчанию. Если они нужны, добавьте их вручную через:

```text
1) Создать прокси / перенаправление
```

Режимы preset:

1. Рекомендуемый режим:
   - OpenVPN: `504`, `508`, `50080`, `50443` через TCP и UDP;
   - WireGuard / AmneziaWG: `540`, `580`, `51080`, `51443`, `52080`, `52443` через UDP.
2. Все preset-порты через TCP + UDP.
3. Все preset-порты только через UDP.
4. Все preset-порты только через TCP.

---

## Использование Proxy UDP с GubernievS/AntiZapret-VPN

Этот раздел для тех, кто использует проект `GubernievS/AntiZapret-VPN` и хочет подключаться к заблокированному серверу AntiZapret через дополнительный proxy-сервер.

Общая схема:

```text
Устройство клиента -> Proxy UDP server -> AntiZapret VPN server
```

### 1. Установить AntiZapret-VPN на сервер AntiZapret

На сервере AntiZapret VPN выполните официальную команду установки:

```bash
bash <(wget -qO- --no-hsts --inet4-only https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/setup.sh)
```

### 2. Установить Proxy UDP на proxy-сервер

На proxy-сервере выполните:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

Или установите короткую команду:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)") install-go
sudo proxy-go
```

### 3. Использовать preset

В Proxy UDP выберите:

```text
2) AntizapretVPN by GubernievS — preset без 80/443
```

Когда скрипт попросит IP-адрес назначения, введите IPv4-адрес сервера AntiZapret VPN.

### 4. Изменить профили подключения клиентов

В профилях OpenVPN, WireGuard и AmneziaWG замените старый IP/домен сервера AntiZapret VPN на новый IP/домен proxy-сервера.

Пример для OpenVPN:

```text
remote OLD_ANTIZAPRET_IP 50080
remote NEW_PROXY_IP 50080
```

Пример для WireGuard/AmneziaWG:

```text
Endpoint = OLD_ANTIZAPRET_IP:51080
Endpoint = NEW_PROXY_IP:51080
```

### 5. Разрешить proxy-сервер на сервере AntiZapret

На сервере AntiZapret добавьте IPv4-адрес proxy-сервера в файл:

```text
/root/antizapret/config/allow-ips.txt
```

После этого выполните:

```bash
/root/antizapret/parse.sh ip
```

### 6. Примечание по MTU

Если на proxy-сервере MTU меньше `1500`, нужно уменьшить MTU в конфигурационных файлах OpenVPN и WireGuard/AmneziaWG.

---

## Высокая нагрузка и зависания UDP

Если при большой скорости UDP начинает подвисать, проблема обычно не в bash-меню. Чаще всего узкое место — Linux NAT/conntrack.

В Proxy UDP откройте:

```text
7) Настройки и диагностика высокой нагрузки
```

Полезные параметры:

```text
nf_conntrack_count
nf_conntrack_max
udp_timeout
udp_timeout_stream
```

Для обычного VPS со статическим публичным IPv4 обычно лучше оставить режим `SNAT` с автоматическим определением IP.

---

## MTProto Manager

`mtproto-manager` — отдельный интерактивный менеджер для запуска MTProto Proxy через Docker.

Возможности:

- создать/запустить MTProto Proxy;
- остановить/перезапустить контейнер;
- посмотреть статус;
- показать ссылку для Telegram;
- изменить внешний порт;
- пересоздать secret;
- изменить количество workers;
- посмотреть Docker-логи;
- посмотреть stats endpoint, если он доступен;
- удалить контейнер, volume и конфиг;
- установить быструю команду `mtproto-go`.

Установка:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

Установка быстрой команды:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)") install-go
sudo mtproto-go
```

---

## Требования

Рекомендуемая ОС:

- Ubuntu 22.04 / 24.04;
- Debian 12 / 13.

Для Proxy UDP нужны:

- `bash`;
- `iptables`;
- `iproute2`;
- `awk`;
- `grep`;
- `sysctl`.

Для MTProto Manager дополнительно нужен Docker. Если Docker не установлен, скрипт может попробовать установить его автоматически на Debian/Ubuntu.

---

## Важные примечания

- Запускайте скрипты от `root` или через `sudo`.
- Перед использованием на рабочем сервере лучше протестировать на отдельном VPS.
- `Proxy UDP` управляет только своими iptables-цепочками.
- Проверка UDP-портов не всегда может быть на 100% точной, потому что UDP-сервис может не возвращать ответ, даже если трафик разрешен.
