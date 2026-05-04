# Proxy UDP

[English](README.md) | [Русский](README.ru_RU.md)

`Proxy UDP` — интерактивный менеджер TCP/UDP-перенаправлений для Linux-серверов.

Несмотря на название проекта, скрипт работает не только с UDP. Он умеет создавать перенаправления для:

- только UDP;
- только TCP;
- TCP и UDP одновременно.

В этом же репозитории также находится отдельный скрипт `mtproto-manager`. Его можно устанавливать и запускать отдельно от `proxy-udp`, без создания отдельного репозитория.

---

## Что входит в репозиторий

```text
proxy-udp          # менеджер TCP/UDP-перенаправлений
mtproto-manager    # менеджер MTProto Proxy через Docker
README.md          # английская документация
README.ru_RU.md    # русская документация
```

---

## Быстрая установка

### Запуск Proxy UDP

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

Ручная установка:

```bash
wget -O /root/proxy-udp "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)"
chmod +x /root/proxy-udp
sudo /root/proxy-udp
```

### Запуск только MTProto Manager

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

Ручная установка:

```bash
wget -O /root/mtproto-manager "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)"
chmod +x /root/mtproto-manager
sudo /root/mtproto-manager
```

Параметр `?$(date +%s)` нужен, чтобы обойти возможный кеш GitHub Raw сразу после обновления файлов в репозитории.

---

## Быстрые локальные команды: `proxy-go` и `mtproto-go`

Не нужно каждый раз заходить на GitHub и копировать длинную команду установки. Один раз установите короткую локальную команду, затем запускайте менеджер одним словом.

### Установить или обновить `proxy-go`

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)") install-go
```

После этого Proxy UDP можно запускать так:

```bash
sudo proxy-go
```

Также быструю команду можно установить из меню Proxy UDP:

```text
8) Установить/обновить быструю команду proxy-go и автоприменение
```

Этот пункт также создает systemd-сервис для восстановления правил Proxy UDP после перезагрузки:

```bash
sudo systemctl status proxy-go.service
```

Применить сохраненные правила вручную:

```bash
sudo proxy-go apply
```

Посмотреть статус:

```bash
sudo proxy-go status
```

Применить сетевой тюнинг:

```bash
sudo proxy-go tune
```

### Установить или обновить `mtproto-go`

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)") install-go
```

После этого MTProto Manager можно запускать так:

```bash
sudo mtproto-go
```

Также быструю команду можно установить из меню MTProto Manager:

```text
13) Установить/обновить быструю команду mtproto-go
```

Полезные быстрые подкоманды MTProto:

```bash
sudo mtproto-go status
sudo mtproto-go logs
sudo mtproto-go restart
sudo mtproto-go stop
```

Чтобы позже обновить локальную быструю команду, повторно выполните команду `install-go` или выберите пункт установки/обновления в меню.

---

## Выбор языка

При первом запуске оба скрипта предлагают выбрать язык:

```text
1) English
2) Русский
0) Выход
```

Выбранный язык сохраняется и используется при следующих запусках.

Файлы конфигурации:

```text
/etc/proxy-udp.conf
/etc/mtproto_manager.conf
```

Сменить язык можно позже через меню:

- Proxy UDP: `Настройки и диагностика высокой нагрузки` -> `Сменить язык`;
- MTProto Manager: `Сменить язык`.

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
- Навигация в разделах меню:
  - `0` — назад;
  - `00` — главное меню.
- Интерфейс на русском и английском языке.
- Настройки и диагностика высокой нагрузки для NAT/conntrack.
- Выбор NAT-режима:
  - `SNAT` — рекомендуется для статического внешнего IPv4;
  - `MASQUERADE` — рекомендуется для динамического внешнего IPv4.
- Возможность установить команду `proxy-go` и systemd-сервис для автоприменения правил после перезагрузки.

---

## Главное меню Proxy UDP

```text
1) Создать прокси / перенаправление
2) AntizapretVPN by GubernievS — preset портов без 80/443
3) Удалить выбранные правила
4) Удалить все правила
5) Посмотреть правила
6) Проверка портов
7) Настройки и диагностика высокой нагрузки
8) Установить/обновить быструю команду proxy-go и автоприменение
0) Выход
```

---

## Preset AntizapretVPN by GubernievS

В preset добавлены порты:

```text
504 508 540 580 50080 50443 51080 51443 52080 52443
```

Порты `80` и `443` намеренно не добавляются в preset по умолчанию. Если нужны порты `80` и `443`, добавьте их вручную через:

```text
1) Создать прокси / перенаправление
```

Доступные режимы:

1. Рекомендуемый режим:
   - OpenVPN: `504`, `508`, `50080`, `50443` через TCP и UDP;
   - WireGuard / AmneziaWG: `540`, `580`, `51080`, `51443`, `52080`, `52443` через UDP.
2. Все preset-порты через TCP + UDP.
3. Все preset-порты только через UDP.
4. Все preset-порты только через TCP.

---

## Использование Proxy UDP с GubernievS/AntiZapret-VPN

Этот раздел для пользователей проекта `GubernievS/AntiZapret-VPN`, которым нужно использовать отдельный прокси-сервер перед сервером AntiZapret VPN.

Типовая схема:

```text
Клиентское устройство -> Proxy UDP сервер -> AntiZapret VPN сервер
```

### 1. Установить AntiZapret-VPN на VPN-сервер

На сервере AntiZapret VPN используйте официальную команду установки проекта AntiZapret-VPN:

```bash
bash <(wget -qO- --no-hsts --inet4-only https://raw.githubusercontent.com/GubernievS/AntiZapret-VPN/main/install.sh)
```

### 2. Установить Proxy UDP на прокси-сервер

На прокси-сервере выполните:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)")
```

Или один раз установите быструю команду:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/proxy-udp?$(date +%s)") install-go
sudo proxy-go
```

В меню выберите:

```text
2) AntizapretVPN by GubernievS — preset портов без 80/443
```

Затем введите IPv4-адрес сервера AntiZapret VPN.

### 3. Заменить адрес сервера в клиентских профилях

В клиентских профилях OpenVPN, WireGuard или AmneziaWG замените IP/домен сервера AntiZapret VPN на IP/домен прокси-сервера.

### 4. Разрешить прокси-сервер на сервере AntiZapret VPN

На сервере AntiZapret VPN добавьте IPv4-адрес прокси-сервера в файл:

```text
/root/antizapret/config/allow-ips.txt
```

Затем выполните:

```bash
/root/antizapret/parse.sh ip
```

### 5. Примечание по MTU

Если на прокси-сервере MTU меньше `1500`, уменьшите MTU в конфигурационных файлах OpenVPN и WireGuard на сервере AntiZapret VPN. Это может помочь избежать фрагментации пакетов и нестабильной работы UDP.

---

## Как работает Proxy UDP

Скрипт создает собственные цепочки iptables:

- `PROXY_UDP_NAT` в таблице `nat` для DNAT;
- `PROXY_UDP_POST` в таблице `nat` для SNAT/MASQUERADE;
- `PROXY_UDP_FWD` в таблице `filter` для FORWARD-разрешений.

Правила хранятся в файле:

```text
/etc/proxy-udp.rules
```

Формат строки:

```text
proto source_port target_ip target_port
```

Пример:

```text
udp 50080 203.0.113.10 50080
tcp 50443 203.0.113.10 50443
```

Скрипт управляет только своими цепочками `PROXY_UDP_*` и не должен удалять посторонние firewall-правила.

---

## Высокая нагрузка и зависания UDP

Если при большой скорости UDP начинает подвисать или лагать, проблема обычно не в bash-меню. Чаще всего узкое место — Linux NAT/conntrack.

В пункте меню `7) Настройки и диагностика высокой нагрузки` есть:

- применение системного тюнинга;
- просмотр `nf_conntrack_count` и `nf_conntrack_max`;
- выбор между `SNAT` и `MASQUERADE`;
- базовая диагностика сценариев с высокой нагрузкой.

Для статического внешнего IPv4 обычно лучше использовать `SNAT`. Для динамического внешнего IPv4 удобнее использовать `MASQUERADE`.

---

## Проверка портов

Пункт меню `6) Проверка портов` умеет проверять:

- уже созданные правила;
- вручную указанный IP-адрес и список портов.

Важно: TCP можно проверить достаточно надежно. UDP невозможно проверить на 100% корректно без ответа приложения. Если UDP-сервис не отвечает на probe-запрос, это не всегда значит, что порт закрыт.

Для более удобной UDP-проверки рекомендуется установить `netcat`:

```bash
apt-get update
apt-get install -y netcat-openbsd
```

---

## MTProto Manager

`mtproto-manager` — отдельный интерактивный менеджер для запуска MTProto Proxy в Docker.

Запуск MTProto Manager:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)")
```

Установить быструю команду `mtproto-go`:

```bash
bash <(wget -qO- --inet4-only "https://raw.githubusercontent.com/dagmagnat/proxy-udp/main/mtproto-manager?$(date +%s)") install-go
sudo mtproto-go
```

Основные возможности:

- создать и запустить MTProto Proxy;
- остановить и перезапустить контейнер;
- посмотреть статус прокси;
- показать ссылку для Telegram;
- изменить внешний порт;
- пересоздать secret/key;
- изменить workers;
- посмотреть Docker-логи;
- обновить Docker-образ;
- удалить контейнер и конфиг;
- интерфейс на русском и английском языке.

MTProto Manager использует Docker. Если Docker не установлен, скрипт может попробовать установить его автоматически на Debian/Ubuntu.

---

## Требования

### Для Proxy UDP

- Debian/Ubuntu или другой Linux с `iptables`.
- root-доступ.
- IPv4 forwarding.
- Для расширенной диагностики: `conntrack-tools`.
- Для UDP-проверок: `netcat-openbsd`.

### Для MTProto Manager

- Рекомендуется Debian/Ubuntu.
- root-доступ.
- Docker.
- Если Docker не установлен, менеджер попробует установить его на Debian/Ubuntu.

---

## Важно

Перед использованием firewall/NAT-скриптов на боевом сервере рекомендуется иметь аварийный доступ через rescue-консоль, VNC или serial console от хостинга. Это поможет не потерять доступ к серверу, если firewall-правило будет настроено неправильно.
