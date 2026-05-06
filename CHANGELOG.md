# CHANGELOG

## UI / Routing / Nodes fixes

- Маршрутизация больше не включает готовые сервисы по умолчанию.
- Старые авто-дефолты маршрутизации из прошлых сборок автоматически считаются пустыми, пока владелец панели сам не сохранит правила.
- Исправлены отступы и выравнивание кнопок в клиентах, массовом удалении, поиске и действиях узлов.
- Добавлена отдельная кнопка синхронизации клиентов агрегатора на конкретный узел.
- При добавлении нового узла подпись функции синхронизации уточнена: она создаёт уже существующих клиентов агрегатора на новом inbound.
- Happ-настройки остаются выключенными по умолчанию и предназначены только для владельцев Provider ID.

## 2026-05-05 — mobile login, node import, UI cleanup

- Loading/modal windows are centered on mobile screens, including long actions like online checks and imports.
- Added a persistent panel-access cookie so saved mobile shortcuts can keep working without pasting `?key=` every time.
- Added `/mobile-login?key=...` as a phone-friendly login entry point.
- Node checkbox now imports existing clients from the selected 3x-ui inbound into the aggregator instead of pushing local clients to the node.
- Node action button now imports clients from that node manually.
- Online clients dashboard now defaults to 10 clients per page and has a cleaner responsive layout.
- Node flags in online lists use emoji fallback instead of relying only on external flag images.
- Project update check now uses GitHub API for `dagmagnat/3xui-Aggregator` by default, so `git` is not required inside the container.



## 2026-05-05 — compact buttons and XHTTP support

- Вернул компактные кнопки удаления клиентов: кнопки больше не растягиваются на всю ширину desktop-блока.
- В списке узлов снова только 4 основные кнопки: проверить, отключить/включить, изменить, удалить.
- Кнопка импорта клиентов перенесена внутрь страницы редактирования узла.
- Добавлена поддержка VLESS + XHTTP + REALITY для JSON-подписок.
- XHTTP-поля подтягиваются из 3x-ui inbound и могут быть сохранены обратно: path, host, mode, stream-one параметры и dialerProxy=fragment.
- Добавлены отдельные настройки JSON/Xray для MUX и Sniffing. Они не требуют Happ Provider ID и по умолчанию выключены.

## 2026-05-05 — multi-instance and subscription auto-update fix

- Добавлена подготовка установщика к нескольким независимым экземплярам на одном VPS.
- Для не-default экземпляров используются отдельные каталоги, имена контейнеров, compose project name и команды `agg-<instance>`.
- Общая команда `agg` теперь умеет выбрать установленный экземпляр.
- Backup-файлы экземпляров получают имя с instance name.
- Заголовки автообновления подписки снова отдаются независимо от Happ Provider ID.
- В настройки добавлена отдельная галочка «Передавать автообновление в подписке».

## Исправление отображения сроков и сохранения inbound

- Отображение срока клиента унифицировано: теперь в дашборде и клиентах показывается только фактический остаток дней, без смешанного формата `353/360`.
- Сохранение частых параметров inbound из страницы редактирования узла теперь отправляет изменения в 3x-ui по умолчанию, если параметры были загружены и присутствуют в форме.
- Обновление inbound пробует JSON API 3x-ui и при необходимости делает fallback на form-urlencoded для совместимости с разными версиями 3x-ui.
- Для REALITY одновременно обновляются `serverName/serverNames` и `shortId/shortIds`, чтобы изменения корректнее применялись в разных сборках 3x-ui.
- Автообновление подписки дополнительно закреплено как независимая от Happ настройка.

## Multi-instance install safety fix

- Исправлен установщик: при создании нового экземпляра на другом IP он больше не останавливает существующую default-панель из-за шаблонного docker-compose.yml в свежем git-клоне.
- docker compose теперь запускается с явным project name экземпляра.
- Добавлена проверка IP привязки Caddy: если IP не найден на интерфейсах сервера, установщик предупреждает перед запуском.
- Автообновление подписки остаётся независимым от Happ и передаётся через заголовки Profile/Subscription update interval.
