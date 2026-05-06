#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/3xui-aggregator"
BACKUP_DIR="/opt/3xui-backups"
SHORTCUT_BIN="/usr/local/bin/agg"
SOURCE_CONF="/etc/3xui-aggregator-source.conf"

if [ -d "$APP_DIR" ]; then
  cd "$APP_DIR"
  docker compose down -v --remove-orphans || true
fi

docker stop 3xui-aggregator-caddy >/dev/null 2>&1 || true
docker rm -f 3xui-aggregator-caddy >/dev/null 2>&1 || true
docker stop 3xui-aggregator >/dev/null 2>&1 || true
docker rm -f 3xui-aggregator >/dev/null 2>&1 || true

cd /
rm -rf "$APP_DIR"
rm -f "$SHORTCUT_BIN"
rm -f "$SOURCE_CONF"

echo "3xui-Aggregator удалён."
echo "Резервные копии в $BACKUP_DIR не удалены."
echo "Команда agg удалена."
