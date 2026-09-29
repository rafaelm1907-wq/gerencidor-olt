#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Execute como root: sudo ./install.sh" >&2
  exit 1
fi

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
APP_DIR=/opt/olt-vision
CONFIG_DIR=/etc/olt-vision
DATA_DIR=/var/lib/olt-vision

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-paramiko snmp iputils-ping

install -d -m 0755 "$APP_DIR"
install -d -m 0700 "$CONFIG_DIR/olts"
install -d -m 0700 "$DATA_DIR"

for file in app.py auth_store.py autofind_query.py fast_collector.py huawei_ssh.py huawei_telnet.py license_manager.py multi_app.py olt_registry.py telegram_dispatcher.py vlan_collector.py prune_history.py migrate_performance.py setup_users.py admin.html change_password.html license.html login.html multi_index.html; do
  install -m 0644 "$SOURCE_DIR/$file" "$APP_DIR/$file"
done

if [[ ! -e "$APP_DIR/olts.json" ]]; then
  install -m 0644 "$SOURCE_DIR/olts.json" "$APP_DIR/olts.json"
fi

if [[ ! -e /etc/olt-vision.env ]]; then
  install -m 0600 "$SOURCE_DIR/.env.example" /etc/olt-vision.env
fi
if [[ ! -e "$CONFIG_DIR/telegram.env" ]]; then
  install -m 0600 "$SOURCE_DIR/telegram.env.example" "$CONFIG_DIR/telegram.env"
fi
if [[ ! -e "$CONFIG_DIR/license.env" ]]; then install -m 0600 /dev/null "$CONFIG_DIR/license.env"; fi

for unit in olt-collector@.service olt-fast.service olt-multi-web.service olt-telegram.service olt-vlan@.service; do
  install -m 0644 "$SOURCE_DIR/$unit" "/etc/systemd/system/$unit"
done

set -a
source /etc/olt-vision.env
set +a
python3 "$APP_DIR/setup_users.py"

systemctl daemon-reload
systemctl enable --now olt-multi-web.service olt-fast.service

echo
echo "Instalação concluída. Painel disponível na porta 6000."
echo "Cadastre a primeira OLT em http://IP-DO-SERVIDOR:6000/admin"
echo "Telegram permanece desativado até que o token e os destinos sejam configurados."

