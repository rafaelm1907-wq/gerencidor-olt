#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Execute como root: sudo ./update.sh" >&2
  exit 1
fi

SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
APP_DIR=/opt/olt-vision

for file in app.py auth_store.py autofind_query.py fast_collector.py huawei_ssh.py huawei_telnet.py license_manager.py module_collector.py multi_app.py olt_registry.py telegram_dispatcher.py vlan_collector.py prune_history.py migrate_performance.py setup_users.py admin.html change_password.html license.html login.html multi_index.html; do
  install -m 0644 "$SOURCE_DIR/$file" "$APP_DIR/$file"
done
for unit in olt-collector@.service olt-fast.service olt-module@.service olt-multi-web.service olt-telegram.service olt-vlan@.service; do
  install -m 0644 "$SOURCE_DIR/$unit" "/etc/systemd/system/$unit"
done

systemctl daemon-reload
systemctl restart olt-multi-web.service olt-fast.service
systemctl try-restart 'olt-collector@*.service' 'olt-vlan@*.service' 'olt-module@*.service' olt-telegram.service
echo "Atualização concluída. Configurações, usuários e bancos foram preservados."

