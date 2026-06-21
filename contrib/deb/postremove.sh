#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi

# Конфиг (/etc/antizapret-go) и состояние (/var/lib/antizapret-go) намеренно не удаляем
# даже при purge: там списки оператора и расходный кэш. Чистить — вручную при желании.

exit 0