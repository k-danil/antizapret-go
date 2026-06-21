#!/bin/sh
set -e

[ -d /run/systemd/system ] || exit 0

# Только при полном удалении (не апгрейде) останавливаем и снимаем enable.
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
	systemctl disable --now antizapret-go.service || true
fi

exit 0