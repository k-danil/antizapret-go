#!/bin/sh
set -e

[ -d /run/systemd/system ] || exit 0

systemctl daemon-reload || true

# дефолтный конфиг, если оператор ещё не положил свой (не conffile). -s: пустой файл
# (в т.ч. от прежней баг-версии) тоже перегенерится; неудачную генерацию не оставляем.
if [ ! -s /etc/antizapret-go/config.yaml ]; then
	tmp=$(mktemp)
	if /usr/bin/antizapret-go -default-config > "$tmp" && [ -s "$tmp" ]; then
		install -m 0644 "$tmp" /etc/antizapret-go/config.yaml
	fi
	rm -f "$tmp"
fi

# На апгрейде перезапускаем, если сервис запущен. На свежей установке НЕ стартуем и НЕ
# включаем: у сервиса хард-зависимость от таблицы `ip nat` и поднятого VPN-интерфейса —
# оператор настраивает firewall/конфиг и затем `systemctl enable --now antizapret-go`.
if systemctl is-active --quiet antizapret-go.service; then
	systemctl restart antizapret-go.service || true
fi

exit 0