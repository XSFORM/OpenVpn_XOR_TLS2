# OpenVpn_XOR_TLS2

OpenVPN-сервер + Telegram-бот для мониторинга/управления.

Особенности:
- `openvpn-install.sh` (angristan) хранится **в этом репо** → установка всегда повторяемая.
- Поддержка **TLS-Crypt** и **TLS-Crypt v2** (как в новом angristan).
- XOR/xormask (scramble) **включается автоматически только если вы выбрали TLS-Crypt**.
- Конфиги OpenVPN ожидаются в новом стиле: `/etc/openvpn/server/...`.

## Установка (как ты привык)

```bash
apt update && apt install -y git && \
  git clone https://github.com/XSFORM/OpenVpn_XOR_TLS2.git && \
  cd OpenVpn_XOR_TLS2 && \
  chmod +x install.sh install_openvpn_xor_tls2.sh openvpn-install.sh && \
  ./install.sh
```

## Что делает установщик

1. Запускает `openvpn-install.sh` из репозитория (интерактивно).
2. Читает итоговый `server.conf` и определяет режим TLS.
3. Если режим `tls-crypt` → ставит OpenVPN XOR и добавляет `scramble xormask 5`.
4. Ставит бота как systemd-сервис `vpn_bot.service`.

## Логи бота

```bash
journalctl -u vpn_bot.service -f
```
## Управление сервисами (OpenVPN и бот)

### OpenVPN

> На большинстве систем с новым расположением `/etc/openvpn/server/` сервис называется `openvpn-server@server`.

```bash
systemctl restart openvpn-server@server
systemctl status openvpn-server@server
```

Если у тебя другое имя сервиса (редко, но бывает), посмотри список:

```bash
systemctl list-units --type=service | grep -i openvpn
```

### Telegram-бот (vpn_bot.service)

```bash
systemctl restart vpn_bot.service
systemctl status vpn_bot.service
```
---

## Автор

XSFORM  
Telegram: [@XSFORM](https://t.me/XS_FORM)