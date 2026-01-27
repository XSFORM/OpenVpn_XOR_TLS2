# OpenVPN installer (TLS-Crypt v2 / TLS-Crypt / TLS-Auth) + Telegram monitor bot

Этот репозиторий — практичный набор для быстрого развёртывания OpenVPN и управления/мониторинга через Telegram‑бота.

## Что умеет

### OpenVPN (сервер)
- Установка OpenVPN (ветка `openvpn-install.sh`).
- Выбор защиты control‑channel:
  - **TLS-Crypt v2** (рекомендуется) — уникальный ключ на каждого клиента.
  - TLS-Crypt (classic) — с поддержкой scramble.
  - TLS-Auth — HMAC подпись control‑channel.
- Генерация `.ovpn` клиентов (включая встраивание сертификатов/ключей в файл).
- `status` лог для онлайн‑статуса и учёта трафика (используется ботом).
- (Опционально) набор твиков для UDP стабильности и исправления нюансов systemd.

### Telegram monitor bot
- Кнопки: список/статус ключей, просмотр лога, трафик/очистка трафика, создание ключа, отправка ключей, бэкап/восстановление и т.д.
- Читает `status.log` OpenVPN и показывает кто онлайн, какие ключи отключены, и т.п.

---

## Быстрый старт

### Скачивание и установка
```bash
apt update && apt install -y git && \
  git clone https://github.com/XSFORM/OpenVpn_XOR_TLS2.git && \
  cd OpenVpn_XOR_TLS2 && \
  chmod +x install.sh install_openvpn_xor_tls2.sh openvpn-install.sh && \
  ./install.sh
```

> `install.sh` — ваш удобный “входной” скрипт, внутри он запускает установку OpenVPN и ставит/включает бот (если вы это добавили).

---

## Важно про выбор TLS (по умолчанию)

В моих настройках **по умолчанию выбран TLS‑Crypt v2**.

Во время установки вы можете выбрать другой режим (TLS‑Crypt / TLS‑Auth) в меню `Control channel security`.

### Как поменять *дефолт* (если хотите не спрашивать при установке)
В `openvpn-install.sh` найдите строку примерно такого вида:

```bash
select_with_labels "Control channel security" tls_sig_labels TLS_SIG_MODES "crypt-v2" TLS_SIG_MODE
```

И замените `"crypt-v2"` на нужное значение:
- `"crypt-v2"` — TLS‑Crypt v2
- `"crypt"` — TLS‑Crypt (classic)
- `"auth"` — TLS‑Auth

---


## Полезные команды (OpenVPN)

Статус/рестарт:
```bash
systemctl status openvpn-server@server --no-pager -l
systemctl restart openvpn-server@server
systemctl stop openvpn-server@server
```

Логи сервиса:
```bash
journalctl -u openvpn-server@server -n 200 --no-pager
journalctl -u openvpn-server@server -f
```

`status.log` (он нужен боту):
- Часто путь задаётся в `server.conf` строкой `status ...`
- Примеры:
  - `/var/log/openvpn/status.log`
  - `/run/openvpn-server/status-server.log`

Проверить, что прописано:
```bash
grep -nE '^\s*status\b' /etc/openvpn/server/server.conf
```

---

## Telegram monitor bot

### Где лежит
Обычно:
- `/root/monitor_bot/openvpn_monitor_bot.py`
- systemd unit: `vpn_bot.service`

### Управление ботом
```bash
systemctl status vpn_bot.service --no-pager -l
systemctl restart vpn_bot.service
journalctl -u vpn_bot.service -n 200 --no-pager
journalctl -u vpn_bot.service -f
```

### Важные настройки в коде
Обычно вверху файла (или рядом с конфиг‑переменными):
- `BOT_TOKEN`
- `ADMIN_ID` (бот отвечает только админу)
- пути к OpenVPN/EasyRSA/папке с ключами `.ovpn`
- путь к `status.log`

---

## Примечание про scramble‑xormask

В моей сборке/логике установки **scramble‑xormask включается для режима TLS‑Crypt (classic)**.

Это сделано специально, чтобы **не ломать** конфигурацию, когда выбран TLS‑Crypt v2: v2 и classic используют разные файлы/ключи, и смешивание логики часто приводит к “полурабочим” `.ovpn`.

---

## Что должно получиться в `.ovpn`

### Для TLS‑Crypt v2 (полный файл)
В клиентском `.ovpn` должны быть блоки:
- `<ca> ... </ca>`
- `<cert> ... </cert>`
- `<key> ... </key>`
- `<tls-crypt-v2> ... </tls-crypt-v2>`

### Для TLS‑Crypt (classic)
- `<ca>`, `<cert>`, `<key>`
- `<tls-crypt> ... </tls-crypt>`

---

## Troubleshooting

### Клиент “вроде подключён”, но пропадает из status/log
- Проверьте `explicit-exit-notify 1` (для UDP).
- Проверьте MTU/MSS (`tun-mtu`, `mssfix`) и наличие `fragment` (если используете).
- Смотрите live‑лог:
  ```bash
  journalctl -u openvpn-server@server -f
  ```

### Бот пишет “Неизвестная команда”
- В `button_handler` нет ветки `elif data == 'traffic':` или callback_data отличается от того, что приходит.
- Быстро увидеть приходящие callback_data:
  ```bash
  journalctl -u vpn_bot.service -n 200 --no-pager | grep "DEBUG callback_data"
  ```

### В трафике “0.00 GB”
- Если вы считаете трафик по `status.log`, то данные появятся только когда:
  1) клиент реально онлайн,
  2) в статусе есть `Bytes Received/Sent`,
  3) бот правильно парсит *версию* status‑лога (`status-version 2` / suppress timestamps и т.д.).
- Проверьте сам `status.log`:
  ```bash
  tail -n 50 /var/log/openvpn/status.log
  ```

---

## Безопасность
- Не храните токен бота в публичном репозитории.
- `ADMIN_ID` обязателен — иначе бот будет отвечать всем.
- Закрывайте доступ к SSH и ограничивайте порты firewall’ом.

---

## Структура репозитория (пример)
- `openvpn-install.sh` — установка OpenVPN
- `install.sh` — ваш оркестратор (установка + бот + патчи)
- `monitor_bot/` — код бота
- `vpn_bot.service` — systemd unit для бота

---

## Автор

XSFORM  
Telegram: [@XSFORM](https://t.me/XS_FORM)