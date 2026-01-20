#!/bin/bash
set -euo pipefail

echo "[*] Начало установки OpenVPN + Telegram-бота."

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Запусти от root." >&2
  exit 1
fi

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Шаг 1. Установка OpenVPN (angristan из репо) + (опционально) XOR/xormask ---
if [[ -f "$BASE_DIR/install_openvpn_xor_tls2.sh" ]]; then
  echo "[*] Копирую install_openvpn_xor_tls2.sh в /root ..."
  cp "$BASE_DIR/install_openvpn_xor_tls2.sh" /root/install_openvpn_xor_tls2.sh
  cp "$BASE_DIR/openvpn-install.sh" /root/openvpn-install.sh
  chmod +x /root/install_openvpn_xor_tls2.sh /root/openvpn-install.sh
  echo "[*] Запуск установки OpenVPN ..."
  bash /root/install_openvpn_xor_tls2.sh
else
  echo "[!] install_openvpn_xor_tls2.sh не найден — пропускаю установку OpenVPN."
fi

# --- Шаг 2. Ввод токена и ID ---
read -rp "Введите Telegram BOT TOKEN: " BOT_TOKEN
read -rp "Введите ваш Telegram ID: " ADMIN_ID

# --- Шаг 3. Каталог бота ---
echo "[*] Готовлю /root/monitor_bot ..."
mkdir -p /root/monitor_bot

if [[ -d "$BASE_DIR/monitor_bot" ]]; then
  cp -r "$BASE_DIR/monitor_bot/"* /root/monitor_bot/
else
  echo "[!] Директория monitor_bot не найдена рядом со скриптом." >&2
  exit 1
fi

# --- Шаг 4. Создаём config.py ---
cat > /root/monitor_bot/config.py <<EOF
TOKEN = "$BOT_TOKEN"
ADMIN_ID = $ADMIN_ID
EOF

# --- Шаг 5. Пакеты и зависимости ---
apt update -y
apt install -y python3 python3-pip git wget curl

# pip
python3 -m pip install --upgrade pip

REQ_FILE="/root/monitor_bot/requirements.txt"
if [[ ! -f "$REQ_FILE" ]]; then
  cat > "$REQ_FILE" <<'REQ'
python-telegram-bot==20.3
requests
pytz
pyOpenSSL
cryptography
REQ
fi

python3 -m pip install -r "$REQ_FILE"

# --- Шаг 6. systemd unit ---
if [[ -f "$BASE_DIR/vpn_bot.service" ]]; then
  cp "$BASE_DIR/vpn_bot.service" /etc/systemd/system/vpn_bot.service
else
  cat > /etc/systemd/system/vpn_bot.service <<'UNIT'
[Unit]
Description=VPN Telegram Monitor Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/monitor_bot
ExecStart=/usr/bin/python3 /root/monitor_bot/openvpn_monitor_bot.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT
fi

systemctl daemon-reload
systemctl enable --now vpn_bot.service || {
  echo "[!] Не удалось запустить сервис. Смотри: journalctl -u vpn_bot.service -n 80" >&2
  exit 1
}

echo "========================================================"
echo "Готово!"
echo "config.py: /root/monitor_bot/config.py"
echo "логи: journalctl -u vpn_bot.service -f"
echo "========================================================"
