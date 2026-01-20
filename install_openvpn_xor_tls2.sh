#!/bin/bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Запусти от root." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Минимальные зависимости (на чистом сервере wget/curl может отсутствовать)
apt update -y
apt install -y wget curl || true

echo "[*] Устанавливаем OpenVPN через локальный angristan (из репо) ..."
chmod +x "$SCRIPT_DIR/openvpn-install.sh"
# angristan сам интерактивный
bash "$SCRIPT_DIR/openvpn-install.sh" install

refresh_paths() {
  SERVER_CONF=""
  if [[ -f /etc/openvpn/server/server.conf ]]; then
    SERVER_CONF="/etc/openvpn/server/server.conf"
  elif [[ -f /etc/openvpn/server.conf ]]; then
    SERVER_CONF="/etc/openvpn/server.conf"
  fi
  [[ -n "${SERVER_CONF}" ]] || return 1
  SERVER_DIR="$(dirname "$SERVER_CONF")"

  CLIENT_TEMPLATE=""
  if [[ -f "$SERVER_DIR/client-template.txt" ]]; then
    CLIENT_TEMPLATE="$SERVER_DIR/client-template.txt"
  elif [[ -f /etc/openvpn/client-template.txt ]]; then
    CLIENT_TEMPLATE="/etc/openvpn/client-template.txt"
  fi
}


# Безопасный симлинк: не пытаемся линковать файл сам на себя
safe_link() {
  local src="$1" dst="$2"
  local src_real dst_real
  src_real="$(readlink -f "$src")"
  dst_real="$(readlink -f "$dst" 2>/dev/null || true)"
  if [[ -n "$dst_real" && "$src_real" == "$dst_real" ]]; then
    return 0
  fi
  ln -sfn "$src" "$dst"
}

echo "[*] Ищу server.conf ..."
if ! refresh_paths; then
  echo "[!] Не найден server.conf после установки. Ожидаю /etc/openvpn/server/server.conf или /etc/openvpn/server.conf" >&2
  exit 1
fi

# На всякий случай создадим legacy-симлинки (многие скрипты/боты их ждут)
mkdir -p /etc/openvpn
safe_link "$SERVER_CONF" /etc/openvpn/server.conf
if [[ -n "$CLIENT_TEMPLATE" && -f "$CLIENT_TEMPLATE" ]]; then
  safe_link "$CLIENT_TEMPLATE" /etc/openvpn/client-template.txt
fi

# --- Определяем режим TLS по server.conf ---
TLS_MODE="none"
if grep -Eqs '^\s*tls-crypt-v2\s+' "$SERVER_CONF"; then
  TLS_MODE="tls-crypt-v2"
elif grep -Eqs '^\s*tls-crypt\s+' "$SERVER_CONF"; then
  TLS_MODE="tls-crypt"
elif grep -Eqs '^\s*tls-auth\s+' "$SERVER_CONF"; then
  TLS_MODE="tls-auth"
fi

echo "[*] Найден конфиг: $SERVER_CONF"
echo "[*] Режим TLS: $TLS_MODE"

# --- Универсальные push routes (безопасно для всех режимов) ---
add_push_routes() {
  local conf="$1"
  for route in \
      "192.168.0.0 255.255.0.0" \
      "10.0.0.0 255.0.0.0" \
      "172.16.0.0 255.240.0.0" \
      "27.34.176.0 255.255.255.0" \
      "57.90.150.0 255.255.254.0" \
      "77.83.59.0 255.255.255.0" \
      "82.198.24.0 255.255.255.0" \
      "91.202.233.0 255.255.255.0" \
      "93.171.174.0 255.255.255.0" \
      "93.171.220.0 255.255.252.0" \
      "94.102.176.0 255.255.240.0" \
      "95.85.96.0 255.255.224.0" \
      "103.220.0.0 255.255.252.0" \
      "119.235.112.0 255.255.240.0" \
      "154.30.29.0 255.255.255.0" \
      "177.93.143.0 255.255.255.0" \
      "178.171.66.0 255.255.254.0" \
      "185.69.184.0 255.255.252.0" \
      "185.246.72.0 255.255.252.0" \
      "196.48.195.0 255.255.255.0" \
      "196.56.195.0 255.255.255.0" \
      "196.57.195.0 255.255.255.0" \
      "196.58.195.0 255.255.255.0" \
      "196.197.195.0 255.255.255.0" \
      "196.198.195.0 255.255.255.0" \
      "196.199.195.0 255.255.255.0" \
      "216.250.8.0 255.255.248.0" \
      "217.8.117.0 255.255.255.0" \
      "217.174.224.0 255.255.240.0"
  do
    ip=$(echo "$route" | awk '{print $1}')
    mask=$(echo "$route" | awk '{print $2}')
    line="push \"route $ip $mask net_gateway\""
    grep -qF "$line" "$conf" || echo "$line" >> "$conf"
  done
}

echo "[*] Добавляем push-маршруты (если их ещё нет) ..."
add_push_routes "$SERVER_CONF"

# --- XOR/Xormask ставим ТОЛЬКО если выбран tls-crypt ---
if [[ "$TLS_MODE" == "tls-crypt" ]]; then
  echo "[*] Выбран tls-crypt -> устанавливаем OpenVPN с поддержкой XOR/xormask ..."

  echo "[*] Удаляем пакетный OpenVPN (без purge) ..."
  apt remove -y openvpn || true

  echo "[*] Устанавливаем OpenVPN XOR (скрипт x0r2d2/openvpn-xor) ..."
  wget -q https://raw.githubusercontent.com/x0r2d2/openvpn-xor/main/openvpn_xor_install.sh -O /tmp/openvpn_xor_install.sh
  chmod +x /tmp/openvpn_xor_install.sh
  bash /tmp/openvpn_xor_install.sh

  # После установки XOR могли появиться/измениться пути — обновим
  refresh_paths || true

  # На всякий случай обновим симлинки
  mkdir -p /etc/openvpn
  safe_link "$SERVER_CONF" /etc/openvpn/server.conf
  if [[ -n "$CLIENT_TEMPLATE" && -f "$CLIENT_TEMPLATE" ]]; then
    safe_link "$CLIENT_TEMPLATE" /etc/openvpn/client-template.txt
  fi

  echo "[*] Добавляем scramble xormask 5 ..."
  grep -q "^scramble xormask" "$SERVER_CONF" || echo "scramble xormask 5" >> "$SERVER_CONF"
  if [[ -n "$CLIENT_TEMPLATE" && -f "$CLIENT_TEMPLATE" ]]; then
    grep -q "^scramble xormask" "$CLIENT_TEMPLATE" || echo "scramble xormask 5" >> "$CLIENT_TEMPLATE"
  else
    echo "[i] client-template.txt не найден — пропускаю добавление scramble в шаблон."
  fi
else
  echo "[*] XOR/xormask пропущен (режим TLS не tls-crypt)."
fi

# --- Рестарт OpenVPN (популярные имена юнитов) ---
restart_openvpn() {
  if systemctl list-units --type=service --all | grep -qE 'openvpn-server@server\.service'; then
    systemctl restart openvpn-server@server.service || true
  elif systemctl list-units --type=service --all | grep -qE 'openvpn@server\.service'; then
    systemctl restart openvpn@server.service || true
  elif systemctl list-units --type=service --all | grep -qE '^openvpn\.service'; then
    systemctl restart openvpn.service || true
  fi
}

echo "[*] Перезапуск OpenVPN (если юнит найден) ..."
restart_openvpn

echo "[✓] Готово. Конфиг: $SERVER_CONF (TLS: $TLS_MODE)"
