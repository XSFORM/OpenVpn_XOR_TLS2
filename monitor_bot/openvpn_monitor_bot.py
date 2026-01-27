# -*- coding: utf-8 -*-
"""
OpenVPN Telegram Monitor Bot
(Изменения 2025-10-01):
  * Натуральная сортировка имён клиентов (1,2,3,...10,11 вместо 1,10,11,2,...)
  * Массовое создание ключей: после ввода логического срока бот спрашивает количество (по умолчанию 1)
    и создаёт несколько ключей сразу (base, base2, base3 ...).
    - Если указано количество = 1: имя как ввёл пользователь.
    - Если >1: первый ключ = base, последующие base2, base3 ... (без подчёркивания).
    - При конфликте имён (существующий .ovpn) создание отменяется и запрашивается новое имя.
Остальной функционал не тронут.
"""


import os
import subprocess
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict
from html import escape
import glob
import json
import traceback
import re
import requests
import shutil
import socket

from OpenSSL import crypto
import pytz

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes,
    MessageHandler, filters
)

from config import TOKEN, ADMIN_ID
from backup_restore import (
    create_backup as br_create_backup,
    apply_restore,
    BACKUP_OUTPUT_DIR,
    MANIFEST_NAME
)

# ------------------ Константы / Глобалы ------------------

# ------------------ Авто-определение путей (совместимость old/new) ------------------
def _first_existing_dir(*candidates: str) -> str:
    for p in candidates:
        if p and os.path.isdir(p):
            return p
    return candidates[0] if candidates else ""

def detect_openvpn_dir() -> str:
    """
    Возвращает каталог, где лежит server.conf и связанные файлы.
    Поддерживает:
      - старое: /etc/openvpn/server.conf
      - новое:  /etc/openvpn/server/server.conf
    """
    cand = [
        "/etc/openvpn/server",  # новое
        "/etc/openvpn",         # старое
    ]
    for d in cand:
        if os.path.isfile(os.path.join(d, "server.conf")):
            return d
    # fallback: если есть server/ но server.conf ещё не создан (редко) — берём /etc/openvpn
    return "/etc/openvpn"

def detect_easyrsa_dir(openvpn_dir: str) -> str:
    # Angristan обычно кладёт easy-rsa рядом с server.conf или в /etc/openvpn/easy-rsa
    candidates = [
        os.path.join(openvpn_dir, "easy-rsa"),
        "/etc/openvpn/easy-rsa",
        "/etc/openvpn/server/easy-rsa",
    ]
    for d in candidates:
        if os.path.isdir(d):
            return d
    return candidates[0]

def detect_ccd_dir(openvpn_dir: str) -> str:
    candidates = [
        os.path.join(openvpn_dir, "ccd"),
        "/etc/openvpn/ccd",
        "/etc/openvpn/server/ccd",
    ]
    for d in candidates:
        if os.path.isdir(d):
            return d
    # если каталога нет — пусть будет стандартный
    return os.path.join(openvpn_dir, "ccd")

def detect_status_log(server_conf_path: str) -> str:
    # Пытаемся вытащить путь из директивы status в server.conf
    try:
        if os.path.isfile(server_conf_path):
            with open(server_conf_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith(("#", ";")):
                        continue
                    if line.startswith("status "):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
    except Exception:
        pass
    # fallback (часто встречаются эти варианты)
    fallbacks = [
        "/var/log/openvpn/status.log",
        "/var/log/openvpn/status-server.log",
        "/var/log/openvpn/openvpn-status.log",
    ]
    for p in fallbacks:
        if os.path.isfile(p):
            return p
    return fallbacks[0]


def detect_ipp_file(server_conf_path: str, openvpn_dir: str) -> str:
    """Return absolute path to ipp.txt based on ifconfig-pool-persist directive."""
    try:
        if os.path.isfile(server_conf_path):
            with open(server_conf_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith(("#", ";")):
                        continue
                    if s.startswith("ifconfig-pool-persist"):
                        parts = s.split()
                        if len(parts) >= 2:
                            p = parts[1]
                            if p.startswith("/"):
                                return p
                            return os.path.join(openvpn_dir, p)
    except Exception:
        pass
    # common fallbacks
    for p in [
        os.path.join(openvpn_dir, "ipp.txt"),
        "/etc/openvpn/ipp.txt",
        "/var/log/openvpn/ipp.txt",
    ]:
        if os.path.isfile(p):
            return p
    return os.path.join(openvpn_dir, "ipp.txt")

def detect_tls_mode(server_conf_path: str) -> str:
    """
    Определяет, что используется на сервере:
      - tls-crypt
      - tls-auth
      - none
    (Если позже добавишь tls-crypt-v2, сюда просто добавится ещё одна ветка.)
    """
    try:
        if not os.path.isfile(server_conf_path):
            return "unknown"
        with open(server_conf_path, "r", encoding="utf-8", errors="ignore") as f:
            conf = f.read()
        # Важно: сначала tls-crypt-v2 (если появится), потом tls-crypt, затем tls-auth
        if "tls-crypt-v2" in conf:
            return "tls-crypt-v2"
        if "tls-crypt" in conf:
            return "tls-crypt"
        if "tls-auth" in conf:
            return "tls-auth"
        return "none"
    except Exception:
        return "unknown"

def runtime_info() -> str:
    mode = detect_tls_mode(os.path.join(OPENVPN_DIR, "server.conf"))
    return (
        f"TLS: {mode}\n"
        f"OPENVPN_DIR: {OPENVPN_DIR}\n"
        f"EASYRSA_DIR: {EASYRSA_DIR}\n"
        f"CCD_DIR: {CCD_DIR}\n"
        f"STATUS_LOG: {STATUS_LOG}"
    )

BOT_VERSION = "2025-10-01-logical-expiry+nat-sort+multi-create"
UPDATE_SOURCE_URL = "https://raw.githubusercontent.com/XSFORM/update_bot/main/openvpn_monitor_bot.py"
SIMPLE_UPDATE_CMD = (
    "curl -L -o /root/monitor_bot/openvpn_monitor_bot.py "
    f"{UPDATE_SOURCE_URL} && systemctl restart vpn_bot.service"
)

TELEGRAPH_TOKEN_FILE = "/root/monitor_bot/telegraph_token.txt"
TELEGRAPH_SHORT_NAME = "vpn-bot"
TELEGRAPH_AUTHOR = "VPN Bot"

KEYS_DIR = "/root"
OPENVPN_DIR = detect_openvpn_dir()

# Refresh STATUS_LOG from actual server.conf (important for OpenVPN status-version 2 CSV)
try:
    STATUS_LOG = detect_status_log(os.path.join(OPENVPN_DIR, "server.conf"))
except Exception:
    pass

EASYRSA_DIR = detect_easyrsa_dir(OPENVPN_DIR)
CCD_DIR = detect_ccd_dir(OPENVPN_DIR)
STATUS_LOG = detect_status_log(os.path.join(OPENVPN_DIR, "server.conf"))

SEND_NEW_OVPN_ON_RENEW = False
TM_TZ = pytz.timezone("Asia/Ashgabat")

MGMT_SOCKET = "/var/run/openvpn.sock"        # fallback unix socket (если настроен)
MANAGEMENT_HOST = "127.0.0.1"                # TCP management host
MANAGEMENT_PORT = 7505                       # TCP management port
MANAGEMENT_TIMEOUT = 3                       # seconds

MIN_ONLINE_ALERT = 15
ALERT_INTERVAL_SEC = 300
# --- Alarm toggle (block alerts ON/OFF) ---
ALARM_FLAG = "/var/run/openvpn_alarm.enabled"

def alarm_is_enabled() -> bool:
    return os.path.exists(ALARM_FLAG)

def alarm_enable():
    os.makedirs(os.path.dirname(ALARM_FLAG), exist_ok=True)
    with open(ALARM_FLAG, "w") as f:
        f.write("on")

def alarm_disable():
    try:
        if os.path.exists(ALARM_FLAG):
            os.remove(ALARM_FLAG)
    except Exception:
        pass
# -----------------------------------------


last_alert_time = 0
clients_last_online = set()

TRAFFIC_DB_PATH = "/root/monitor_bot/traffic_usage.json"
traffic_usage: Dict[str, Dict[str, int]] = {}
_last_session_state = {}
_last_traffic_save_time = 0
TRAFFIC_SAVE_INTERVAL = 60

CLIENT_META_PATH = "/root/monitor_bot/clients_meta.json"
client_meta: Dict[str, Dict[str, str]] = {}

ENFORCE_INTERVAL_SECONDS = 43200  # 12 часов

ROOT_ARCHIVE_EXCLUDE_GLOBS = ["/root/*.tar.gz", "/root/*.tgz"]
EXCLUDE_TEMP_DIR = "/root/monitor_bot/.excluded_root_archives"

PAGE_SIZE_KEYS = 40

# Постоянное меню (inline)
MENU_MESSAGE_ID = None
MENU_CHAT_ID = None

# Предупреждения о скором истечении
_notified_expiry: Dict[str, str] = {}
UPCOMING_EXPIRY_DAYS = 1

# ---------- Натуральная сортировка ----------
_nat_num_re = re.compile(r'(\d+)')

def _natural_key(s: str):
    # Разбиваем строку на числа и текст: "client12a" -> ['client', 12, 'a']
    return [int(x) if x.isdigit() else x.lower() for x in _nat_num_re.split(s)]

def natural_sorted(seq: List[str]) -> List[str]:
    return sorted(seq, key=_natural_key)

def locate_backup(fname: str) -> Optional[str]:
    """
    Возвращает полный путь к архиву.
    Порядок проверки:
      1. Абсолютный путь
      2. BACKUP_OUTPUT_DIR/fname
      3. /root/fname
      4. /root/backups/fname
    """
    if fname.startswith("/"):
        if os.path.isfile(fname):
            return fname
    try:
        if 'BACKUP_OUTPUT_DIR' in globals() and BACKUP_OUTPUT_DIR:
            p = os.path.join(BACKUP_OUTPUT_DIR, fname)
            if os.path.isfile(p):
                return p
    except Exception:
        pass
    p2 = os.path.join("/root", fname)
    if os.path.isfile(p2):
        return p2
    p3 = os.path.join("/root/backups", fname)
    if os.path.isfile(p3):
        return p3
    return None

# ------------------ Логические сроки ------------------
def load_client_meta():
    global client_meta
    try:
        if os.path.exists(CLIENT_META_PATH):
            with open(CLIENT_META_PATH, "r") as f:
                client_meta = json.load(f)
        else:
            client_meta = {}
    except Exception as e:
        print(f"[meta] load error: {e}")
        client_meta = {}

def save_client_meta():
    try:
        tmp = CLIENT_META_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(client_meta, f)
        os.replace(tmp, CLIENT_META_PATH)
    except Exception as e:
        print(f"[meta] save error: {e}")

def set_client_expiry_days_from_now(name: str, days: int) -> str:
    if days < 1:
        days = 1
    dt = datetime.utcnow() + timedelta(days=days)
    iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    client_meta.setdefault(name, {})["expire"] = iso
    save_client_meta()
    unblock_client_ccd(name)
    return iso

def get_client_expiry(name: str) -> Tuple[Optional[str], Optional[int]]:
    data = client_meta.get(name)
    if not data:
        return None, None
    iso = data.get("expire")
    if not iso:
        return None, None
    try:
        dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        return iso, (dt - datetime.utcnow()).days
    except Exception:
        return iso, None

def enforce_client_expiries():
    now = datetime.utcnow()
    changed = False
    for name, data in list(client_meta.items()):
        iso = data.get("expire")
        if not iso:
            continue
        try:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        if now > dt and not is_client_ccd_disabled(name):
            block_client_ccd(name)
            disconnect_client_sessions(name)
            changed = True
    if changed:
        print("[meta] enforced expiries")

def check_and_notify_expiring(bot):
    if not client_meta:
        return
    now = datetime.utcnow()
    for name, data in client_meta.items():
        iso = data.get("expire")
        if not iso:
            continue
        try:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        days_left = (dt - now).days
        if days_left == UPCOMING_EXPIRY_DAYS and not is_client_ccd_disabled(name):
            if _notified_expiry.get(name) == iso:
                continue
            try:
                bot.send_message(
                    ADMIN_ID,
                    f"⚠️ Клиент {name} истекает через {days_left} день (до {iso}). Продли: ⌛ Обновить ключ."
                )
                _notified_expiry[name] = iso
            except Exception as e:
                print(f"[notify_expiring] fail {name}: {e}")
        elif _notified_expiry.get(name) and _notified_expiry.get(name) != iso and days_left >= 0:
            _notified_expiry.pop(name, None)

# ------------------ Management (отключение сессий) ------------------
def _mgmt_tcp_command(cmd: str) -> str:
    data = b""
    with socket.create_connection((MANAGEMENT_HOST, MANAGEMENT_PORT), MANAGEMENT_TIMEOUT) as s:
        s.settimeout(MANAGEMENT_TIMEOUT)
        try: data += s.recv(4096)
        except Exception: pass
        s.sendall((cmd.strip() + "\n").encode())
        time.sleep(0.15)
        try:
            while True:
                chunk = s.recv(65535)
                if not chunk: break
                data += chunk
                if len(chunk) < 65535: break
        except Exception: pass
        try: s.sendall(b"quit\n")
        except Exception: pass
    return data.decode(errors="ignore")

def disconnect_client_sessions(client_name: str) -> bool:
    try:
        out = _mgmt_tcp_command(f"client-kill {client_name}")
        if out:
            print(f"[mgmt] client-kill {client_name} -> {out.strip()[:120]}")
            return True
    except Exception:
        pass
    if os.path.exists(MGMT_SOCKET):
        try:
            subprocess.run(f'echo "kill {client_name}" | nc -U {MGMT_SOCKET}', shell=True)
            print(f"[mgmt] unix kill {client_name}")
            return True
        except Exception as e:
            print(f"[mgmt] unix kill failed {client_name}: {e}")
    return False

# ------------------ Update helpers ------------------
async def show_update_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    await update.message.reply_text(
        f"<b>Команда обновления:</b>\n<code>{SIMPLE_UPDATE_CMD}</code>",
        parse_mode="HTML"
    )

async def send_simple_update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer()
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("📋 Копия", callback_data="copy_update_cmd")]])
    await context.bot.send_message(
        chat_id=q.message.chat_id,
        text=f"<b>Команда обновления (версия {BOT_VERSION}):</b>\n<code>{SIMPLE_UPDATE_CMD}</code>",
        parse_mode="HTML",
        reply_markup=kb
    )

async def resend_update_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer("Отправлено")
    await context.bot.send_message(chat_id=q.message.chat_id, text=f"<code>{SIMPLE_UPDATE_CMD}</code>", parse_mode="HTML")

# ------------------ Helpers ------------------
def get_ovpn_files():
    return [f for f in os.listdir(KEYS_DIR) if f.endswith(".ovpn")]

def is_client_ccd_disabled(client_name):
    p = os.path.join(CCD_DIR, client_name)
    if not os.path.exists(p): return False
    try:
        with open(p, "r") as f:
            return "disable" in f.read().lower()
    except:
        return False

def block_client_ccd(client_name):
    os.makedirs(CCD_DIR, exist_ok=True)
    with open(os.path.join(CCD_DIR, client_name), "w") as f:
        f.write("disable\n")
    disconnect_client_sessions(client_name)

def unblock_client_ccd(client_name):
    os.makedirs(CCD_DIR, exist_ok=True)
    with open(os.path.join(CCD_DIR, client_name), "w") as f:
        f.write("enable\n")

def split_message(text, max_length=4000):
    lines = text.split('\n')
    out, cur = [], ""
    for line in lines:
        if len(cur) + len(line) + 1 <= max_length:
            cur += line + "\n"
        else:
            out.append(cur); cur = line + "\n"
    if cur: out.append(cur)
    return out

def format_clients_by_certs():
    cert_dir = f"{EASYRSA_DIR}/pki/issued/"
    if not os.path.isdir(cert_dir):
        return "<b>Список клиентов:</b>\n\nКаталог issued отсутствует."
    certs = [f for f in os.listdir(cert_dir) if f.endswith(".crt")]
    certs = sorted(certs, key=lambda x: _natural_key(x[:-4]))  # натурально по имени без .crt
    res = "<b>Список клиентов (по сертификатам):</b>\n\n"
    idx = 1
    for f in certs:
        name = f[:-4]
        if name.startswith("server_"):  # пропуск серверных
            continue
        mark = "⛔" if is_client_ccd_disabled(name) else "🟢"
        res += f"{idx}. {mark} <b>{name}</b>\n"
        idx += 1
    if idx == 1:
        res += "Нет выданных сертификатов."
    return res

def parse_remote_proto_from_ovpn(path: str):
    remote = ""; proto = ""
    try:
        with open(path, "r") as f:
            for line in f:
                ls = line.strip()
                if ls.startswith("remote "):
                    parts = ls.split()
                    if len(parts) >= 3:
                        remote = parts[2]
                elif ls.startswith("proto "):
                    proto = ls.split()[1]
                if remote and proto:
                    break
    except:
        pass
    return f"{remote}:{proto}" if (remote or proto) else ""

def get_cert_days_left(client_name: str) -> Optional[int]:
    cert_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
    if not os.path.exists(cert_path): return None
    try:
        with open(cert_path, "rb") as f:
            data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        not_after = cert.get_notAfter().decode("ascii")
        expiry_dt = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
        return (expiry_dt - datetime.utcnow()).days
    except Exception:
        return None

def gather_key_metadata():
    rows = []
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))  # натуральная сортировка
    for f in files:
        name = f[:-5]
        days = get_cert_days_left(name)
        days_str = str(days) if days is not None else "-"
        ovpn_path = os.path.join(KEYS_DIR, f)
        cfg = parse_remote_proto_from_ovpn(ovpn_path)
        crt_path = f"{EASYRSA_DIR}/pki/issued/{name}.crt"
        ctime = "-"
        try:
            path_for_time = crt_path if os.path.exists(crt_path) else ovpn_path
            ts = os.path.getmtime(path_for_time)
            ctime = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
        except:
            pass
        rows.append({"name": name, "days": days_str, "cfg": cfg, "created": ctime})
    return rows

def build_keys_table_text(rows: List[Dict]):
    if not rows: return "Нет ключей."
    name_w = max([len(r["name"]) for r in rows] + [4])
    cfg_w = max([len(r["cfg"]) for r in rows] + [6])
    days_w = max([len(r["days"]) for r in rows] + [4])
    header = f"N | {'Имя'.ljust(name_w)} | {'СерДн'.ljust(days_w)} | {'Конфиг'.ljust(cfg_w)} | Создан"
    lines = [header]
    for i, r in enumerate(rows, 1):
        lines.append(f"{i} | {r['name'].ljust(name_w)} | {r['days'].ljust(days_w)} | {r['cfg'].ljust(cfg_w)} | {r['created']}")
    return "\n".join(lines)

# ------------------ Telegraph ------------------
def get_telegraph_token() -> Optional[str]:
    try:
        if os.path.exists(TELEGRAPH_TOKEN_FILE):
            with open(TELEGRAPH_TOKEN_FILE, "r") as f:
                tok = f.read().strip()
                if tok: return tok
        resp = requests.post("https://api.telegra.ph/createAccount",
                             data={"short_name": TELEGRAPH_SHORT_NAME,"author_name": TELEGRAPH_AUTHOR},
                             timeout=10)
        data = resp.json()
        token = data.get("result", {}).get("access_token")
        if token:
            os.makedirs(os.path.dirname(TELEGRAPH_TOKEN_FILE), exist_ok=True)
            with open(TELEGRAPH_TOKEN_FILE, "w") as f:
                f.write(token)
            return token
    except Exception as e:
        print(f"[telegraph] token error: {e}")
    return None

def create_telegraph_pre_page(title: str, text: str) -> Optional[str]:
    token = get_telegraph_token()
    if not token: return None
    content_nodes = json.dumps([{"tag": "pre", "children": [text]}], ensure_ascii=False)
    try:
        resp = requests.post("https://api.telegra.ph/createPage", data={
            "access_token": token,
            "title": title,
            "author_name": TELEGRAPH_AUTHOR,
            "content": content_nodes,
            "return_content": "false"
        }, timeout=15)
        data = resp.json()
        return data.get("result", {}).get("url")
    except Exception as e:
        print(f"[telegraph] create page error: {e}")
        return None

def create_keys_detailed_page():
    rows = gather_key_metadata()
    if not rows: return None
    text = "Полный список ключей (СерДн = остаток по сертификату, не логический срок)\n\n" + build_keys_table_text(rows)
    return create_telegraph_pre_page("Список ключей", text)

def create_names_telegraph_page(names: List[str], title: str, caption: str) -> Optional[str]:
    if not names: return None
    names = natural_sorted(names)
    lines = [caption, ""]
    for i, n in enumerate(names, 1):
        lines.append(f"{i}. {n}")
    return create_telegraph_pre_page(title, "\n".join(lines))

# ------------------ Парсер множественного выбора ------------------
def parse_bulk_selection(text: str, max_index: int) -> Tuple[List[int], List[str]]:
    text = text.strip().lower()
    if not text: return [], ["Пустой ввод."]
    if text == "all":
        return list(range(1, max_index + 1)), []
    parts = re.split(r"[,\s]+", text)
    chosen, errors = set(), []
    for p in parts:
        if not p: continue
        if re.fullmatch(r"\d+", p):
            idx = int(p)
            if 1 <= idx <= max_index: chosen.add(idx)
            else: errors.append(f"Число вне диапазона: {p}")
        elif re.fullmatch(r"\d+-\d+", p):
            a, b = p.split('-'); a, b = int(a), int(b)
            if a > b: a, b = b, a
            if a < 1 or b > max_index:
                errors.append(f"Диапазон вне диапазона: {p}")
                continue
            for i in range(a, b + 1):
                chosen.add(i)
        else:
            errors.append(f"Неверный фрагмент: {p}")
    return sorted(chosen), errors

# ------------------ Массовое удаление ------------------
def revoke_and_collect(names: List[str]) -> Tuple[List[str], List[str]]:
    revoked, failed = [], []
    for name in names:
        cert_path = f"{EASYRSA_DIR}/pki/issued/{name}.crt"
        if not os.path.exists(cert_path):
            revoked.append(name); continue
        try:
            subprocess.run(f"cd {EASYRSA_DIR} && ./easyrsa --batch revoke {name}", shell=True, check=True)
            revoked.append(name)
        except subprocess.CalledProcessError as e:
            failed.append(f"{name}: revoke error {e}")
    return revoked, failed

def generate_crl_once() -> Optional[str]:
    try:
        subprocess.run(f"cd {EASYRSA_DIR} && EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl", shell=True, check=True)
        crl_src = f"{EASYRSA_DIR}/pki/crl.pem"; crl_dst = "/etc/openvpn/crl.pem"
        if os.path.exists(crl_src):
            subprocess.run(f"cp {crl_src} {crl_dst}", shell=True, check=True)
            os.chmod(crl_dst, 0o644)
        return "OK"
    except Exception as e:
        return f"CRL error: {e}"

def remove_client_files(name: str):
    paths = [
        os.path.join(KEYS_DIR, f"{name}.ovpn"),
        f"{EASYRSA_DIR}/pki/issued/{name}.crt",
        f"{EASYRSA_DIR}/pki/private/{name}.key",
        f"{EASYRSA_DIR}/pki/reqs/{name}.req",
        os.path.join(CCD_DIR, name)
    ]
    for p in paths:
        try:
            if os.path.exists(p): os.remove(p)
        except Exception as e:
            print(f"[delete] cannot remove {p}: {e}")
    if name in client_meta:
        client_meta.pop(name, None); save_client_meta()
    if name in traffic_usage:
        traffic_usage.pop(name, None); save_traffic_db(force=True)

# ------------------ Бэкап (скрытие архивов /root) ------------------
TMP_EXCLUDE_DIR = "/tmp/._exclude_root_archives"

def _temporarily_hide_root_backup_stuff() -> List[Tuple[str, str, str]]:
    os.makedirs(TMP_EXCLUDE_DIR, exist_ok=True)
    moved: List[Tuple[str, str, str]] = []
    for pattern in ("/root/*.tar.gz", "/root/*.tgz"):
        for src in glob.glob(pattern):
            dst = os.path.join(TMP_EXCLUDE_DIR, os.path.basename(src))
            try:
                if os.path.abspath(src) != os.path.abspath(dst):
                    if os.path.exists(dst): os.remove(dst)
                    shutil.move(src, dst)
                    moved.append(("file", src, dst))
            except Exception as e:
                print(f"[backup exclude] cannot move {src}: {e}")
    backups_dir = "/root/backups"
    if os.path.isdir(backups_dir):
        dst_dir = os.path.join(TMP_EXCLUDE_DIR, "__backups_dir__")
        try:
            if os.path.exists(dst_dir): shutil.rmtree(dst_dir, ignore_errors=True)
            shutil.move(backups_dir, dst_dir)
            moved.append(("dir", backups_dir, dst_dir))
        except Exception as e:
            print(f"[backup exclude] cannot move {backups_dir}: {e}")
    return moved

def _restore_hidden_root_backup_stuff(moved: List[Tuple[str, str, str]]):
    for kind, src, dst in reversed(moved):
        try:
            if os.path.exists(src):
                if os.path.exists(dst):
                    if kind == "dir": shutil.rmtree(dst, ignore_errors=True)
                    else: os.remove(dst)
                continue
            if os.path.exists(dst):
                os.makedirs(os.path.dirname(src), exist_ok=True)
                shutil.move(dst, src)
        except Exception as e:
            print(f"[backup exclude] cannot restore {src}: {e}")

def create_backup_in_root_excluding_archives() -> str:
    moved = _temporarily_hide_root_backup_stuff()
    try:
        path = br_create_backup()
        if not path or not os.path.exists(path):
            raise RuntimeError("Backup creation failed (no path returned)")
        dest = os.path.join("/root", os.path.basename(path))
        if os.path.abspath(path) != os.path.abspath(dest):
            if os.path.exists(dest): os.remove(dest)
            shutil.move(path, dest)
        else:
            dest = path
        return dest
    finally:
        _restore_hidden_root_backup_stuff(moved)

# ------------------ BULK HANDLERS (delete/send/enable/disable) ------------------
# (Без изменений логики, только сортировки ниже где нужно)

async def start_bulk_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    rows = gather_key_metadata()
    if not rows:
        await safe_edit_text(q, context, "Нет ключей."); return
    url = create_keys_detailed_page()
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    keys_order = [r["name"] for r in rows]
    context.user_data['bulk_delete_keys'] = keys_order
    context.user_data['await_bulk_delete_numbers'] = True
    text = ("<b>Удаление ключей</b>\n"
            "Формат: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
            f"<a href=\"{url}\">Полный список</a>\n\nОтправьте строку с номерами.")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]]))

async def process_bulk_delete_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_delete_numbers'): return
    keys_order: List[str] = context.user_data.get('bulk_delete_keys', [])
    if not keys_order:
        await update.message.reply_text("Список потерян. Начните снова.")
        context.user_data.pop('await_bulk_delete_numbers', None); return
    selection_text = update.message.text.strip()
    idxs, errs = parse_bulk_selection(selection_text, len(keys_order))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs) + "\nПовторите ввод.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]]))
        return
    selected_names = [keys_order[i - 1] for i in idxs]
    context.user_data['bulk_delete_selected'] = selected_names
    context.user_data['await_bulk_delete_numbers'] = False
    preview = "\n".join(selected_names[:25])
    if len(selected_names) > 25:
        preview += f"\n... ещё {len(selected_names)-25}"
    await update.message.reply_text(
        f"<b>Удалить ключи ({len(selected_names)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_delete_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_delete")]
        ])
    )

async def bulk_delete_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    selected: List[str] = context.user_data.get('bulk_delete_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Пусто."); return
    revoked, failed = revoke_and_collect(selected)
    crl_status = generate_crl_once()
    for name in revoked:
        remove_client_files(name)
        disconnect_client_sessions(name)
    context.user_data.pop('bulk_delete_selected', None)
    context.user_data.pop('bulk_delete_keys', None)
    summary = (f"<b>Удаление завершено</b>\n"
               f"Запрошено: {len(selected)}\nRevoked: {len(revoked)}\nОшибок: {len(failed)}\nCRL: {crl_status}")
    if failed:
        summary += "\n\n<b>Ошибки:</b>\n" + "\n".join(failed[:10])
        if len(failed) > 10:
            summary += f"\n... ещё {len(failed)-10}"
    await safe_edit_text(q, context, summary, parse_mode="HTML")

async def bulk_delete_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['bulk_delete_selected', 'bulk_delete_keys', 'await_bulk_delete_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Массовое удаление отменено.")

# ------------------ Массовая отправка ------------------
async def start_bulk_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    if not files:
        await safe_edit_text(q, context, "Нет ключей."); return
    names = [f[:-5] for f in files]
    url = create_names_telegraph_page(names, "Отправка ключей", "Список ключей")
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    context.user_data['bulk_send_keys'] = names
    context.user_data['await_bulk_send_numbers'] = True
    text = ("<b>Отправить ключи</b>\n"
            "Формат: all | 1 | 1,2,5 | 3-7 | 1,2,5-9\n"
            f"<a href=\"{url}\">Список</a>\n\nПришлите строку.")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]]))

async def process_bulk_send_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_send_numbers'): return
    names: List[str] = context.user_data.get('bulk_send_keys', [])
    if not names:
        await update.message.reply_text("Список потерян. Начните заново.")
        context.user_data.pop('await_bulk_send_numbers', None); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs),
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]]))
        return
    selected = [names[i - 1] for i in idxs]
    context.user_data['bulk_send_selected'] = selected
    context.user_data['await_bulk_send_numbers'] = False
    preview = "\n".join(selected[:25])
    if len(selected) > 25: preview += f"\n... ещё {len(selected)-25}"
    await update.message.reply_text(
        f"<b>Отправить ({len(selected)}) ключей:</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_send_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_send")]
        ])
    )

async def bulk_send_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    import asyncio
    q = update.callback_query; await q.answer()
    selected: List[str] = context.user_data.get('bulk_send_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Список пуст."); return
    await safe_edit_text(q, context, f"Отправляю {len(selected)} ключ(ов)...")
    sent = 0
    for name in selected:
        path = os.path.join(KEYS_DIR, f"{name}.ovpn")
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    await context.bot.send_document(chat_id=q.message.chat_id, document=InputFile(f), filename=f"{name}.ovpn")
                sent += 1
                await asyncio.sleep(0.25)
            except Exception as e:
                print(f"[bulk_send] error {name}: {e}")
    for k in ['bulk_send_selected', 'bulk_send_keys', 'await_bulk_send_numbers']:
        context.user_data.pop(k, None)
    await context.bot.send_message(chat_id=q.message.chat_id, text=f"✅ Отправлено: {sent} / {len(selected)}")

async def bulk_send_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['bulk_send_selected', 'bulk_send_keys', 'await_bulk_send_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Массовая отправка отменена.")

# ------------------ Массовое включение ------------------
async def start_bulk_enable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    disabled = [f[:-5] for f in files if is_client_ccd_disabled(f[:-5])]
    if not disabled:
        await safe_edit_text(q, context, "Нет заблокированных клиентов."); return
    url = create_names_telegraph_page(disabled, "Включение клиентов", "Заблокированные клиенты")
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    context.user_data['bulk_enable_keys'] = disabled
    context.user_data['await_bulk_enable_numbers'] = True
    text = ("<b>Включить клиентов</b>\n"
            "Формат: all | 1 | 1,2 | 3-7 ...\n"
            f"<a href=\"{url}\">Список</a>\n\nПришлите строку.")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]]))

async def process_bulk_enable_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_enable_numbers'): return
    names: List[str] = context.user_data.get('bulk_enable_keys', [])
    if not names:
        await update.message.reply_text("Список потерян.")
        context.user_data.pop('await_bulk_enable_numbers', None); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs),
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]]))
        return
    selected = [names[i - 1] for i in idxs]
    context.user_data['bulk_enable_selected'] = selected
    context.user_data['await_bulk_enable_numbers'] = False
    preview = "\n".join(selected[:30])
    if len(selected) > 30: preview += f"\n... ещё {len(selected)-30}"
    await update.message.reply_text(
        f"<b>Включить ({len(selected)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_enable_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_enable")]
        ])
    )

async def bulk_enable_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    selected: List[str] = context.user_data.get('bulk_enable_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Пусто."); return
    for name in selected:
        unblock_client_ccd(name)
    for k in ['bulk_enable_selected', 'bulk_enable_keys', 'await_bulk_enable_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, f"✅ Включено клиентов: {len(selected)}")

async def bulk_enable_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['bulk_enable_selected', 'bulk_enable_keys', 'await_bulk_enable_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Массовое включение отменено.")

# ------------------ Массовое отключение ------------------
async def start_bulk_disable(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    active = [f[:-5] for f in files if not is_client_ccd_disabled(f[:-5])]
    if not active:
        await safe_edit_text(q, context, "Нет активных клиентов."); return
    url = create_names_telegraph_page(active, "Отключение клиентов", "Активные клиенты")
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    context.user_data['bulk_disable_keys'] = active
    context.user_data['await_bulk_disable_numbers'] = True
    text = ("<b>Отключить клиентов</b>\n"
            "Формат: all | 1 | 1,2,7 | 3-10 ...\n"
            f"<a href=\"{url}\">Список</a>\n\nПришлите строку.")
    await safe_edit_text(q, context, text, parse_mode="HTML",
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]]))

async def process_bulk_disable_numbers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_bulk_disable_numbers'): return
    names: List[str] = context.user_data.get('bulk_disable_keys', [])
    if not names:
        await update.message.reply_text("Список потерян.")
        context.user_data.pop('await_bulk_disable_numbers', None); return
    idxs, errs = parse_bulk_selection(update.message.text.strip(), len(names))
    if errs:
        await update.message.reply_text("Ошибки:\n" + "\n".join(errs),
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]]))
        return
    if not idxs:
        await update.message.reply_text("Ничего не выбрано.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]]))
        return
    selected = [names[i - 1] for i in idxs]
    context.user_data['bulk_disable_selected'] = selected
    context.user_data['await_bulk_disable_numbers'] = False
    preview = "\n".join(selected[:30])
    if len(selected) > 30: preview += f"\n... ещё {len(selected)-30}"
    await update.message.reply_text(
        f"<b>Отключить ({len(selected)}):</b>\n<code>{preview}</code>\nПодтвердить?",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="bulk_disable_confirm")],
            [InlineKeyboardButton("❌ Отмена", callback_data="cancel_bulk_disable")]
        ])
    )

async def bulk_disable_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    selected: List[str] = context.user_data.get('bulk_disable_selected', [])
    if not selected:
        await safe_edit_text(q, context, "Пусто."); return
    for name in selected:
        block_client_ccd(name); disconnect_client_sessions(name)
    for k in ['bulk_disable_selected', 'bulk_disable_keys', 'await_bulk_disable_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, f"⚠️ Отключено клиентов: {len(selected)}")

async def bulk_disable_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['bulk_disable_selected', 'bulk_disable_keys', 'await_bulk_disable_numbers']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Массовое отключение отменено.")

# ------------------ UPDATE REMOTE ------------------
CLIENT_TEMPLATE_CANDIDATES = [
    "/etc/openvpn/client-template.txt",
    "/root/openvpn/client-template.txt"
]

def find_client_template_path() -> Optional[str]:
    for p in CLIENT_TEMPLATE_CANDIDATES:
        if os.path.exists(p): return p
    return None

def replace_remote_line_in_text(text: str, new_host: str, new_port: str) -> str:
    lines = []; replaced = False
    for line in text.splitlines():
        if line.strip().startswith("remote "):
            lines.append(f"remote {new_host} {new_port}"); replaced = True
        else:
            lines.append(line)
    if not replaced:
        lines.append(f"remote {new_host} {new_port}")
    return "\n".join(lines) + "\n"

def update_template_and_ovpn(new_host: str, new_port: str) -> Dict[str, int]:
    stats = {"template_updated": 0, "ovpn_updated": 0, "errors": 0}
    tpl = find_client_template_path()
    if tpl:
        try:
            with open(tpl, "r") as f: old = f.read()
            new = replace_remote_line_in_text(old, new_host, new_port)
            if new != old:
                backup = tpl + ".bak_" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
                shutil.copy2(tpl, backup)
                with open(tpl, "w") as f: f.write(new)
                stats["template_updated"] = 1
        except Exception as e:
            print(f"[update_remote] template error: {e}"); stats["errors"] += 1
    else:
        print("[update_remote] template not found")
    for f in get_ovpn_files():
        path = os.path.join(KEYS_DIR, f)
        try:
            with open(path, "r") as fr: oldc = fr.read()
            newc = replace_remote_line_in_text(oldc, new_host, new_port)
            if newc != oldc:
                bak = path + ".bak_" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
                shutil.copy2(path, bak)
                with open(path, "w") as fw: fw.write(newc)
                stats["ovpn_updated"] += 1
        except Exception as e:
            print(f"[update_remote] file {f} error: {e}"); stats["errors"] += 1
    return stats

async def start_update_remote_dialog(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    tpl = find_client_template_path()
    tpl_info = tpl if tpl else "не найден"
    text = ("Введите новый remote в формате host:port\n"
            f"(Обнаруженный шаблон: {tpl_info})\nПример: vpn.example.com:1194")
    await safe_edit_text(q, context, text,
                         reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_update_remote")]]))
    context.user_data['await_remote_input'] = True

async def process_remote_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_remote_input'): return
    raw = update.message.text.strip()
    if ':' not in raw:
        await update.message.reply_text("Формат неверный. Нужно host:port. Пример: myvpn.com:1194"); return
    host, port = raw.split(':', 1)
    host, port = host.strip(), port.strip()
    if not host or not port.isdigit():
        await update.message.reply_text("Некорректные host или port."); return
    stats = update_template_and_ovpn(host, port)
    context.user_data.pop('await_remote_input', None)
    await update.message.reply_text(
        f"✅ Обновление завершено.\nШаблон: {stats['template_updated']}\n.ovpn изменено: {stats['ovpn_updated']}\nОшибок: {stats['errors']}"
    )

# ------------------ HELP ------------------
HELP_TEXT = """
🧰 OpenVPN Monitor Bot — справка

Этот бот управляет OpenVPN и помогает:
• смотреть статус ключей (онлайн/оффлайн/заблокирован)
• смотреть/очищать трафик (если включён учёт)
• создавать/отправлять ключи (.ovpn)
• включать/выключать клиента (CCD)
• делать бэкап/восстановление
• смотреть хвост логов и диагностировать ошибки

────────────────────────────────────────────
1) Обозначения в “Статус всех ключей”
🟢  клиент онлайн (есть в status.log)
🔴  клиент оффлайн
⛔  клиент отключён (CCD/disable)

────────────────────────────────────────────
2) Пути и файлы (смотри также /help → “TLS/пути”)
Обычно используется:
OPENVPN_DIR : /etc/openvpn/server
EASYRSA_DIR : /etc/openvpn/server/easy-rsa
CCD_DIR     : /etc/openvpn/server/ccd

Файлы:
• server.conf                 → /etc/openvpn/server/server.conf
• tls-crypt (обычный)         → /etc/openvpn/server/tls-crypt.key
• tls-crypt-v2 (серверный)    → /etc/openvpn/server/tls-crypt-v2.key
• ipp.txt (пулы адресов)      → определяется автоматически из server.conf (ifconfig-pool-persist)
• status.log (онлайн/байты)   → обычно /var/log/openvpn/status.log
  (в systemd-инстансе может быть /run/openvpn-server/status-server.log)

────────────────────────────────────────────
3) Сервисы (systemd) — самые нужные команды

OpenVPN (инстанс):
• Статус:
  systemctl status openvpn-server@server --no-pager -l
• Перезапуск:
  systemctl restart openvpn-server@server
• Логи (последние 200 строк):
  journalctl -u openvpn-server@server -n 200 --no-pager
• Логи “вживую”:
  journalctl -u openvpn-server@server -f

Бот:
• Статус:
  systemctl status vpn_bot.service --no-pager -l
• Перезапуск:
  systemctl restart vpn_bot.service
• Логи:
  journalctl -u vpn_bot.service -n 200 --no-pager
• Логи “вживую”:
  journalctl -u vpn_bot.service -f

────────────────────────────────────────────
4) Если OpenVPN “не перезапускается / timeout”
Иногда systemd ждёт sd_notify и даёт timeout. Решение — override:
mkdir -p /etc/systemd/system/openvpn-server@.service.d

cat > /etc/systemd/system/openvpn-server@.service.d/override.conf <<'EOF'
[Service]
Type=simple
EOF

systemctl daemon-reload
systemctl restart openvpn-server@server

────────────────────────────────────────────
5) UDP: чтобы не было “10–15 секунд и трафик в ноль”
Для UDP обычно помогает:
explicit-exit-notify 1
(добавляется в server.conf для UDP-сервера)

────────────────────────────────────────────
6) TLS режимы (важное)
• tls-crypt-v2:
  - у каждого клиента свой tls-crypt-v2 client key
  - на сервере хранится tls-crypt-v2.key
• tls-crypt (обычный):
  - один общий tls-crypt.key на всех клиентов

В боте генерация .ovpn должна подхватывать правильный TLS-режим
по server.conf и добавлять нужный блок (<tls-crypt-v2> или <tls-crypt>).

────────────────────────────────────────────
7) Про “Трафик” в боте
Учёт трафика берётся из status.log (Bytes Received / Bytes Sent).
Если у тебя “0.00 GB”, проверь:
• какой status.log реально пишет OpenVPN (см. пути выше)
• что включён status-version 2 и обновляется status.log
• что в status.log есть строки CLIENT_LIST с байтами

────────────────────────────────────────────
8) Быстрая проверка status.log вручную
tail -n 30 /var/log/openvpn/status.log

Если status.log в /run:
tail -n 30 /run/openvpn-server/status-server.log

────────────────────────────────────────────
9) Что прислать, если что-то сломалось
1) journalctl -u vpn_bot.service -n 200 --no-pager
2) journalctl -u openvpn-server@server -n 200 --no-pager
3) tail -n 60 status.log (тот, который реально используется)
4) первые ~80 строк /etc/openvpn/server/server.conf (без приватных ключей)

"""


def build_help_messages():
    esc = escape(HELP_TEXT.strip("\n"))
    lines = esc.splitlines()
    parts, block, cur_len = [], [], 0
    LIMIT = 3500
    for line in lines:
        l = len(line) + 1
        if block and cur_len + l > LIMIT:
            content = "\n".join(block)
            parts.append(f"<b>Помощь</b>\n<pre>{content}</pre>")
            block = [line]; cur_len = l
        else:
            block.append(line); cur_len += l
    if block:
        content = "\n".join(block)
        parts.append(f"<b>Помощь</b>\n<pre>{content}</pre>")
    return parts

async def send_help_messages(context: ContextTypes.DEFAULT_TYPE, chat_id: int):
    for part in build_help_messages():
        await context.bot.send_message(chat_id=chat_id, text=part, parse_mode="HTML")

# ------------------ MAIN KEYBOARD ------------------
def get_main_keyboard():
    keyboard = [
        [InlineKeyboardButton("🔄 Список клиентов", callback_data='refresh')],
        [InlineKeyboardButton("📊 Статистика", callback_data='stats'),
         InlineKeyboardButton("🛣️ Тунель", callback_data='send_ipp')],
        [InlineKeyboardButton("📶 Трафик", callback_data='traffic'),
         InlineKeyboardButton("🔗 Обновление", callback_data='update_info')],
        [InlineKeyboardButton("🧹 Очистить трафик", callback_data='traffic_clear'),
         InlineKeyboardButton("🌐 Обновить адрес", callback_data='update_remote')],
        [InlineKeyboardButton("⏳ Сроки ключей", callback_data='keys_expiry'),
         InlineKeyboardButton("⌛ Обновить ключ", callback_data='renew_key')],
        [InlineKeyboardButton("✅ Вкл.клиента", callback_data='bulk_enable_start'),
         InlineKeyboardButton("⚠️ Откл.клиента", callback_data='bulk_disable_start')],
        [InlineKeyboardButton("➕ Создать ключ", callback_data='create_key'),
         InlineKeyboardButton("🗑️ Удалить ключ", callback_data='bulk_delete_start')],
        [InlineKeyboardButton("📤 Отправить ключи", callback_data='bulk_send_start'),
         InlineKeyboardButton("📜 Просмотр лога", callback_data='log')],
        [InlineKeyboardButton("📦 Бэкап OpenVPN", callback_data='backup_menu'),
         InlineKeyboardButton("🔄 Восстан.бэкап", callback_data='restore_menu')],
        [InlineKeyboardButton("🚨 Тревога ON", callback_data='alarm_on'), InlineKeyboardButton("🛑 Тревога OFF", callback_data='alarm_off')],
        [InlineKeyboardButton("❓ Помощь", callback_data='help'),
         InlineKeyboardButton("🏠 В главное меню", callback_data='home')],
    ]
    return InlineKeyboardMarkup(keyboard)

# ------------------ Генерация .ovpn ------------------
def extract_pem_cert(cert_path: str) -> str:
    with open(cert_path, "r") as f:
        lines = f.read().splitlines()
    in_pem = False
    out = []
    for line in lines:
        if "-----BEGIN CERTIFICATE-----" in line:
            in_pem = True
        if in_pem:
            out.append(line)
        if "-----END CERTIFICATE-----" in line:
            break
    return "\n".join(out).strip()

def generate_ovpn_for_client(
    client_name,
    output_dir=KEYS_DIR,
    template_path=f"{OPENVPN_DIR}/client-template.txt",
    ca_path=f"{EASYRSA_DIR}/pki/ca.crt",
    cert_path=None,
    key_path=None,
    tls_crypt_path=f"{OPENVPN_DIR}/tls-crypt.key",
    tls_crypt_v2_path=f"{OPENVPN_DIR}/tls-crypt-v2.key",
    tls_auth_path=f"{OPENVPN_DIR}/tls-auth.key",
    server_conf_path=f"{OPENVPN_DIR}/server.conf",
    openvpn_bin="/usr/sbin/openvpn",
):
    """
    Генерация .ovpn:
      - Всегда: template + <ca> + <cert> + <key>
      - Если сервер tls-crypt-v2: добавляем <tls-crypt-v2> (генерим через openvpn --tls-crypt-v2 ... --genkey tls-crypt-v2-client)
      - Иначе если tls-crypt: добавляем <tls-crypt>
      - Иначе если tls-auth: добавляем key-direction 1 + <tls-auth>
    """

    if cert_path is None:
        cert_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
    if key_path is None:
        key_path = f"{EASYRSA_DIR}/pki/private/{client_name}.key"

    ovpn_file = os.path.join(output_dir, f"{client_name}.ovpn")

    # --- читаем server.conf и определяем режим ---
    conf = ""
    if server_conf_path and os.path.exists(server_conf_path):
        with open(server_conf_path, "r", encoding="utf-8", errors="ignore") as f:
            conf = f.read()

    # порядок важен: сначала v2, потом tls-crypt, потом tls-auth
    tls_mode = None
    if "tls-crypt-v2" in conf:
        tls_mode = "tls-crypt-v2"
    elif "tls-crypt" in conf:
        tls_mode = "tls-crypt"
    elif "tls-auth" in conf:
        tls_mode = "tls-auth"

    # --- читаем шаблон/серты ---
    with open(template_path, "r", encoding="utf-8", errors="ignore") as f:
        template_content = f.read().rstrip()

    with open(ca_path, "r", encoding="utf-8", errors="ignore") as f:
        ca_content = f.read().strip()

    # у тебя уже есть extract_pem_cert() в коде — используем её
    cert_content = extract_pem_cert(cert_path)

    with open(key_path, "r", encoding="utf-8", errors="ignore") as f:
        key_content = f.read().strip()

    content = (
        template_content + "\n"
        + "<ca>\n" + ca_content + "\n</ca>\n"
        + "<cert>\n" + cert_content + "\n</cert>\n"
        + "<key>\n" + key_content + "\n</key>\n"
    )

    # --- добавляем TLS блок ---
    if tls_mode == "tls-crypt-v2":
        # генерируем клиентский tls-crypt-v2 ключ
        tmp_v2 = f"/tmp/{client_name}.tls-crypt-v2.key"
        if os.path.exists(tmp_v2):
            try:
                os.remove(tmp_v2)
            except:
                pass

        # openvpn --tls-crypt-v2 <serverkey> --genkey tls-crypt-v2-client <outfile>
        cmd = [
            openvpn_bin,
            "--tls-crypt-v2", tls_crypt_v2_path,
            "--genkey", "tls-crypt-v2-client", tmp_v2,
        ]
        subprocess.run(cmd, check=True)

        with open(tmp_v2, "r", encoding="utf-8", errors="ignore") as f:
            v2_client_key = f.read().strip()

        content += "<tls-crypt-v2>\n" + v2_client_key + "\n</tls-crypt-v2>\n"

    elif tls_mode == "tls-crypt" and tls_crypt_path and os.path.exists(tls_crypt_path):
        with open(tls_crypt_path, "r", encoding="utf-8", errors="ignore") as f:
            tls_crypt_content = f.read().strip()
        content += "<tls-crypt>\n" + tls_crypt_content + "\n</tls-crypt>\n"

    elif tls_mode == "tls-auth" and tls_auth_path and os.path.exists(tls_auth_path):
        with open(tls_auth_path, "r", encoding="utf-8", errors="ignore") as f:
            tls_auth_content = f.read().strip()
        content += "key-direction 1\n"
        content += "<tls-auth>\n" + tls_auth_content + "\n</tls-auth>\n"

    # --- сохраняем .ovpn ---
    os.makedirs(output_dir, exist_ok=True)
    with open(ovpn_file, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)

    return ovpn_file


# ------------------ Создание ключей (расширено) ------------------
async def create_key_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Шаг 1: Имя клиента
    if context.user_data.get('await_key_name'):
        key_name = update.message.text.strip()
        if not key_name:
            await update.message.reply_text("Имя пустое. Введите имя:")
            return
        ovpn_file = os.path.join(KEYS_DIR, f"{key_name}.ovpn")
        if os.path.exists(ovpn_file):
            await update.message.reply_text("Такой клиент существует, введите другое имя.")
            return
        context.user_data['new_key_name'] = key_name
        context.user_data['await_key_name'] = False
        context.user_data['await_key_expiry'] = True
        await update.message.reply_text("Введите логический срок (дней, по умолчанию 30):")
        return

    # Шаг 2: Срок
    if context.user_data.get('await_key_expiry'):
        try:
            days = int(update.message.text.strip())
            if days < 1: raise ValueError
        except:
            days = 30
        context.user_data['new_key_expiry'] = days
        context.user_data['await_key_expiry'] = False
        context.user_data['await_key_quantity'] = True
        await update.message.reply_text("Введите количество ключей (по умолчанию 1):")
        return

    # Шаг 3: Количество
    if context.user_data.get('await_key_quantity'):
        try:
            qty = int(update.message.text.strip())
            if qty < 1: raise ValueError
        except:
            qty = 1
        if qty > 100:
            await update.message.reply_text("Слишком много. Максимум 100. Введите снова:")
            return
        base = context.user_data.get('new_key_name')
        days = context.user_data.get('new_key_expiry', 30)

        # Формируем список имён
        if qty == 1:
            names = [base]
        else:
            # base, base2, base3...
            names = [base] + [f"{base}{i}" for i in range(2, qty + 1)]

        # Проверка коллизий
        collisions = [n for n in names if os.path.exists(os.path.join(KEYS_DIR, f"{n}.ovpn"))]
        if collisions:
            await update.message.reply_text(
                "Конфликт имён (существуют): " + ", ".join(collisions) +
                "\nВведите другое базовое имя /start → Создать ключ"
            )
            context.user_data.clear()
            return

        created = []
        errors = []
        for n in names:
            try:
                subprocess.run(
                    f"EASYRSA_CERT_EXPIRE=3650 {EASYRSA_DIR}/easyrsa --batch build-client-full {n} nopass",
                    shell=True, check=True, cwd=EASYRSA_DIR
                )
                ovpn_path = generate_ovpn_for_client(n)
                iso = set_client_expiry_days_from_now(n, days)
                created.append((n, ovpn_path, iso))
            except subprocess.CalledProcessError as e:
                errors.append(f"{n}: {e}")
            except Exception as e:
                errors.append(f"{n}: {e}")

        # Отправка результатов
        if created:
            await update.message.reply_text(
                f"Создано ключей: {len(created)} (срок ~{days} дн)", parse_mode="HTML"
            )
            for (n, path, iso) in created:
                try:
                    await update.message.reply_text(f"{n}: до {iso}\n{path}")
                    with open(path, "rb") as f:
                        await context.bot.send_document(
                            chat_id=update.effective_chat.id,
                            document=InputFile(f),
                            filename=f"{n}.ovpn"
                        )
                except Exception as e:
                    await update.message.reply_text(f"Ошибка отправки {n}: {e}")
        if errors:
            err_txt = "\n".join(errors[:10])
            if len(errors) > 10: err_txt += f"\n... ещё {len(errors)-10}"
            await update.message.reply_text(f"Ошибки:\n{err_txt}")

        context.user_data.clear()
        return

# ------------------ Renew (логический) ------------------
async def renew_key_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer()
    rows = gather_key_metadata()
    if not rows:
        await safe_edit_text(q, context, "Нет ключей."); return
    url = create_keys_detailed_page()
    if not url:
        await safe_edit_text(q, context, "Ошибка Telegraph."); return
    order = [r["name"] for r in rows]
    context.user_data['renew_keys_order'] = order
    context.user_data['await_renew_number'] = True
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]])
    text = ("<b>Установить новый логический срок</b>\n"
            "Открой список и введи НОМЕР клиента:\n"
            f"<a href=\"{url}\">Список (Telegraph)</a>\n\nПример: 5")
    await safe_edit_text(q, context, text, parse_mode="HTML", reply_markup=kb)

async def process_renew_number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_renew_number'): return
    text = update.message.text.strip()
    if not re.fullmatch(r"\d+", text):
        await update.message.reply_text("Нужно ввести один номер клиента.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]]))
        return
    idx = int(text)
    order: List[str] = context.user_data.get('renew_keys_order', [])
    if not order:
        await update.message.reply_text("Список потерян. Начните заново.")
        context.user_data.pop('await_renew_number', None); return
    if idx < 1 or idx > len(order):
        await update.message.reply_text(f"Номер вне диапазона 1..{len(order)}.",
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Отмена", callback_data="cancel_renew")]]))
        return
    key_name = order[idx - 1]
    context.user_data['renew_key_name'] = key_name
    context.user_data['await_renew_number'] = False
    context.user_data['await_renew_expiry'] = True
    await update.message.reply_text(f"Введите НОВЫЙ срок (дней) для {key_name}:")

async def renew_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer("Отменено")
    for k in ['await_renew_number', 'await_renew_expiry', 'renew_keys_order', 'renew_key_name']:
        context.user_data.pop(k, None)
    await safe_edit_text(q, context, "Продление отменено.")

async def renew_key_select_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа", show_alert=True); return
    await q.answer()
    data = q.data
    key_name = data.split('_', 1)[1]
    context.user_data['renew_key_name'] = key_name
    context.user_data['await_renew_expiry'] = True
    await safe_edit_text(q, context, f"Введите НОВЫЙ срок (дней) для {key_name}:")

async def renew_key_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get('await_renew_expiry'): return
    key_name = context.user_data['renew_key_name']
    try:
        days = int(update.message.text.strip())
        if days < 1: raise ValueError
    except Exception:
        await update.message.reply_text("Некорректное число дней."); return
    iso = set_client_expiry_days_from_now(key_name, days)
    await update.message.reply_text(f"Логический срок для {key_name} установлен до: {iso} (~{days} дн). Клиент разблокирован.")
    context.user_data.clear()

# ------------------ Лог ------------------
def get_status_log_tail(n=40):
    try:
        with open(STATUS_LOG, "r") as f:
            lines = f.readlines()
        return "".join(lines[-n:])
    except Exception as e:
        return f"Ошибка чтения status.log: {e}"

def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

async def log_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    log_text = get_status_log_tail()
    safe = _html_escape(log_text)
    msgs = split_message(f"<b>status.log (хвост):</b>\n<pre>{safe}</pre>")
    await safe_edit_text(q, context, msgs[0], parse_mode="HTML")
    for m in msgs[1:]:
        await context.bot.send_message(chat_id=q.message.chat_id, text=m, parse_mode="HTML")

# ------------------ Backup / Restore UI ------------------
def list_backups() -> List[str]:
    # Бэкапы сортируем как было (по имени, обратный порядок) — менять не просили
    return sorted([os.path.basename(p) for p in glob.glob("/root/openvpn_full_backup_*.tar.gz")], reverse=True)

async def perform_backup_and_send(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    try:
        path = create_backup_in_root_excluding_archives()
        size = os.path.getsize(path)
        txt = f"✅ Бэкап создан: <code>{os.path.basename(path)}</code>\nРазмер: {size/1024/1024:.2f} MB"
        q = update.callback_query
        await safe_edit_text(q, context, txt, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("📤 Отправить", callback_data=f"backup_send_{os.path.basename(path)}")],
            [InlineKeyboardButton("📦 Список", callback_data="backup_list")],
        ]))
    except Exception as e:
        await update.callback_query.edit_message_text(f"Ошибка бэкапа: {e}")

async def send_backup_file(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    if not os.path.exists(full):
        await safe_edit_text(update.callback_query, context, "Файл не найден."); return
    with open(full, "rb") as f:
        await context.bot.send_document(chat_id=update.effective_chat.id, document=InputFile(f), filename=fname)
    await safe_edit_text(update.callback_query, context, "Отправлен.")

async def show_backup_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    bl = list_backups()
    if not bl:
        await safe_edit_text(update.callback_query, context, "Бэкапов нет."); return
    kb = [[InlineKeyboardButton(b, callback_data=f"backup_info_{b}")] for b in bl[:15]]
    await safe_edit_text(update.callback_query, context, "Список бэкапов:", reply_markup=InlineKeyboardMarkup(kb))

async def show_backup_info(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    staging = f"/tmp/info_{int(time.time())}"
    os.makedirs(staging, exist_ok=True)
    try:
        import tarfile
        with tarfile.open(full, "r:gz") as tar:
            tar.extractall(staging)
        manifest_path = os.path.join(staging, MANIFEST_NAME)
        if not os.path.exists(manifest_path):
            await safe_edit_text(update.callback_query, context, "manifest.json отсутствует."); return
        with open(manifest_path, "r") as f:
            m = json.load(f)
        clients = m.get("openvpn_pki", {}).get("clients", [])
        v_count = sum(1 for c in clients if c.get("status") == "V")
        r_count = sum(1 for c in clients if c.get("status") == "R")
        txt = (f"<b>{fname}</b>\nСоздан: {m.get('created_at')}\n"
               f"Файлов: {len(m.get('files', []))}\n"
               f"Клиентов V: {v_count} / R: {r_count}\nПоказать diff?")
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🧪 Diff", callback_data=f"restore_dry_{fname}")],
            [InlineKeyboardButton("📤 Отправить", callback_data=f"backup_send_{fname}")],
            [InlineKeyboardButton("🗑️ Удалить", callback_data=f"backup_delete_{fname}")],
        ])
        await safe_edit_text(update.callback_query, context, txt, parse_mode="HTML", reply_markup=kb)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

async def restore_dry_run(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    backup_path = locate_backup(fname)
    if not backup_path:
        await safe_edit_text(update.callback_query, context,
                             f"Файл '{fname}' не найден ни в /root, ни в /root/backups.",
                             parse_mode="HTML")
        return
    try:
        report = apply_restore(backup_path, dry_run=True)
        diff = report["diff"]
        def lim(lst):
            return lst[:6] + [f"... ещё {len(lst)-6}"] if len(lst) > 6 else lst
        text = (f"<b>Diff {os.path.basename(backup_path)}</b>\n"
                f"Extra: {len(diff['extra'])}\n" + "\n".join(lim(diff['extra'])) + "\n\n"
                f"Missing: {len(diff['missing'])}\n" + "\n".join(lim(diff['missing'])) + "\n\n"
                f"Changed: {len(diff['changed'])}\n" + "\n".join(lim(diff['changed'])) + "\n\n"
                "Применить restore?")
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⚠️ Применить", callback_data=f"restore_apply_{fname}")],
            [InlineKeyboardButton("⬅️ Назад", callback_data=f"backup_info_{fname}")]
        ])
        await safe_edit_text(update.callback_query, context, text, parse_mode="HTML", reply_markup=kb)
    except Exception as e:
        await safe_edit_text(update.callback_query, context, f"Ошибка dry-run: {e}", parse_mode="HTML")

async def restore_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    backup_path = locate_backup(fname)
    if not backup_path:
        await safe_edit_text(update.callback_query, context,
                             f"Файл '{fname}' не найден ни в BACKUP_OUTPUT_DIR, ни в /root, ни в /root/backups.",
                             parse_mode="HTML")
        return
    try:
        report = apply_restore(backup_path, dry_run=False)
        diff = report["diff"]
        text = (f"<b>Restore:</b> {os.path.basename(backup_path)}\n"
                f"Удалено extra: {len(diff['extra'])}\n"
                f"Missing: {len(diff['missing'])}\n"
                f"Changed: {len(diff['changed'])}\n"
                f"CRL: {report.get('crl_action')}\n"
                f"OpenVPN restart: {report.get('service_restart')}")
        await safe_edit_text(update.callback_query, context, text, parse_mode="HTML")
    except Exception as e:
        tb = traceback.format_exc()
        await safe_edit_text(update.callback_query, context, f"Ошибка restore: {e}\n{tb[-400:]}", parse_mode="HTML")

async def backup_delete_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    if not os.path.exists(full):
        await safe_edit_text(update.callback_query, context, "Файл не найден."); return
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Да, удалить", callback_data=f"backup_delete_confirm_{fname}")],
        [InlineKeyboardButton("⬅️ Назад", callback_data=f"backup_info_{fname}")]
    ])
    await safe_edit_text(update.callback_query, context, f"Удалить бэкап <b>{fname}</b>?", parse_mode="HTML", reply_markup=kb)

async def backup_delete_apply(update: Update, context: ContextTypes.DEFAULT_TYPE, fname: str):
    full = os.path.join("/root", fname)
    try:
        if os.path.exists(full):
            os.remove(full)
            await safe_edit_text(update.callback_query, context, "🗑️ Бэкап удалён.")
            await show_backup_list(update, context)
        else:
            await safe_edit_text(update.callback_query, context, "Файл не найден.")
    except Exception as e:
        await safe_edit_text(update.callback_query, context, f"Ошибка удаления: {e}")

async def backup_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🆕 Создать бэкап", callback_data="backup_create")],
        [InlineKeyboardButton("📦 Список бэкапов", callback_data="backup_list")],
    ])
    await safe_edit_text(q, context, "Меню бэкапов:", reply_markup=kb)

async def restore_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("📦 Список бэкапов", callback_data="backup_list")]])
    await safe_edit_text(q, context, "Восстановление: выбери бэкап → Diff → Применить.", reply_markup=kb)

# ------------------ Трафик ------------------
def load_traffic_db():
    global traffic_usage
    try:
        if os.path.exists(TRAFFIC_DB_PATH):
            with open(TRAFFIC_DB_PATH, "r") as f:
                raw = json.load(f)
            migrated = {}
            for k, v in raw.items():
                if isinstance(v, dict):
                    migrated[k] = {'rx': int(v.get('rx', 0)), 'tx': int(v.get('tx', 0))}
            traffic_usage = migrated
        else:
            traffic_usage = {}
    except Exception as e:
        print(f"[traffic] load error: {e}")
        traffic_usage = {}

def save_traffic_db(force=False):
    global _last_traffic_save_time
    now = time.time()
    if not force and now - _last_traffic_save_time < TRAFFIC_SAVE_INTERVAL: return
    try:
        tmp = TRAFFIC_DB_PATH + ".tmp"
        with open(tmp, "w") as f: json.dump(traffic_usage, f)
        os.replace(tmp, TRAFFIC_DB_PATH)
        _last_traffic_save_time = now
    except Exception as e:
        print(f"[traffic] save error: {e}")

def update_traffic_from_status(clients):
    """Accumulate per-client traffic deltas from status bytes counters."""
    global traffic_usage, _last_session_state
    changed = False

    for c in clients:
        name = c.get("name", "").strip()
        if not name:
            continue

        # bytes in status are cumulative since connection start
        try:
            recv = int(c.get("bytes_recv", 0))
            sent = int(c.get("bytes_sent", 0))
        except Exception:
            continue

        connected_since = c.get("connected_since", "") or ""

        if name not in traffic_usage:
            traffic_usage[name] = {"rx": 0, "tx": 0}

        prev = _last_session_state.get(name)
        if prev is None or prev.get("connected_since") != connected_since:
            # new session (or first time): set baseline
            _last_session_state[name] = {"connected_since": connected_since, "rx": recv, "tx": sent}
            continue

        # delta from previous snapshot
        delta_rx = recv - int(prev.get("rx", 0))
        delta_tx = sent - int(prev.get("tx", 0))

        # handle counter reset (shouldn't happen often)
        if delta_rx < 0:
            delta_rx = recv
        if delta_tx < 0:
            delta_tx = sent

        if delta_rx or delta_tx:
            traffic_usage[name]["rx"] += delta_rx
            traffic_usage[name]["tx"] += delta_tx
            changed = True

        prev["rx"] = recv
        prev["tx"] = sent

    if changed:
        save_traffic_db(force=True)

def clear_traffic_stats():
    global traffic_usage, _last_session_state
    try:
        if os.path.exists(TRAFFIC_DB_PATH):
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            subprocess.run(f"cp {TRAFFIC_DB_PATH} {TRAFFIC_DB_PATH}.bak_{ts}", shell=True)
    except: pass
    traffic_usage = {}; _last_session_state = {}
    save_traffic_db(force=True)

def build_traffic_report():
    if not traffic_usage:
        return "<b>Трафик:</b>\nНет данных."
    items = sorted(traffic_usage.items(), key=lambda x: x[1]['rx'] + x[1]['tx'], reverse=True)
    lines = ["<b>Использование трафика:</b>"]
    for name, val in items:
        total = val['rx'] + val['tx']
        lines.append(f"• {name}: {total/1024/1024/1024:.2f} GB")
    return "\n".join(lines)

# ------------------ Monitoring loop ------------------
async def check_new_connections(app: Application):
    import asyncio
    global clients_last_online, last_alert_time
    if not hasattr(check_new_connections, "_last_enforce"):
        check_new_connections._last_enforce = 0
    while True:
        try:
            clients, online_names, tunnel_ips = parse_openvpn_status()
            update_traffic_from_status(clients)
            now_t = time.time()
            if now_t - check_new_connections._last_enforce > ENFORCE_INTERVAL_SECONDS:
                enforce_client_expiries()
                check_and_notify_expiring(app.bot)
                check_new_connections._last_enforce = now_t
            online_count = len(online_names)
            alarm_on = alarm_is_enabled()
            alarm_on = alarm_is_enabled()
            total_keys = len(get_ovpn_files())
            now = time.time()
            if online_count == 0 and total_keys > 0:
                if alarm_on and now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(ADMIN_ID, "❌ Все клиенты оффлайн!", parse_mode="HTML")
                    last_alert_time = now
            elif 0 < online_count < MIN_ONLINE_ALERT:
                if alarm_on and now - last_alert_time > ALERT_INTERVAL_SEC:
                    await app.bot.send_message(ADMIN_ID, f"⚠️ Онлайн мало: {online_count}/{total_keys}", parse_mode="HTML")
                    last_alert_time = now
            else:
                if online_count >= MIN_ONLINE_ALERT:
                    last_alert_time = 0
            clients_last_online = set(online_names)
            await asyncio.sleep(10)
        except Exception as e:
            print(f"[monitor] {e}")
            await asyncio.sleep(10)

def parse_openvpn_status(status_path: str = "/var/log/openvpn/status.log"):
    """
    Парсит OpenVPN status.log
    Поддержка:
      - CSV (status-version 2): строки CLIENT_LIST,<CN>,<Real>,<Virtual>,...
      - Старый формат: секции OpenVPN CLIENT LIST / ROUTING TABLE
    Возвращает: (clients_list, online_names_set, tunnel_ips_dict)
    """
    clients = []
    online_names = set()
    tunnel_ips = {}

    try:
        if not status_path or not os.path.exists(status_path):
            return clients, online_names, tunnel_ips

        with open(status_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # --- Самое главное: если есть CSV строки CLIENT_LIST, берём их напрямую ---
        csv_client_lines = [ln.strip() for ln in lines if ln.startswith("CLIENT_LIST,")]
        if csv_client_lines:
            for line in csv_client_lines:
                parts = line.split(",")
                # CLIENT_LIST,CommonName,RealAddress,VirtualAddress,VirtualIPv6,BytesRecv,BytesSent,ConnectedSince,...
                if len(parts) < 4:
                    continue

                name = parts[1].strip()
                real = parts[2].strip()
                virt = parts[3].strip()

                bytes_recv = parts[5].strip() if len(parts) > 5 else "0"
                bytes_sent = parts[6].strip() if len(parts) > 6 else "0"
                connected_since = parts[7].strip() if len(parts) > 7 else ""

                ip, port = "", ""
                if real:
                    if ":" in real:
                        ip, port = real.rsplit(":", 1)
                    else:
                        ip = real

                if name:
                    online_names.add(name)
                    if virt:
                        tunnel_ips[name] = virt

                clients.append({
                    "name": name,
                    "ip": ip,
                    "port": port,
                    "bytes_recv": bytes_recv,
                    "bytes_sent": bytes_sent,
                    "connected_since": connected_since,
                })

            return clients, online_names, tunnel_ips

        # --- Фолбэк: старый текстовый формат ---
        section = None
        for raw in lines:
            line = raw.strip()
            if not line:
                section = None
                continue

            if line.startswith("OpenVPN CLIENT LIST"):
                section = "CLIENT_LIST"
                continue
            if line.startswith("ROUTING TABLE"):
                section = "ROUTING_TABLE"
                continue

            if section == "CLIENT_LIST":
                if line.startswith("Common Name,"):
                    continue
                if "," not in line:
                    continue
                parts = line.split(",")
                if len(parts) < 2:
                    continue
                name = parts[0].strip()
                real = parts[1].strip()
                ip, port = "", ""
                if real:
                    if ":" in real:
                        ip, port = real.rsplit(":", 1)
                    else:
                        ip = real

                bytes_recv = parts[2].strip() if len(parts) > 2 else "0"
                bytes_sent = parts[3].strip() if len(parts) > 3 else "0"
                connected_since = parts[4].strip() if len(parts) > 4 else ""

                if name:
                    online_names.add(name)

                clients.append({
                    "name": name,
                    "ip": ip,
                    "port": port,
                    "bytes_recv": bytes_recv,
                    "bytes_sent": bytes_sent,
                    "connected_since": connected_since,
                })

            elif section == "ROUTING_TABLE":
                if line.startswith("Virtual Address,"):
                    continue
                if "," not in line:
                    continue
                parts = line.split(",")
                if len(parts) < 2:
                    continue
                virt = parts[0].strip()
                name = parts[1].strip()
                if name:
                    online_names.add(name)
                    if virt:
                        tunnel_ips[name] = virt

    except Exception as e:
        print(f"[parse_openvpn_status] {e}")

    return clients, online_names, tunnel_ips


# ------------------ safe_edit_text ------------------
async def safe_edit_text(q, context, text, **kwargs):
    if MENU_MESSAGE_ID and q.message.message_id == MENU_MESSAGE_ID:
        await context.bot.send_message(chat_id=q.message.chat_id, text=text, **kwargs)
    else:
        await q.edit_message_text(text, **kwargs)

# ------------------ Универсальный текстовый ввод ------------------
async def universal_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    if context.user_data.get('await_bulk_delete_numbers'):
        await process_bulk_delete_numbers(update, context); return
    if context.user_data.get('await_bulk_send_numbers'):
        await process_bulk_send_numbers(update, context); return
    if context.user_data.get('await_bulk_enable_numbers'):
        await process_bulk_enable_numbers(update, context); return
    if context.user_data.get('await_bulk_disable_numbers'):
        await process_bulk_disable_numbers(update, context); return
    if context.user_data.get('await_renew_number'):
        await process_renew_number(update, context); return
    if context.user_data.get('await_renew_expiry'):
        await renew_key_expiry_handler(update, context); return
    if (context.user_data.get('await_key_name') or
        context.user_data.get('await_key_expiry') or
        context.user_data.get('await_key_quantity')):
        await create_key_handler(update, context); return
    if context.user_data.get('await_remote_input'):
        await process_remote_input(update, context); return
    await update.message.reply_text("Неизвестный ввод. Используй меню или /start.")

# ------------------ HELP / START / Прочие команды ------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    global MENU_MESSAGE_ID, MENU_CHAT_ID
    kb = get_main_keyboard()
    if MENU_MESSAGE_ID and MENU_CHAT_ID:
        try:
            await context.bot.delete_message(chat_id=MENU_CHAT_ID, message_id=MENU_MESSAGE_ID)
        except: pass
    sent = await update.message.reply_text(f"Добро пожаловать! Версия: {BOT_VERSION}\n\n{runtime_info()}", reply_markup=kb)
    MENU_MESSAGE_ID = sent.message_id; MENU_CHAT_ID = sent.chat.id

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    await update.message.reply_text(runtime_info())
    await send_help_messages(context, update.effective_chat.id)

async def clients_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    await update.message.reply_text(format_clients_by_certs(), parse_mode="HTML")

async def traffic_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    save_traffic_db(force=True)
    await update.message.reply_text(build_traffic_report(), parse_mode="HTML")

async def cmd_backup_now(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    try:
        path = create_backup_in_root_excluding_archives()
        await update.message.reply_text(f"✅ Бэкап: {os.path.basename(path)}")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

async def cmd_backup_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    items = list_backups()
    if not items:
        await update.message.reply_text("Бэкапов нет."); return
    await update.message.reply_text("<b>Бэкапы:</b>\n" + "\n".join(items), parse_mode="HTML")

async def cmd_backup_restore(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    if not context.args:
        await update.message.reply_text("Использование: /backup_restore <архив>"); return
    fname = context.args[0]
    path = locate_backup(fname)
    if not path:
        await update.message.reply_text("Файл не найден."); return
    report = apply_restore(path, dry_run=True)
    diff = report["diff"]
    await update.message.reply_text(
        f"Dry-run {fname}:\nExtra={len(diff['extra'])} Missing={len(diff['missing'])} Changed={len(diff['changed'])}\n"
        f"Применить: /backup_restore_apply {fname}"
    )

async def cmd_backup_restore_apply(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    if not context.args:
        await update.message.reply_text("Использование: /backup_restore_apply <архив>"); return
    fname = context.args[0]
    path = locate_backup(fname)
    if not path:
        await update.message.reply_text("Файл не найден."); return
    report = apply_restore(path, dry_run=False)
    diff = report["diff"]
    await update.message.reply_text(
        f"Restore {fname}:\nExtra удалено: {len(diff['extra'])}\nMissing: {len(diff['missing'])}\nChanged: {len(diff['changed'])}"
    )

# ------------------ Просмотр логических сроков ------------------
async def view_keys_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    files = get_ovpn_files()
    files = sorted(files, key=lambda x: _natural_key(x[:-5]))
    names = [f[:-5] for f in files]
    text = "<b>Логические сроки клиентов:</b>\n"
    if not names:
        text += "Нет."
    else:
        rows = []
        for name in names:
            iso, days_left = get_client_expiry(name)
            if iso is None:
                status = "нет срока"
            else:
                if days_left is not None:
                    if days_left < 0: status = f"❌ истёк ({iso})"
                    elif days_left == 0: status = f"⚠️ сегодня ({iso})"
                    else: status = f"{days_left}д (до {iso})"
                else:
                    status = iso
            mark = "⛔" if is_client_ccd_disabled(name) else "🟢"
            rows.append(f"{mark} {name}: {status}")
        text += "\n".join(rows)
    if update.callback_query:
        await safe_edit_text(update.callback_query, context, text, parse_mode="HTML")
    else:
        await update.message.reply_text(text, parse_mode="HTML")

# ------------------ BUTTON HANDLER ------------------
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Доступ запрещён.", show_alert=True)
        return

    await q.answer()
    data = q.data
    print("DEBUG callback_data:", data)

    # Алиасы на случай разных callback_data (чтобы потом не ломалось)
    aliases = {
        "trafik": "traffic",
        "traffic_btn": "traffic",
        "traffic_menu": "traffic",
        "traffic_report": "traffic",
    }
    data = aliases.get(data, data)

    if data == 'refresh':
        await safe_edit_text(q, context, format_clients_by_certs(), parse_mode="HTML")

    elif data == 'stats':
        clients, online_names, tunnel_ips = parse_openvpn_status("/var/log/openvpn/status.log")
        files = get_ovpn_files()
        files = sorted(files, key=lambda x: _natural_key(x[:-5]))
        lines = ["<b>Статус всех ключей:</b>"]
        for f in files:
            name = f[:-5]
            st = "⛔" if is_client_ccd_disabled(name) else ("🟢" if name in online_names else "🔴")
            lines.append(f"{st} {name}")
        text = "\n".join(lines)
        msgs = split_message(text)
        await safe_edit_text(q, context, msgs[0], parse_mode="HTML")
        for m in msgs[1:]:
            await context.bot.send_message(chat_id=q.message.chat_id, text=m, parse_mode="HTML")

    # ✅ ДОБАВЛЕНО: обработка кнопки "Трафик"
    elif data == 'traffic':
        status_path = "/var/log/openvpn/status.log"
        clients, _online_names, _tunnel_ips = parse_openvpn_status(status_path)

        # обновляем накопление трафика из status.log (если у тебя эти функции есть)
        update_traffic_from_status(clients)
        save_traffic_db(force=True)

        await safe_edit_text(q, context, build_traffic_report(), parse_mode="HTML")

    elif data == 'traffic_clear':
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Да", callback_data="confirm_clear_traffic")],
            [InlineKeyboardButton("❌ Нет", callback_data="cancel_clear_traffic")]
        ])
        await safe_edit_text(q, context, "Очистить накопленный трафик?", reply_markup=kb)

    elif data == 'confirm_clear_traffic':
        clear_traffic_stats()
        await safe_edit_text(q, context, "Очищено.")

    elif data == 'cancel_clear_traffic':
        await safe_edit_text(q, context, "Отменено.")

    elif data == 'update_remote':
        await start_update_remote_dialog(update, context)

    elif data == 'cancel_update_remote':
        context.user_data.pop('await_remote_input', None)
        await safe_edit_text(q, context, "Отменено.")

    elif data == 'renew_key':
        await renew_key_request(update, context)

    elif data.startswith('renew_'):
        await renew_key_select_handler(update, context)

    elif data == 'cancel_renew':
        await renew_cancel(update, context)

    elif data == 'backup_menu':
        await backup_menu(update, context)

    elif data == 'restore_menu':
        await restore_menu(update, context)

    elif data == 'backup_create':
        await perform_backup_and_send(update, context)

    elif data == 'backup_list':
        await show_backup_list(update, context)

    elif data.startswith('backup_info_'):
        await show_backup_info(update, context, data.replace('backup_info_', '', 1))

    elif data.startswith('backup_send_'):
        await send_backup_file(update, context, data.replace('backup_send_', '', 1))

    elif data.startswith('restore_dry_'):
        await restore_dry_run(update, context, data.replace('restore_dry_', '', 1))

    elif data.startswith('restore_apply_'):
        await restore_apply(update, context, data.replace('restore_apply_', '', 1))

    elif data.startswith('backup_delete_confirm_'):
        await backup_delete_apply(update, context, data.replace('backup_delete_confirm_', '', 1))

    elif data.startswith('backup_delete_'):
        await backup_delete_prompt(update, context, data.replace('backup_delete_', '', 1))

    elif data == 'bulk_delete_start':
        await start_bulk_delete(update, context)

    elif data == 'bulk_delete_confirm':
        await bulk_delete_confirm(update, context)

    elif data == 'cancel_bulk_delete':
        await bulk_delete_cancel(update, context)

    elif data == 'bulk_send_start':
        await start_bulk_send(update, context)

    elif data == 'bulk_send_confirm':
        await bulk_send_confirm(update, context)

    elif data == 'cancel_bulk_send':
        await bulk_send_cancel(update, context)

    elif data == 'bulk_enable_start':
        await start_bulk_enable(update, context)

    elif data == 'bulk_enable_confirm':
        await bulk_enable_confirm(update, context)

    elif data == 'cancel_bulk_enable':
        await bulk_enable_cancel(update, context)

    elif data == 'bulk_disable_start':
        await start_bulk_disable(update, context)

    elif data == 'bulk_disable_confirm':
        await bulk_disable_confirm(update, context)

    elif data == 'cancel_bulk_disable':
        await bulk_disable_cancel(update, context)

    elif data == 'update_info':
        await send_simple_update_command(update, context)

    elif data == 'copy_update_cmd':
        await resend_update_command(update, context)

    elif data == 'keys_expiry':
        await view_keys_expiry_handler(update, context)

    elif data == 'send_ipp':
        ipp_path = detect_ipp_file(os.path.join(OPENVPN_DIR, "server.conf"), OPENVPN_DIR)
        if os.path.exists(ipp_path):
            with open(ipp_path, "rb") as f:
                await context.bot.send_document(
                    chat_id=q.message.chat_id,
                    document=InputFile(f),
                    filename="ipp.txt",
                )
            await safe_edit_text(q, context, "ipp.txt отправлен.")
        else:
            await safe_edit_text(q, context, f"ipp.txt не найден. Ожидал: {ipp_path}")

    elif data == 'alarm_on':
        alarm_enable()
        await safe_edit_text(q, context, "⏰ Тревога включена (ON).")

    elif data == 'alarm_off':
        alarm_disable()
        await safe_edit_text(q, context, "⏰ Тревога выключена (OFF).")

    elif data == 'block_alert':
        await safe_edit_text(
            q, context,
            "🔔 Мониторинг блокировки включен.\n"
            f"Порог MIN_ONLINE_ALERT = {MIN_ONLINE_ALERT}\n"
            "Оповещения если:\n • Все клиенты оффлайн\n • Онлайн меньше порога\n"
            "Проверка каждые 10с. Истечения — каждые 12ч."
        )

    elif data == 'help':
        await context.bot.send_message(q.message.chat_id, runtime_info())
        await send_help_messages(context, q.message.chat_id)

    elif data == 'log':
        await log_request(update, context)

    elif data == 'create_key':
        await safe_edit_text(q, context, "Введите имя нового клиента:")
        context.user_data['await_key_name'] = True

    elif data == 'home':
        await context.bot.send_message(q.message.chat_id, "Главное меню уже показано. Для обновления нажми /start.")

    else:
        await safe_edit_text(q, context, "Неизвестная команда.")


# ------------------ Команды (CLI) ------------------
async def traffic_cmd_cli(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID: return
    save_traffic_db(force=True)
    await update.message.reply_text(build_traffic_report(), parse_mode="HTML")

# ------------------ MAIN ------------------
def main():
    app = Application.builder().token(TOKEN).build()
    load_traffic_db()
    load_client_meta()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("clients", clients_command))
    app.add_handler(CommandHandler("traffic", traffic_command))
    app.add_handler(CommandHandler("show_update_cmd", show_update_cmd))
    app.add_handler(CommandHandler("backup_now", cmd_backup_now))
    app.add_handler(CommandHandler("backup_list", cmd_backup_list))
    app.add_handler(CommandHandler("backup_restore", cmd_backup_restore))
    app.add_handler(CommandHandler("backup_restore_apply", cmd_backup_restore_apply))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, universal_text_handler))
    app.add_handler(CallbackQueryHandler(button_handler))

    import asyncio
    loop = asyncio.get_event_loop()
    loop.create_task(check_new_connections(app))

    app.run_polling()

if __name__ == '__main__':
    main()

