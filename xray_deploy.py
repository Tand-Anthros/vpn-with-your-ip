#!/usr/bin/env python3
"""
xray_restore - поднимает на сервере XRay (VLESS + Reality, без Vision, под Mux)
с новыми ключами и печатает готовую ссылку vless://.

Запуск на сервере (Ubuntu / Debian) от root:

    python3 xray_restore.py

XRay ставится как обычная системная служба (без Docker и без Amnezia).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from pathlib import Path

# ============================================================================
# ПРЕДУСТАНОВКИ. Пустое значение = скрипт спросит в консоли.
# ============================================================================

# Версия XRay. "" = последняя. Сейчас на сервере стоит 26.10.31
XRAY_VERSION = "26.10.31"

# Порт и домен маскировки
PORT = 443
SNI = "www.googletagmanager.com"

# Алгоритм TCP. "" = не трогать (правильно для обычного сервера).
# На нынешнем сервере с большой задержкой стоит "hybla".
CONGESTION = ""

# ============================================================================

XRAY_BIN = "/usr/local/bin/xray"
XRAY_CONFIG = Path("/usr/local/etc/xray/config.json")
SYSCTL_FILE = Path("/etc/sysctl.d/99-xray-chain.conf")
INSTALLER_URL = "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def choose(title: str, options: list[str]) -> int:
    print(f"\n{title}")
    for i, text in enumerate(options, 1):
        print(f"  {i}) {text}")
    while True:
        raw = input(f"Выбор [1-{len(options)}, Enter = 1]: ").strip()
        if not raw:
            return 0
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        print("  Введите номер из списка.")


# ----------------------------------------------------------------------------
# Установка XRay
# ----------------------------------------------------------------------------

def install_xray():
    if Path(XRAY_BIN).exists():
        current = run([XRAY_BIN, "version"], check=False).stdout.splitlines()[:1]
        print(f"\nXRay уже установлен: {current[0] if current else '?'}")
        if choose("Переустановить?", ["Нет, оставить как есть", "Да, поставить заново"]) == 0:
            return
    print("\nСкачиваю установщик XRay с GitHub (XTLS/Xray-install)...")
    with tempfile.NamedTemporaryFile("wb", suffix=".sh", delete=False) as f:
        f.write(urllib.request.urlopen(INSTALLER_URL, timeout=60).read())
        script = f.name
    cmd = ["bash", script, "install"]
    if XRAY_VERSION:
        cmd += ["--version", "v" + XRAY_VERSION.lstrip("v")]
    print("Устанавливаю, это займёт до минуты...")
    res = subprocess.run(cmd, text=True)
    os.unlink(script)
    if res.returncode != 0 or not Path(XRAY_BIN).exists():
        raise SystemExit("Установка XRay не удалась, см. сообщения выше.")


# ----------------------------------------------------------------------------
# Конфиг
# ----------------------------------------------------------------------------

def parse_x25519(output: str) -> tuple[str, str]:
    """Достаёт (private, public) из вывода `xray x25519` любой версии."""
    priv = re.search(r"(?im)^private\s*key\s*:\s*(\S+)", output)
    pub = re.search(r"(?im)^(?:public\s*key|password)\s*:\s*(\S+)", output)
    if not pub:
        raise ValueError("не удалось разобрать вывод xray x25519:\n" + output)
    return (priv.group(1) if priv else ""), pub.group(1)


def public_key(private: str) -> str:
    return parse_x25519(run([XRAY_BIN, "x25519", "-i", private]).stdout)[1]


def find_inbound(config: dict) -> dict:
    for ib in config.get("inbounds", []):
        if ib.get("protocol") == "vless" and ib.get("streamSettings", {}).get("security") == "reality":
            return ib
    raise ValueError("в конфиге нет входящего VLESS + Reality")


def new_config() -> dict:
    private, _ = parse_x25519(run([XRAY_BIN, "x25519"]).stdout)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": PORT,
            "protocol": "vless",
            "settings": {"clients": [{"id": str(uuid.uuid4()), "flow": ""}], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": f"{SNI}:443",
                    "serverNames": [SNI],
                    "privateKey": private,
                    "shortIds": [secrets.token_hex(8)],
                },
            },
        }],
        "outbounds": [{"protocol": "freedom"}],
    }


def make_link(config: dict, address: str) -> str:
    ib = find_inbound(config)
    rs = ib["streamSettings"]["realitySettings"]
    return ("vless://{id}@{addr}:{port}?encryption=none&type=tcp&security=reality"
            "&sni={sni}&fp=chrome&pbk={pbk}&sid={sid}#my-server").format(
        id=ib["settings"]["clients"][0]["id"], addr=address, port=ib["port"],
        sni=rs["serverNames"][0], pbk=public_key(rs["privateKey"]),
        sid=(rs.get("shortIds") or [""])[0])


# ----------------------------------------------------------------------------
# Система
# ----------------------------------------------------------------------------

def port_is_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def apply_sysctl():
    lines = ["net.ipv4.tcp_slow_start_after_idle=0"]
    if CONGESTION:
        run(["modprobe", "tcp_" + CONGESTION], check=False)
        lines.append(f"net.ipv4.tcp_congestion_control={CONGESTION}")
    SYSCTL_FILE.write_text("\n".join(lines) + "\n")
    res = run(["sysctl", "-p", str(SYSCTL_FILE)], check=False)
    print(res.stdout.strip() or res.stderr.strip())


def server_ip() -> str:
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=10).read().decode().strip()
    except Exception:
        return "IP_СЕРВЕРА"


def main() -> int:
    print("xray_restore: XRay (VLESS + Reality под Mux) как системная служба")
    if os.geteuid() != 0:
        print("Запустите от root: sudo python3 xray_restore.py")
        return 1

    install_xray()
    config = new_config()
    port = find_inbound(config)["port"]

    run(["systemctl", "stop", "xray"], check=False)
    if not port_is_free(port):
        print(f"\nПорт {port} занят другой программой (например, контейнером amnezia-xray).")
        print(f"Посмотреть, кем: ss -ltnp | grep :{port}")
        print("Освободите порт (для Amnezia: docker stop amnezia-xray) и запустите скрипт снова.")
        return 1

    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    if XRAY_CONFIG.exists():
        shutil.copy(XRAY_CONFIG, XRAY_CONFIG.with_suffix(".json.old"))
    XRAY_CONFIG.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    os.chmod(XRAY_CONFIG, 0o644)

    test = run([XRAY_BIN, "run", "-test", "-c", str(XRAY_CONFIG)], check=False)
    if test.returncode != 0:
        print("\nXRay не принял конфиг:\n" + (test.stdout + test.stderr)[-1500:])
        return 1

    print("\nНастройки сети:")
    apply_sysctl()

    if shutil.which("ufw") and "Status: active" in run(["ufw", "status"], check=False).stdout:
        run(["ufw", "allow", f"{port}/tcp"], check=False)
        print(f"Открыл порт {port}/tcp в ufw")

    run(["systemctl", "enable", "xray"], check=False)
    run(["systemctl", "restart", "xray"], check=False)
    if run(["systemctl", "is-active", "xray"], check=False).stdout.strip() != "active":
        print("\nСлужба xray не запустилась. Причина: journalctl -u xray -n 30 --no-pager")
        return 1

    print("\nГотово, XRay работает и будет запускаться после перезагрузки.")
    print("Строка для EXIT_SERVER в chainsub.py:\n")
    print("    " + make_link(config, server_ip()))
    print("\nВ chainsub.py должно стоять MUX = True.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nПрервано.")
        sys.exit(1)
