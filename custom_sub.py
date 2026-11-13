#!/usr/bin/env python3
"""
chainsub - делает из обычной подписки (Happ / v2RayTun / v2rayN) вторую подписку,
в которой каждый сервер выходит в интернет через ВАШ сервер:

    вы -> узел из подписки -> ваш сервер -> интернет

Запуск:  python chainsub.py
Нужен только Python 3.9+, сторонних библиотек нет.
Всё, что не задано в блоке ПРЕДУСТАНОВКИ, скрипт спросит в консоли.
"""
from __future__ import annotations

import base64
import copy
import gzip
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

# ============================================================================
# ПРЕДУСТАНОВКИ
# Заполните то, что меняется редко. Пустое значение = скрипт спросит в консоли.
# ============================================================================

# Ссылка подписки провайдера (https://...) или путь к сохранённому файлу
SUB_URL = ""

# Ваш сервер: строка vless://... или путь к JSON-файлу от Amnezia
EXIT_SERVER = ""

# Дополнительные HTTP-заголовки для запроса подписки.
# Пример: HEADERS = {"x-hwid": "любая-постоянная-строка"}
HEADERS = {
    "x-hwid": "tandy-exit"
}

# Каким приложением представляться провайдеру
USER_AGENT = "Happ/3.13.0"

# Какие серверы брать: "all" - все, "" - спросить
SERVERS = ""

# Что сделать в конце: "file" - записать файл, "local" - подписка на этом
# компьютере, "lan" - подписка для устройств в домашней сети, "" - спросить
MODE = ""

OUT_FILE = "chain.json"   # имя файла для режима "file"
PORT = 8765               # порт для режимов "local" и "lan"
SUFFIX = " -> my"         # что дописать к имени каждого сервера
TITLE = "Chain"           # название подписки в клиенте
RU_DIRECT = True          # российские сайты напрямую (только для узлов-ссылок)
BLOCK_QUIC = True         # блокировать UDP:443, чтобы приложения шли по TCP
MUX = True                # общее соединение до вашего сервера (на сервере XRay без Vision)
CACHE_SECONDS = 60        # как часто можно перезапрашивать провайдера

# ============================================================================

PROXY_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria"}
ENTRY_TAG = "chain-entry"

# Домены, которые идут напрямую (мимо обоих серверов), если узел пришёл ссылкой,
# а не готовым JSON. Для JSON-подписок правила провайдера сохраняются как есть.
RU_DIRECT = [
    "regexp:\\.(ru|su|xn--p1ai)$",
    "domain:vk.com", "domain:userapi.com", "domain:mycdn.me",
    "regexp:(^|\\.)yand[a-z0-9-]*\\.(com|net|org)$",
    "regexp:(^|\\.)yast[a-z0-9-]*\\.net$",
]


QUIET = False


def log(*a):
    if QUIET:
        return
    print("[chainsub]", *a, file=sys.stderr, flush=True)


# ----------------------------------------------------------------------------
# Загрузка подписки
# ----------------------------------------------------------------------------

def fetch(source: str, ua: str, headers: dict[str, str], timeout: int = 30):
    """Возвращает (текст, заголовки ответа). source - URL или путь к файлу."""
    if not source.lower().startswith(("http://", "https://")):
        return Path(source).read_text(encoding="utf-8-sig"), {}
    req = urllib.request.Request(source, headers={"User-Agent": ua, "Accept": "*/*", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        if r.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
        return raw.decode("utf-8-sig", errors="replace"), dict(r.headers.items())


def b64decode_loose(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


# ----------------------------------------------------------------------------
# Разбор ссылок vless:// trojan:// ss:// vmess:// в outbound Xray
# ----------------------------------------------------------------------------

def _q(url) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(url.query, keep_blank_values=True).items()}


def _fp(value: str | None, default: str = "chrome") -> str:
    # Amnezia пишет отпечатки вида hellochrome_120 - новые Xray их могут не знать
    if not value or value.lower().startswith("hello"):
        return default
    return value


def build_stream(q: dict[str, str], host: str) -> dict:
    net = (q.get("type") or q.get("net") or "tcp").lower()
    net = {"raw": "tcp", "splithttp": "xhttp", "h2": "http"}.get(net, net)
    s: dict = {"network": net}

    sec = (q.get("security") or "none").lower()
    sni = q.get("sni") or q.get("peer") or q.get("host") or host
    if sec == "tls":
        tls: dict = {"serverName": sni, "fingerprint": _fp(q.get("fp"))}
        if q.get("alpn"):
            tls["alpn"] = [x for x in unquote(q["alpn"]).split(",") if x]
        if q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"):
            tls["allowInsecure"] = True
        s["security"], s["tlsSettings"] = "tls", tls
    elif sec == "reality":
        s["security"] = "reality"
        s["realitySettings"] = {
            "serverName": sni,
            "fingerprint": _fp(q.get("fp")),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": unquote(q.get("spx", "")),
        }
    else:
        s["security"] = "none"

    path, hhost = unquote(q.get("path", "")), q.get("host", "")
    if net == "ws":
        s["wsSettings"] = {"path": path or "/", **({"host": hhost} if hhost else {})}
    elif net == "grpc":
        s["grpcSettings"] = {
            "serviceName": unquote(q.get("serviceName", "")),
            "authority": q.get("authority", ""),
            "multiMode": q.get("mode") == "multi",
        }
    elif net == "xhttp":
        x: dict = {"path": path or "/"}
        if hhost:
            x["host"] = hhost
        if q.get("mode"):
            x["mode"] = q["mode"]
        if q.get("extra"):
            try:
                x["extra"] = json.loads(unquote(q["extra"]))
            except ValueError:
                pass
        s["xhttpSettings"] = x
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": path or "/", **({"host": hhost} if hhost else {})}
    elif net == "tcp" and q.get("headerType") == "http":
        s["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path or "/"], "headers": {"Host": [hhost] if hhost else []}}}}
    return s


def parse_link(link: str):
    """Возвращает (имя, outbound) или бросает ValueError."""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()

    if scheme == "vmess":
        d = json.loads(b64decode_loose(link[8:]).decode("utf-8", "replace"))
        q = {"type": d.get("net", "tcp"), "security": "tls" if d.get("tls") == "tls" else "none",
             "sni": d.get("sni", ""), "host": d.get("host", ""), "path": d.get("path", ""),
             "alpn": d.get("alpn", ""), "fp": d.get("fp", ""), "headerType": d.get("type", "")}
        if q["type"] == "grpc":
            q["serviceName"] = d.get("path", "")
        out = {"protocol": "vmess", "settings": {"vnext": [{
            "address": d["add"], "port": int(d["port"]),
            "users": [{"id": d["id"], "alterId": int(d.get("aid") or 0), "security": d.get("scy") or "auto"}]}]},
            "streamSettings": build_stream({k: v for k, v in q.items() if v}, d["add"])}
        return d.get("ps") or d["add"], out

    u = urlsplit(link)
    name = unquote(u.fragment) or (u.hostname or "server")
    q = _q(u)

    if scheme == "vless":
        user = {"id": unquote(u.username or ""), "encryption": q.get("encryption") or "none"}
        if q.get("flow"):
            user["flow"] = q["flow"]
        out = {"protocol": "vless",
               "settings": {"vnext": [{"address": u.hostname, "port": u.port or 443, "users": [user]}]},
               "streamSettings": build_stream(q, u.hostname)}
        return name, out

    if scheme == "trojan":
        q.setdefault("security", "tls")
        out = {"protocol": "trojan",
               "settings": {"servers": [{"address": u.hostname, "port": u.port or 443,
                                         "password": unquote(u.username or "")}]},
               "streamSettings": build_stream(q, u.hostname)}
        return name, out

    if scheme == "ss":
        body = link[5:].split("#", 1)[0].split("?", 1)[0]
        if "@" in body:
            cred, hp = body.rsplit("@", 1)
            try:
                cred = b64decode_loose(cred).decode()
            except Exception:
                cred = unquote(cred)
        else:
            cred, hp = b64decode_loose(body).decode().rsplit("@", 1)
        method, password = cred.split(":", 1)
        host, port = hp.rsplit(":", 1)
        out = {"protocol": "shadowsocks", "settings": {"servers": [{
            "address": host.strip("[]"), "port": int(port.strip("/")), "method": method, "password": password}]}}
        return name, out

    raise ValueError(f"протокол {scheme}:// не поддерживается")


# ----------------------------------------------------------------------------
# Разбор подписки целиком
# ----------------------------------------------------------------------------

def template_config(name: str, entry: dict, ru_direct: bool) -> dict:
    rules = [{"type": "field", "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
              "outboundTag": "direct"}]
    if ru_direct:
        rules.append({"type": "field", "domain": RU_DIRECT, "outboundTag": "direct"})
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"]}
    return {
        "remarks": name,
        "dns": {"servers": ["8.8.8.8", "1.1.1.1"], "queryStrategy": "UseIP"},
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
        "inbounds": [
            {"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
             "settings": {"udp": True, "auth": "noauth"}, "sniffing": sniff},
            {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http", "sniffing": sniff},
        ],
        "outbounds": [
            {"tag": "proxy", **entry},
            {"tag": "direct", "protocol": "freedom", "domainStrategy": "UseIPv4"},
            {"tag": "block", "protocol": "blackhole"},
        ],
    }


def parse_subscription(text: str, ru_direct: bool) -> list[dict]:
    """Возвращает список полных Xray-конфигов (по одному на сервер)."""
    text = text.strip()
    if text[:1] in "[{":
        data = json.loads(text)
        items = data if isinstance(data, list) else [data]
        return [c for c in items if isinstance(c, dict) and c.get("outbounds")]

    if "://" not in text:  # вероятно, base64
        try:
            text = b64decode_loose("".join(text.split())).decode("utf-8", "replace")
        except Exception as e:
            raise ValueError("не удалось распознать формат подписки") from e

    configs, skipped = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "://" not in line:
            continue
        try:
            name, out = parse_link(line)
            configs.append(template_config(name, out, ru_direct))
        except Exception as e:
            skipped += 1
            log("пропущен узел:", e)
    if skipped:
        log(f"пропущено узлов: {skipped}")
    return configs


# ----------------------------------------------------------------------------
# Выходной сервер и сборка цепочки
# ----------------------------------------------------------------------------

def load_exit(spec: str) -> dict:
    """spec - ссылка vless://... либо путь к JSON (формат Amnezia/Xray)."""
    if "://" in spec:
        _, out = parse_link(spec)
    else:
        data = json.loads(Path(spec).read_text(encoding="utf-8-sig"))
        if "outbounds" in data:
            out = next(o for o in data["outbounds"] if o.get("protocol") in PROXY_PROTOCOLS)
        else:
            out = data
        out = copy.deepcopy(out)
        rs = out.get("streamSettings", {}).get("realitySettings")
        if rs:
            rs["fingerprint"] = _fp(rs.get("fingerprint"))
    out.pop("tag", None)
    return out


def find_entry(config: dict):
    outs = config.get("outbounds", [])
    for i, o in enumerate(outs):
        if o.get("tag") == "proxy" and o.get("protocol") in PROXY_PROTOCOLS:
            return i
    for i, o in enumerate(outs):
        if o.get("protocol") in PROXY_PROTOCOLS:
            return i
    return None


def chain_config(config: dict, exit_out: dict, suffix: str):
    """Вставляет выходной сервер в конфиг. Возвращает новый конфиг или None."""
    if config.get("routing", {}).get("balancers"):
        return None  # авто-выбор из нескольких узлов: такие конфиги не трогаем
    cfg = copy.deepcopy(config)
    i = find_entry(cfg)
    if i is None:
        return None
    entry = cfg["outbounds"][i]
    old_tag = entry.get("tag") or "proxy"
    entry["tag"] = ENTRY_TAG

    ex = copy.deepcopy(exit_out)
    ex.pop("proxySettings", None)
    ex.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = ENTRY_TAG
    # выходной сервер получает прежний тег узла, поэтому правила маршрутизации
    # провайдера продолжают работать без изменений
    cfg["outbounds"].insert(i, {"tag": old_tag, **ex})

    ex.pop("proxySettings", None)
    if MUX:
        for srv in ex.get("settings", {}).get("vnext", []):
            for user in srv.get("users", []):
                user.pop("flow", None)
        ex["mux"] = {"enabled": True, "concurrency": 128, "xudpConcurrency": 16, "xudpProxyUDP443": "reject"}

    if BLOCK_QUIC:
        if not any(o.get("tag") == "block" for o in cfg["outbounds"]):
            cfg["outbounds"].append({"tag": "block", "protocol": "blackhole"})
        cfg.setdefault("routing", {}).setdefault("rules", []).insert(
            0, {"type": "field", "network": "udp", "port": "443", "outboundTag": "block"})
        cfg["remarks"] = f"{cfg.get('remarks') or 'server'}{suffix}"

    return cfg


def build(sub_text: str, exit_out: dict, suffix: str, ru_direct: bool, only=None) -> list[dict]:
    """only - множество имён серверов, которые нужно оставить (None = все)."""
    result, skipped = [], 0
    for c in parse_subscription(sub_text, ru_direct):
        if only is not None and (c.get("remarks") or "server") not in only:
            continue
        chained = chain_config(c, exit_out, suffix)
        if chained:
            result.append(chained)
        else:
            skipped += 1
    if skipped:
        log(f"конфигов без изменений пропущено: {skipped} (балансировщик или нет прокси-узла)")
    return result


# ----------------------------------------------------------------------------
# Вопросы в консоли
# ----------------------------------------------------------------------------

def ask(prompt: str) -> str:
    while True:
        value = input(f"{prompt}\n> ").strip().strip('"')
        if value:
            return value


def choose(title: str, options: list[str]) -> int:
    """Показывает нумерованный список, возвращает индекс выбранного (с нуля)."""
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


def parse_numbers(raw: str, total: int) -> list[int]:
    """'1,3-5 7' -> [0, 2, 3, 4, 6]"""
    picked = []
    for part in raw.replace(",", " ").split():
        a, _, b = part.partition("-")
        if not a.isdigit() or (b and not b.isdigit()):
            raise ValueError(part)
        lo, hi = int(a), int(b or a)
        if not (1 <= lo <= hi <= total):
            raise ValueError(part)
        picked += [n - 1 for n in range(lo, hi + 1)]
    return sorted(set(picked))


def lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.168.255.255", 9))  # пакеты не отправляются
            return s.getsockname()[0]
    except OSError:
        return "IP-этого-компьютера"


# ----------------------------------------------------------------------------
# Шаги сценария
# ----------------------------------------------------------------------------

def get_exit() -> dict:
    spec = EXIT_SERVER
    while True:
        if not spec:
            spec = ask("\nВаш сервер: вставьте строку vless://... или путь к JSON-файлу от Amnezia")
        try:
            return load_exit(spec)
        except Exception as e:
            print(f"  Не получилось прочитать: {e}")
            spec = ""


def get_subscription(state: dict) -> tuple[str, dict]:
    """Скачивает подписку; при отказе провайдера предлагает варианты."""
    while True:
        if not state["sub"]:
            state["sub"] = ask("\nСсылка подписки провайдера (https://...) или путь к файлу")
        try:
            return fetch(state["sub"], state["ua"], state["headers"])
        except urllib.error.HTTPError as e:
            problem = f"провайдер ответил кодом {e.code}"
        except Exception as e:
            problem = str(e)
        pick = choose(f"Не удалось получить подписку: {problem}", [
            "Попробовать ещё раз",
            "Добавить заголовок x-hwid (если провайдер привязывает подписку к устройству)",
            "Сменить User-Agent (сейчас: %s)" % state["ua"],
            "Ввести другую ссылку",
            "Выйти",
        ])
        if pick == 1:
            state["headers"]["x-hwid"] = ask("Значение x-hwid (любая постоянная строка)")
        elif pick == 2:
            state["ua"] = ask("User-Agent, например Happ/3.13.0 или v2rayNG/1.10.23")
        elif pick == 3:
            state["sub"] = ""
        elif pick == 4:
            raise SystemExit(1)


def pick_servers(names: list[str]):
    """Возвращает множество выбранных имён или None, если нужны все."""
    print(f"\nНайдено серверов: {len(names)}")
    for i, n in enumerate(names, 1):
        print(f"  {i:>2}. {n}")
    if SERVERS == "all" or len(names) == 1:
        return None
    if choose("Какие серверы связать с вашим?", ["Все", "Выбрать по номерам"]) == 0:
        return None
    while True:
        raw = input(f"Номера через пробел или запятую, можно диапазоном (например 1,3-5): ")
        try:
            idx = parse_numbers(raw, len(names))
            if idx:
                return {names[i] for i in idx}
        except ValueError as e:
            print(f"  Не понял «{e}».")


def pick_mode() -> str:
    if MODE in ("file", "local", "lan"):
        return MODE
    return ("file", "local", "lan")[choose("Что сделать с результатом?", [
        f"Записать файл {OUT_FILE} (импортируете его в клиент вручную)",
        "Запустить подписку на этом компьютере (для Happ на этом же ПК, обновляется сама)",
        "Запустить подписку для домашней сети (для телефона в том же Wi-Fi)",
    ])]


# ----------------------------------------------------------------------------
# Локальная подписка
# ----------------------------------------------------------------------------

def serve(state: dict, exit_out: dict, only, first_body: bytes, first_info, lan: bool):
    cache = {"at": time.time(), "body": first_body, "info": first_info}

    def refresh():
        if time.time() - cache["at"] < CACHE_SECONDS:
            return
        cache["at"] = time.time()
        try:
            text, hdrs = fetch(state["sub"], state["ua"], state["headers"])
            configs = build(text, exit_out, SUFFIX, RU_DIRECT, only)
            if configs:
                cache["body"] = dump(configs)
                cache["info"] = userinfo(hdrs)
                log(f"обновлено: {len(configs)} серверов")
            else:
                log("подписка пришла пустой, отдаю прошлую версию")
        except Exception as e:
            log("не удалось обновить подписку, отдаю прошлую версию:", e)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.split("?")[0].rstrip("/") != "/sub":
                self.send_error(404)
                return
            refresh()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(cache["body"])))
            self.send_header("profile-title", TITLE)
            self.send_header("profile-update-interval", "1")
            if cache["info"]:
                self.send_header("subscription-userinfo", cache["info"])
            self.end_headers()
            self.wfile.write(cache["body"])

        def log_message(self, *a):
            pass

    try:
        srv = ThreadingHTTPServer(("0.0.0.0" if lan else "127.0.0.1", PORT), Handler)
    except OSError as e:
        print(f"\nНе удалось занять порт {PORT}: {e}\nПоменяйте PORT в предустановках.")
        return
    print("\nПодписка запущена. Добавьте в клиент этот адрес:")
    print(f"    http://{lan_ip() if lan else '127.0.0.1'}:{PORT}/sub")
    if lan:
        print("Телефон должен быть в той же сети. Если адрес не открывается, разрешите Python")
        print("в брандмауэре Windows; при включённом VPN адрес компьютера может определиться неверно.")
    print("Окно не закрывайте, пока пользуетесь подпиской. Остановить: Ctrl+C")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")


def dump(configs: list[dict]) -> bytes:
    return json.dumps(configs, ensure_ascii=False, indent=1).encode("utf-8")


def userinfo(headers: dict):
    return next((v for k, v in headers.items() if k.lower() == "subscription-userinfo"), None)


# ----------------------------------------------------------------------------

def main() -> int:
    print("chainsub: подписка -> подписка с выходом через ваш сервер")
    state = {"sub": SUB_URL, "ua": USER_AGENT, "headers": dict(HEADERS)}

    exit_out = get_exit()

    while True:
        text, hdrs = get_subscription(state)
        try:
            names = [c["remarks"] for c in build(text, exit_out, "", RU_DIRECT)]
        except Exception as e:
            names = []
            print(f"\nНе удалось разобрать подписку: {e}")
        if names:
            break
        print("\nВ подписке не нашлось подходящих серверов.")
        if text.lstrip().lower().startswith(("happ://", "<!doctype", "<html")):
            print("Похоже, это не сама подписка, а зашифрованная ссылка или веб-страница.")
        if SUB_URL or choose("Что дальше?", ["Ввести другую ссылку", "Выйти"]) == 1:
            return 1
        state["sub"] = ""

    only = pick_servers(names)
    global QUIET
    QUIET = True   # эти предупреждения уже показаны выше
    configs = build(text, exit_out, SUFFIX, RU_DIRECT, only)
    QUIET = False
    print(f"\nСобрано цепочек: {len(configs)}")

    # последний вопрос: куда отдать результат
    mode = pick_mode()
    if mode == "file":
        Path(OUT_FILE).write_bytes(dump(configs))
        print(f"\nГотово: {Path(OUT_FILE).resolve()}")
    else:
        serve(state, exit_out, only, dump(configs), userinfo(hdrs), lan=(mode == "lan"))
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except (KeyboardInterrupt, EOFError):
        print("\nПрервано.")
        code = 1
    if sys.stdin.isatty() and sys.platform == "win32":
        input("\nНажмите Enter, чтобы закрыть окно...")
    sys.exit(code)
