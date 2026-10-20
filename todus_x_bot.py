import os, re, time, uuid, signal, asyncio, logging, subprocess, threading, ssl, base64, hashlib, socket
from urllib.parse import urlparse
import requests, urllib3
from aiohttp import web
import blurhash
import numpy as np
from PIL import Image
from todus.client import S3Client

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TODUS_PHONE = os.environ.get("TODUS_PHONE", "5350155246")
AUTH_URL = "https://auth.todus.cu/v2/auth/token"
XMPP_HOST = os.environ.get("XMPP_HOST", "ws.todus.cu")
XMPP_PORT = int(os.environ.get("XMPP_PORT", "1756"))
XMPP_DOMAIN = "im.todus.cu"
FAKE_SECRET = "fake1234567890abcdef12345678"
RECV_BUFFER = 65536
COOKIES_PATH = os.environ.get("X_COOKIES_PATH", "/tmp/cookies.txt")
DOWNLOAD_PATH = os.environ.get("TODUS_TMP", "/tmp/todus_uploads")
PORT = int(os.environ.get("PORT", 10000))
WATCHDOG_LIFETIME = int(os.environ.get("WATCHDOG_LIFETIME", 13800))
MAX_VIDEO_SECONDS = 600
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024

os.makedirs(DOWNLOAD_PATH, exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
log = logging.getLogger("todus_x")

x_global = None
_seen = set()
_MAX_SEEN = 10000
activos = {}

MULTIMEDIA = ("<image", "<video", "<voice", "<file", "<gif", "<sticker", "<audio", "<document")
X_HOSTS = {"x.com", "twitter.com", "www.x.com", "www.twitter.com", "mobile.x.com", "mobile.twitter.com", "t.co"}
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _varint(n):
    out = b""
    while True:
        b = n & 0x7F; n >>= 7
        if n: out += bytes([b | 0x80])
        else: out += bytes([b]); break
    return out


def _sf(num, val):
    if isinstance(val, str): val = val.encode()
    return bytes([(num << 3) | 2]) + _varint(len(val)) + val


def login(phone):
    phone = re.sub(r"[^\d]", "", phone)
    payload = _sf(1, phone) + _sf(2, FAKE_SECRET)
    r = requests.post(AUTH_URL, data=payload, timeout=30, verify=False,
        headers={"Content-Type": "application/x-protobuf", "User-Agent": "ToDus 2.1.2 Auth"})
    r.raise_for_status()
    m = re.search(r"eyJ[\w\-\.]+", r.content.decode("utf-8", "ignore"))
    if not m: raise RuntimeError(f"No JWT: {r.content[:200]}")
    return m.group(0)


def xml_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def format_size(b):
    if b < 1024: return f"{b} B"
    if b < 1048576: return f"{b/1024:.1f} KB"
    if b < 1073741824: return f"{b/1048576:.1f} MB"
    return f"{b/1073741824:.2f} GB"


def extract_url(text):
    m = URL_RE.search(text.strip())
    return m.group(0).rstrip(".,;:!?)]}'\"") if m else None


def is_x_url(url):
    try:
        return (urlparse(url).hostname or "").lower() in X_HOSTS
    except Exception:
        return False


def extraer_from_body(stanza):
    m = re.search(r"""\b(?:f|from)=["']([^"']+)["']""", stanza)
    if not m: return None, None
    uid = m.group(1).split("@")[0].split("/")[0]
    bodies = re.findall(r"<b[^>]*>([^<]*)</b>", stanza)
    return uid, (bodies[-1].strip() if bodies else "")


def extraer_id(stanza):
    m = re.search(r"""\b(?:i|id)=["']([^"']+)["']""", stanza)
    return m.group(1) if m else None


class XMPP:
    def __init__(self, phone, jwt):
        self.phone = re.sub(r"[^\d]", "", phone)
        self.jwt = jwt
        self.resource = hashlib.md5(self.phone.encode()).hexdigest() + "_Android"
        self.sock = None
        self.buf = b""
        self.send_lock = threading.Lock()
        self.running = False
        self.full_jid = f"{self.phone}@{XMPP_DOMAIN}/{self.resource}"
        self.on_message = None

    def connect(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((XMPP_HOST, XMPP_PORT), timeout=30)
        self.sock = ctx.wrap_socket(raw, server_hostname=XMPP_HOST)
        self.sock.settimeout(30)
        self._send('<?xml version="1.0"?><stream:stream to="%s" xmlns="jc" xmlns:stream="x1" version="1.0">' % XMPP_DOMAIN)
        self._recv_until(b"</stream:features>")
        auth = b"\x00" + self.phone.encode() + b"\x00" + self.jwt.encode()
        self._send(f'<auth mechanism="PLAIN" xmlns="urn:ietf:params:xml:ns:xmpp-sasl">{base64.b64encode(auth).decode()}</auth>')
        r = self._recv_until(b"<ok", timeout=10)
        if b"<ok" not in r and b"<success" not in r:
            raise RuntimeError(f"SASL fallo: {r[:300]}")
        self._send('<?xml version="1.0"?><stream:stream to="%s" xmlns="jc" xmlns:stream="x1" version="1.0">' % XMPP_DOMAIN)
        self._recv_until(b"</stream:features>")
        bid = uuid.uuid4().hex
        self._send(f'<iq type="set" id="{bid}"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>{self.resource}</resource></bind></iq>')
        r = self._recv_until(b"</iq>", timeout=10)
        m = re.search(rb"<jid>([^<]+)</jid>", r)
        if m: self.full_jid = m.group(1).decode()
        self._send('<iq type="set" id="sess1"><session xmlns="urn:ietf:params:xml:ns:xmpp-session"/></iq>')
        self._recv_until(b"</iq>", timeout=10)
        self._send("<presence/>")
        time.sleep(0.3)
        self.running = True
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()

    def _send(self, data):
        with self.send_lock:
            raw = data.encode() if isinstance(data, str) else data
            self.sock.sendall(raw)

    def _recv_until(self, marker, timeout=10):
        self.sock.settimeout(timeout)
        data = b""
        try:
            while marker not in data:
                c = self.sock.recv(RECV_BUFFER)
                if not c: break
                data += c
        except socket.timeout: pass
        return data

    def _reader(self):
        self.sock.settimeout(1)
        while self.running and self.sock:
            try:
                c = self.sock.recv(RECV_BUFFER)
                if not c: break
                self.buf += c
                self._process()
            except socket.timeout: continue
            except Exception: break

    def _keepalive(self):
        while self.running:
            time.sleep(25)
            try: self._send(" ")
            except Exception: break

    def _process(self):
        while True:
            text = self.buf.decode("utf-8", "replace")
            i = text.find("<m ")
            if i != -1:
                end = text.find("</m>", i)
                if end == -1:
                    end = text.find("/>", i)
                    if end == -1: return
                    end += 2
                else:
                    end += 4
                stanza = text[i:end]
                self.buf = self.buf[end:]
                if self.on_message:
                    threading.Thread(target=self.on_message, args=(stanza,), daemon=True).start()
                continue
            i = text.find("<iq")
            if i == -1:
                self.buf = b""; return
            if i > 0:
                self.buf = self.buf[i:]; text = text[i:]
            end = text.find("</iq>")
            if end == -1:
                if re.match(r"<iq\b[^>]*/>", text):
                    sc = re.match(r"<iq\b[^>]*/>", text).group(0)
                    self.buf = self.buf[len(sc):]
                    continue
                return
            self.buf = self.buf[end + 5:]

    def send_stanza(self, stanza):
        self._send(stanza)

    def close(self):
        self.running = False
        try: self._send("</stream:stream>")
        except Exception: pass
        try: self.sock.close()
        except Exception: pass


def marcar_leido(x, uid, msg_id):
    if not msg_id: return
    to = f"{uid}@{XMPP_DOMAIN}"
    x.send_stanza(f'<m to="{to}" t="c" i="{uuid.uuid4().hex[:16]}" xmlns="jc"><rd xmlns="x8" i="{msg_id}"/></m>')
    time.sleep(0.1)
    x.send_stanza(f'<m to="{to}" t="c" i="{uuid.uuid4().hex[:16]}" xmlns="jc"><dd xmlns="x8" i="{msg_id}"/></m>')


def _forwarded(uid, reply_to):
    if not reply_to: return ""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000+00:00", time.gmtime())
    to = f"{uid}@{XMPP_DOMAIN}"
    return (f'<forwarded xmlns="urn:xmpp:forward:0">'
            f'<delay xmlns="urn:xmpp:delay" stamp="{stamp}"/>'
            f'<m xmlns="jc" o="{to}" f="{to}" i="{reply_to}" t="c"></m>'
            f'</forwarded>')


def enviar_texto(x, uid, texto, msg_id=None, reply_to=None):
    if msg_id is None: msg_id = uuid.uuid4().hex[:16]
    to = f"{uid}@{XMPP_DOMAIN}"
    x.send_stanza(f'<m to="{to}" t="c" i="{msg_id}" xmlns="jc"><k xmlns="x8"/>{_forwarded(uid, reply_to)}<b>{xml_escape(texto)}</b></m>')
    return msg_id


def editar_texto(x, uid, msg_id_orig, nuevo, reply_to=None):
    to = f"{uid}@{XMPP_DOMAIN}"
    new_id = uuid.uuid4().hex[:16]
    x.send_stanza(
        f'<m to="{to}" t="c" i="{msg_id_orig}" xmlns="jc"><k xmlns="x8"/>'
        f'{_forwarded(uid, reply_to)}'
        f'<edited xmlns="edited:n" i="{new_id}" mi="{msg_id_orig}"/>'
        f'<b>{xml_escape(nuevo)}</b></m>'
    )


def borrar_texto(x, uid, msg_id, texto_orig, reply_to=None):
    if not msg_id: return
    to = f"{uid}@{XMPP_DOMAIN}"
    new_id = uuid.uuid4().hex[:16]
    x.send_stanza(
        f'<m to="{to}" t="c" i="{msg_id}" xmlns="jc"><k xmlns="x8"/>'
        f'{_forwarded(uid, reply_to)}'
        f'<deleted xmlns="deleted:n" i="{new_id}" mi="{msg_id}"/>'
        f'<b>{xml_escape(texto_orig)}</b></m>'
    )


def descargar_x(url, out_dir):
    outtmpl = os.path.join(out_dir, "%(id)s.%(ext)s")
    cmd = ["yt-dlp", "--cookies", COOKIES_PATH, "--no-playlist", "--no-warnings", "--no-progress",
           "--merge-output-format", "mp4",
           "-f", "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best",
           "-o", outtmpl, url]
    log.info(f"yt-dlp: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=MAX_VIDEO_SECONDS + 120)
    if r.returncode != 0: raise RuntimeError(f"yt-dlp: {r.stderr[-400:]}")
    for f in os.listdir(out_dir):
        if f.endswith(".mp4"): return os.path.join(out_dir, f)
    files = [f for f in os.listdir(out_dir) if not f.endswith(".part")]
    if not files: raise RuntimeError("yt-dlp no descargo nada")
    return os.path.join(out_dir, files[0])


def extraer_thumb(video, thumb):
    r = subprocess.run(["ffmpeg", "-y", "-ss", "00:00:01", "-i", video, "-frames:v", "1", "-q:v", "2", thumb],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or not os.path.isfile(thumb): raise RuntimeError(f"ffmpeg: {r.stderr[-200:]}")


def extraer_dur(video):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", video],
                       capture_output=True, text=True, timeout=30)
    try: return int(float(r.stdout.strip()))
    except Exception: return 0


def extraer_dims(video):
    r = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width,height", "-of", "csv=p=0", video],
                       capture_output=True, text=True, timeout=30)
    try:
        w, h = r.stdout.strip().split(","); return int(w), int(h)
    except Exception: return 0, 0


def blurhash_thumb(thumb):
    img = Image.open(thumb).convert("RGB")
    img.thumbnail((64, 64))
    return blurhash.encode(np.array(img), components_x=4, components_y=4)


def subir_s3(path, key):
    with S3Client() as s3:
        res = s3.put(path, key, show_progress=False, inline=True)
        if not res["success"]: raise RuntimeError(f"S3: {res['error']}")
        return s3.build_url(key)


def procesar(x, uid, url, reply_to):
    tmp = os.path.join(DOWNLOAD_PATH, uuid.uuid4().hex)
    os.makedirs(tmp, exist_ok=True)
    status = None
    try:
        status = enviar_texto(x, uid, "Analizando...", reply_to=reply_to)
        log.info(f"[{uid}] Analizando id={status}")

        video = descargar_x(url, tmp)
        size = os.path.getsize(video)
        log.info(f"[{uid}] descargado {format_size(size)}")
        if size > MAX_FILE_SIZE: raise RuntimeError(f"Archivo {format_size(size)} > 2 GB")

        thumb = os.path.join(tmp, "thumb.jpg")
        extraer_thumb(video, thumb)
        dur = extraer_dur(video)
        w, h = extraer_dims(video)
        bh = blurhash_thumb(thumb)
        log.info(f"[{uid}] dur={dur}s dims={w}x{h}")

        editar_texto(x, uid, status, "Procesando...", reply_to=reply_to)
        log.info(f"[{uid}] editado Procesando")

        name = os.path.basename(video)
        vurl = subir_s3(video, f"x_videos/{uuid.uuid4().hex}_{name}")
        log.info(f"[{uid}] S3 OK")

        borrar_texto(x, uid, status, "Procesando...", reply_to=reply_to)
        log.info(f"[{uid}] borrado Procesando")

        msg_id = uuid.uuid4().hex[:16]
        file_id = uuid.uuid4().hex[:16]
        to = f"{uid}@{XMPP_DOMAIN}"
        stanza = (
            f'<m to="{to}" t="c" i="{msg_id}" xmlns="jc"><k xmlns="x8"/>'
            f'{_forwarded(uid, reply_to)}'
            f'<video xmlns="video:n" i="{file_id}" mi="{msg_id}" '
            f'url="{xml_escape(vurl)}" n="{xml_escape(name)}" '
            f's="{size}" h="" d="{dur}" w="{w}" he="{h}" tnail="{bh}"/>'
            f'<b/></m>'
        )
        x.send_stanza(stanza)
        log.info(f"[{uid}] video enviado")
    except Exception as e:
        log.exception(f"[{uid}] error")
        try:
            if status: borrar_texto(x, uid, status, "Procesando...", reply_to=reply_to)
        except Exception: pass
        try: enviar_texto(x, uid, f"Error: {str(e)[:300]}", reply_to=reply_to)
        except Exception: pass
    finally:
        try:
            if os.path.isdir(tmp):
                for f in os.listdir(tmp):
                    try: os.unlink(os.path.join(tmp, f))
                    except Exception: pass
                os.rmdir(tmp)
        except Exception: pass


def on_message(stanza):
    global _seen
    try:
        msg_id = extraer_id(stanza)
        if msg_id:
            if msg_id in _seen: return
            _seen.add(msg_id)
            if len(_seen) > _MAX_SEEN: _seen.clear()

        uid, body = extraer_from_body(stanza)
        if not uid: return

        es_chat = "<csc" in stanza or "<csp" in stanza
        if msg_id and not es_chat:
            try: marcar_leido(x_global, uid, msg_id)
            except Exception: pass

        if not body: return
        if any(t in stanza for t in MULTIMEDIA): return

        log.info(f"[{uid}] {body[:100]}")

        if body.lower() in ("/start", "hola", "ayuda", "help"):
            enviar_texto(x_global, uid, "Bot X -> toDus\n\nEnviame un enlace de X/Twitter y te devuelvo el video.")
            return

        url = extract_url(body)
        if not url:
            enviar_texto(x_global, uid, "Enviame un enlace de X/Twitter.")
            return
        if not is_x_url(url):
            enviar_texto(x_global, uid, f"Solo acepto enlaces de X/Twitter.\nRecibi: {url}")
            return
        if uid in activos:
            enviar_texto(x_global, uid, "Ya tienes un trabajo en curso. Espera.")
            return

        activos[uid] = True
        def _run():
            try: procesar(x_global, uid, url, msg_id)
            finally: activos.pop(uid, None)
        threading.Thread(target=_run, daemon=True).start()
    except Exception as e:
        log.exception(f"on_message: {e}")


START = time.time()


async def health(request):
    return web.json_response({"status": "healthy", "uptime": round(time.time() - START, 1), "activos": len(activos)})


async def root(request):
    return web.json_response({"status": "online"})


async def run_web():
    a = web.Application()
    a.router.add_get("/", root)
    a.router.add_get("/health", health)
    runner = web.AppRunner(a)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    return runner


async def watchdog():
    while True:
        await asyncio.sleep(30)
        if WATCHDOG_LIFETIME <= 0: continue
        if time.time() - START > WATCHDOG_LIFETIME:
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(10)
            os._exit(0)


async def main():
    global x_global
    web_runner = await run_web()
    asyncio.create_task(watchdog())
    log.info(f"login {TODUS_PHONE}...")
    jwt = login(TODUS_PHONE)
    log.info(f"JWT OK")
    x_global = XMPP(TODUS_PHONE, jwt)
    x_global.on_message = on_message
    x_global.connect()
    log.info(f"BOT READY - {x_global.full_jid}")
    try:
        await asyncio.Event().wait()
    finally:
        x_global.close()
        await web_runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
