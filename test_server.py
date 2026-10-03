#!/usr/bin/env python3
"""
MeshSOS receiver server (runs on a LAPTOP/PC, not on the phone).

  pip install cryptography
  python test_server.py            # then open  http://localhost:8080  in Chrome

* Chrome cannot open http://0.0.0.0:8080 -> use localhost (on this PC) or the
  LAN address printed below (from other devices).
* Generates server_key.pem on first run. Phones "Pair" with it (GET /api/pubkey)
  so SOS payloads are end-to-end encrypted to THIS server only.
* POST /api/sos receives packets from the gateway phone, decrypts, replies with
  an ACK token that travels back through the mesh to the victim.
"""
import argparse, base64, hashlib, hmac, json, os, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

HKDF_INFO = b"MeshSOS-v1-aes256"
HERE = os.path.dirname(os.path.abspath(__file__))


def hkdf(ikm):
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, HKDF_INFO + b"\x01", hashlib.sha256).digest()


def sha256hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def fingerprint(der):
    h = hashlib.sha256(der).hexdigest()[:16].upper()
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


def parse_env_pem(raw):
    """Accepts a PEM pasted in almost any mangled form: quotes, 'MESHSOS_KEY_PEM=' prefix,
    literal \\n, doubled backslashes, or spaces instead of line breaks. Returns clean PEM bytes or None."""
    import re
    t = raw.strip().strip('"').strip("'")
    m = re.search(r"-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----", t, re.S)
    if not m:
        return None
    body = re.sub(r"(\\+n|\\+r|\s)", "", m.group(2))
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    name = m.group(1)
    return ("-----BEGIN %s-----\n%s\n-----END %s-----\n" % (name, "\n".join(lines), name)).encode()


def lan_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    return sorted(ips)


class Store:
    def __init__(self, data_dir):
        self.lock = threading.Lock()
        self.records = {}
        self.log_path = os.path.join(data_dir, "emergencies_log.json")
        self.priv = None
        self.pub_der = b""
        if HAVE_CRYPTO:
            key_path = os.path.join(data_dir, "server_key.pem")
            env_raw = os.environ.get("MESHSOS_KEY_PEM", "")
            if env_raw.strip():   # hosted: keep the SAME key across restarts (free hosts wipe the disk)
                try:
                    self.priv = serialization.load_pem_private_key(parse_env_pem(env_raw), password=None)
                except Exception as e:
                    print("!! MESHSOS_KEY_PEM is invalid (%s). Using a NEW temporary key instead." % type(e).__name__)
                    print("!! Phones will re-fetch the new key automatically, but fix the variable to keep it stable.", flush=True)
                    self.priv = ec.generate_private_key(ec.SECP256R1())
            elif os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    self.priv = serialization.load_pem_private_key(f.read(), password=None)
            else:
                self.priv = ec.generate_private_key(ec.SECP256R1())
                with open(key_path, "wb") as f:
                    f.write(self.priv.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()))
                try:
                    os.chmod(key_path, 0o600)
                except Exception:
                    pass
            self.pub_der = self.priv.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path) as f:
                    self.records = json.load(f)
            except Exception:
                self.records = {}

    def save(self):
        tmp = self.log_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.records, f, indent=1)
        os.replace(tmp, self.log_path)

    def new_record(self, tag):
        now = time.time() * 1000
        return {"tag": tag, "sosId": None, "type": None, "victimId": None, "victimName": None,
                "contact": None, "phone": None, "device": None, "activatedAt": None, "status": "ACTIVE", "decrypted": False,
                "decryptError": None, "firstReceivedAt": now, "lastUpdatedAt": now,
                "packetsReceived": 0, "locations": [], "nearby": {}, "paths": [],
                "acks": [], "cancelHash": "", "pendingCancel": "", "seenKeys": [], "raw": []}

    def ingest(self, p, gw):
        tag, typ, seq = p["tag"], p["t"], p["s"]
        now = time.time() * 1000
        with self.lock:
            rec = self.records.setdefault(tag, self.new_record(tag))
            key = "%s|%s" % (p["id"], "/".join(p.get("p", [])))
            resp = {"status": "ok", "tag": tag, "seq": seq}
            dup = key in rec["seenKeys"]
            if not dup:
                rec["seenKeys"].append(key)
                rec["packetsReceived"] += 1
                rec["lastUpdatedAt"] = now
                rec["paths"].append({"seq": seq, "type": typ, "hops": p.get("h", 0),
                                     "path": p.get("p", []), "gateway": gw, "at": now})
                rec["raw"] = (rec["raw"] + [p])[-300:]
                rec["paths"] = rec["paths"][-300:]
            if typ in (1, 2):
                if p.get("ch") and not rec["cancelHash"]:
                    rec["cancelHash"] = p["ch"]
                    if rec["pendingCancel"] and sha256hex(rec["pendingCancel"]) == p["ch"]:
                        rec["status"] = "CANCELLED"
                self._decrypt(rec, p, resp)
            elif typ == 3:
                tok = p.get("tk", "")
                if rec["cancelHash"] and sha256hex(tok) == rec["cancelHash"]:
                    rec["status"] = "CANCELLED"
                    resp["cancelled"] = True
                else:
                    rec["pendingCancel"] = tok
                    resp["cancelled"] = False
            self.save()
            tag_s = rec["sosId"] or tag
            print("[%s] %s pkt type=%s seq=%s hops=%s via %s path=%s%s" % (
                time.strftime("%H:%M:%S"), tag_s, typ, seq, p.get("h"), gw,
                " > ".join(p.get("p", [])), "  (duplicate)" if dup else ""), flush=True)
            return resp

    def _decrypt(self, rec, p, resp):
        if not HAVE_CRYPTO:
            rec["decryptError"] = "server has no 'cryptography' package"
            resp["decrypted"] = False
            return
        try:
            peer = serialization.load_der_public_key(base64.b64decode(p["epk"]))
            key = hkdf(self.priv.exchange(ec.ECDH(), peer))
            aad = ("MSOS1|%s|%s" % (p["tag"], p["s"])).encode()
            pt = AESGCM(key).decrypt(base64.b64decode(p["n"]), base64.b64decode(p["pl"]), aad)
            d = json.loads(pt.decode("utf-8"))
        except Exception as e:
            rec["decryptError"] = "decrypt failed (phone not paired with THIS server key?): %s" % type(e).__name__
            resp["decrypted"] = False
            return
        rec["decrypted"], rec["decryptError"] = True, None
        resp["decrypted"] = True
        for k_src, k_dst in (("sosId", "sosId"), ("type", "type"), ("victimId", "victimId"),
                             ("victimName", "victimName"), ("contact", "contact"), ("phone", "phone"), ("device", "device"),
                             ("activatedAt", "activatedAt")):
            if d.get(k_src) is not None:
                rec[k_dst] = d[k_src]
        have = {(l["t"], l["lat"], l["lon"]) for l in rec["locations"]}
        for l in d.get("locations", []):
            if (l["t"], l["lat"], l["lon"]) not in have:
                rec["locations"].append(l)
        rec["locations"].sort(key=lambda l: l["t"])
        for n in d.get("nearby", []):
            old = rec["nearby"].get(n["id"])
            if old:
                old["first"] = min(old["first"], n["first"])
                old["last"] = max(old["last"], n["last"])
                old["n"] = max(old["n"], n["n"])
                old["rssi"] = n.get("rssi", old.get("rssi"))
            else:
                rec["nearby"][n["id"]] = n
        token = hmac.new(key, ("ACK|%s|%s" % (p["tag"], p["s"])).encode(), hashlib.sha256).hexdigest()
        if sha256hex(token) == p.get("ah"):
            resp["ack"] = {"tag": p["tag"], "seq": p["s"], "token": token}
            if p["s"] not in rec["acks"]:
                rec["acks"].append(p["s"])
        else:
            rec["decryptError"] = "ack hash mismatch (packet tampered?)"
        if p["t"] == 1:
            loc = rec["locations"][-1] if rec["locations"] else None
            where = ("https://maps.google.com/?q=%s,%s" % (loc["lat"], loc["lon"])) if loc else "location pending"
            resp["summary"] = "MeshSOS %s %s from %s: %s" % (
                "SOS" if d.get("type") == "RED" else "CHASE", d.get("sosId"),
                d.get("victimName") or d.get("victimId"), where)

    def public(self):
        with self.lock:
            out = []
            for r in self.records.values():
                r.setdefault("phone", None); r.setdefault("device", None)
                c = {k: v for k, v in r.items() if k not in ("raw", "seenKeys", "pendingCancel")}
                c["nearby"] = list(r["nearby"].values())
                out.append(c)
            out.sort(key=lambda r: -r["lastUpdatedAt"])
            return out


STORE = None
PORT = 8080
ADMIN_PW = os.environ.get("MESHSOS_ADMIN_PASSWORD", "")
PROTECTED = ("/", "/dashboard", "/index.html", "/api/info", "/api/emergencies")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (
            body.encode() if isinstance(body, str) else json.dumps(body).encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _auth(self):
        if not ADMIN_PW:
            return True
        h = self.headers.get("Authorization", "")
        try:
            user_pw = base64.b64decode(h.split(" ", 1)[1]).decode()
            if hmac.compare_digest(user_pw.split(":", 1)[1], ADMIN_PW):
                return True
        except Exception:
            pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="MeshSOS"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in PROTECTED and not self._auth():
            return
        if path in ("/", "/dashboard", "/index.html"):
            self._send(200, DASHBOARD, "text/html")
        elif path == "/api/pubkey":
            if not STORE.pub_der:
                return self._send(503, {"error": "server needs: pip install cryptography"})
            self._send(200, {"publicKey": base64.b64encode(STORE.pub_der).decode(),
                             "fingerprint": fingerprint(STORE.pub_der)})
        elif path == "/api/info":
            self._send(200, {"fingerprint": fingerprint(STORE.pub_der) if STORE.pub_der else "n/a",
                             "cryptography": HAVE_CRYPTO,
                             "urls": ["http://%s:%d" % (ip, PORT) for ip in lan_ips()]})
        elif path == "/api/health":
            self._send(200, {"status": "ok"})
        elif path == "/api/emergencies":
            self._send(200, STORE.public())
        elif path == "/favicon.ico":
            self._send(204, b"")
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?")[0] != "/api/sos":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n <= 0 or n > 65536:
                raise ValueError("bad length")
            p = json.loads(self.rfile.read(n).decode("utf-8"))
            if not isinstance(p, dict) or p.get("v") != 1 or p.get("t") not in (1, 2, 3, 4):
                raise ValueError("not a MeshSOS v1 packet")
            for k in ("id", "tag"):
                if not isinstance(p.get(k), str) or len(p[k]) != 16:
                    raise ValueError("bad " + k)
            p["s"] = int(p.get("s", 0))
            p["p"] = [str(x) for x in p.get("p", [])][:40]
            gw = str(p.pop("gw", "?"))[:32]
            self._send(200, STORE.ingest(p, gw))
        except Exception as e:
            self._send(400, {"status": "error", "message": str(e)})


DASHBOARD = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>MeshSOS Receiver</title>
<style>
body{font-family:system-ui,sans-serif;background:#121212;color:#eee;margin:0;padding:16px}
h1{color:#ff5252;margin:0 0 4px}.sub{color:#999;font-size:13px;margin-bottom:14px}
.card{background:#1e1e1e;border:1px solid #333;border-radius:10px;padding:14px;margin-bottom:14px}
.b{display:inline-block;padding:2px 9px;border-radius:12px;font-size:12px;margin-right:6px;color:#fff}
.RED{background:#d32f2f}.ORANGE{background:#f57c00}.ok{background:#2e7d32}.no{background:#555}.warn{background:#8d6e00}
table{border-collapse:collapse;font-size:12px;margin-top:6px}td,th{padding:3px 10px;border-bottom:1px solid #333;text-align:left}
.path{color:#66bb6a}a{color:#64b5f6}small{color:#999}svg{background:#101820;border-radius:6px;margin-top:8px}
</style></head><body>
<h1>MeshSOS Emergency Receiver</h1><div class="sub" id="info">loading...</div><div id="list"></div>
<script>
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const T=t=>t?new Date(t).toLocaleTimeString():'-';
function track(L){ if(!L.length) return '';
 const la=L.map(l=>l.lat),lo=L.map(l=>l.lon),k=Math.cos(la[0]*Math.PI/180);
 const a=Math.min(...la),b=Math.max(...la),c=Math.min(...lo),d=Math.max(...lo);
 const w=Math.max((d-c)*k,1e-5),h=Math.max(b-a,1e-5),s=Math.min(280/w,140/h);
 const P=L.map(l=>[10+(l.lon-c)*k*s,150-(l.lat-a)*s]);
 return '<svg width="300" height="160"><polyline fill="none" stroke="#4fc3f7" stroke-width="2" points="'+P.map(p=>p.join(',')).join(' ')+'"/>'+
  P.map((p,i)=>'<circle cx="'+p[0]+'" cy="'+p[1]+'" r="'+(i==P.length-1?6:3)+'" fill="'+(i==P.length-1?'#ff5252':'#4fc3f7')+'"/>').join('')+'</svg>';}
function card(r){
 const t=r.type||'?',L=r.locations,last=L[L.length-1];
 let h='<div class="card"><span class="b '+esc(t)+'">'+(t=='RED'?'SOS':t=='ORANGE'?'CHASE':'ENCRYPTED')+'</span>'+
  '<b>'+esc(r.sosId||('tag '+r.tag))+'</b> <span class="b '+(r.status=='ACTIVE'?'warn':'no')+'">'+esc(r.status)+'</span>'+
  '<span class="b '+(r.decrypted?'ok':'no')+'">'+(r.decrypted?'decrypted':'cannot decrypt')+'</span>'+
  (r.acks.length?'<span class="b ok">ACK sent ('+r.acks.length+')</span>':'')+'<br>';
 if(r.decryptError)h+='<small>'+esc(r.decryptError)+'</small><br>';
 h+='<small>Victim: '+esc(r.victimName||'')+' '+esc(r.victimId||'-')+' | phone: '+esc(r.phone||r.contact||'-')+' | device: '+esc(r.device?(r.device.manufacturer+' '+r.device.model+' (Android '+r.device.android+')'):'-')+' | packets: '+r.packetsReceived+' | last: '+T(r.lastUpdatedAt)+'</small><br>';
 if(last)h+='Latest: <a target="_blank" href="https://maps.google.com/?q='+last.lat+','+last.lon+'">'+last.lat.toFixed(6)+', '+last.lon.toFixed(6)+'</a> <small>±'+Math.round(last.acc)+'m at '+T(last.t)+' ('+L.length+' fixes)</small>'+track(L);
 else if(r.decrypted)h+='<small>No location fix yet</small>';
 const seen={};r.paths.filter(p=>p.type<3).forEach(p=>{seen[p.path.join('>')+'|'+p.gateway]=p});
 h+='<h4>Relay trail</h4>'+Object.values(seen).map(p=>'<div class="path">'+p.path.map(esc).join(' &rarr; ')+' &rarr; <b>'+esc(p.gateway)+'</b> (gateway) <small>'+p.hops+' hops</small></div>').join('');
 if(r.nearby.length)h+='<h4>Nearby observations <small>(possible proximity nodes - NOT confirmed suspects)</small></h4><table><tr><th>Node</th><th>Seen</th><th>First</th><th>Last</th><th>RSSI</th></tr>'+
  r.nearby.map(n=>'<tr><td>'+esc(n.id)+'</td><td>'+n.n+'x</td><td>'+T(n.first)+'</td><td>'+T(n.last)+'</td><td>'+esc(n.rssi)+'</td></tr>').join('')+'</table>';
 return h+'</div>';}
async function go(){try{
 const [i,l]=await Promise.all([fetch('/api/info').then(r=>r.json()),fetch('/api/emergencies').then(r=>r.json())]);
 document.getElementById('info').innerHTML='Phones use: <b>'+esc(i.urls.join('  or  ')||'(no LAN IP found)')+'</b> | key fingerprint: <b>'+esc(i.fingerprint)+'</b>'+(i.cryptography?'':' | <span style="color:#ff5252">install cryptography!</span>')+' | emergencies: '+l.length;
 document.getElementById('list').innerHTML=l.length?l.map(card).join(''):'<div class="card">No emergencies received yet. Waiting...</div>';
}catch(e){document.getElementById('info').textContent='server unreachable'}}
go();setInterval(go,2000);
</script></body></html>"""


def main():
    global STORE, PORT
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    ap.add_argument("--data-dir", default=HERE)
    ap.add_argument("--public-url", default="https://YOUR-PUBLIC-SERVER-URL",
                    help="the stable URL phones should use (e.g. https://xyz.trycloudflare.com)")
    ap.add_argument("--print-env", action="store_true", help="print MESHSOS_KEY_PEM value for a hosting provider")
    a = ap.parse_args()
    PORT = a.port
    STORE = Store(a.data_dir)
    if STORE.pub_der:
        cfg = os.path.join(a.data_dir, "meshsos_config.json")
        with open(cfg, "w") as f:
            json.dump({"serverUrl": a.public_url, "publicKey": base64.b64encode(STORE.pub_der).decode()}, f, indent=1)
        print("  Wrote %s -> upload it to a public URL (GitHub raw/gist) and put that URL in" % cfg)
        print("  gradle.properties as MESHSOS_CONFIG_URL. Phones then find the server automatically.")
    if a.print_env and STORE.priv:
        pem = STORE.priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()).decode()
        print("\nMESHSOS_KEY_PEM=" + pem.strip().replace("\n", "\\n") + "\n")
        return
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.daemon_threads = True
    print("MeshSOS server running.")
    print("  Open in Chrome on this PC : http://localhost:%d" % a.port)
    for ip in lan_ips():
        print("  Use in the PHONE app      : http://%s:%d" % (ip, a.port))
    print("  (Do NOT browse to 0.0.0.0 - Chrome blocks it.)")
    if STORE.pub_der:
        print("  Server key fingerprint    : " + fingerprint(STORE.pub_der))
    else:
        print("  !! pip install cryptography   (needed to decrypt SOS packets)")
    print("  If phones can't connect: allow Python through Windows Firewall (Private networks).")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main()
