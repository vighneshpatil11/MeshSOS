#!/usr/bin/env python3
"""Simulates a victim phone + relays + gateway. Tests the server without any phones.
   python simulate_sos.py [--server http://localhost:8080] [--chase] [--cancel]"""
import argparse, base64, hashlib, hmac, json, os, time, urllib.request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ap = argparse.ArgumentParser()
ap.add_argument("--server", default="http://localhost:8080")
ap.add_argument("--chase", action="store_true")
ap.add_argument("--cancel", action="store_true")
a = ap.parse_args()
b64 = lambda b: base64.b64encode(b).decode()
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()


def hkdf(ikm):
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, b"MeshSOS-v1-aes256\x01", hashlib.sha256).digest()


def call(url, body=None):
    req = urllib.request.Request(url, json.dumps(body).encode() if body else None,
                                 {"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=5).read())


pk = call(a.server + "/api/pubkey")
print("server fingerprint:", pk["fingerprint"])
eph = ec.generate_private_key(ec.SECP256R1())
key = hkdf(eph.exchange(ec.ECDH(), serialization.load_der_public_key(base64.b64decode(pk["publicKey"]))))
epk = b64(eph.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
tag, cancel_secret = os.urandom(8).hex(), os.urandom(16).hex()
sos_id = "SOS-%s-%s" % (time.strftime("%Y%m%d"), os.urandom(2).hex().upper())
path = ["NODE-AAAAAAAAAAAA", "NODE-BBBBBBBBBBBB", "NODE-CCCCCCCCCCCC"]
locs = []


def packet(typ, seq):
    la, lo = 18.5204 + seq * 0.0003, 73.8567 + seq * 0.0002
    locs.append({"lat": la, "lon": lo, "acc": 8.0, "t": int(time.time() * 1000), "seq": seq})
    pt = json.dumps({"sosId": sos_id, "type": "ORANGE" if a.chase else "RED", "victimId": path[0],
                     "victimName": "Simulated", "contact": "+910000000000", "phone": "+910000000000", "device": {"manufacturer": "realme", "model": "RMX-SIM", "android": "15", "sdk": 35}, "activatedAt": int(time.time() * 1000),
                     "locations": locs[-5:], "nearby": [{"id": path[1], "rssi": -60, "first": 1, "last": int(time.time() * 1000), "n": seq, "tech": "BLE"}]}).encode()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, pt, ("MSOS1|%s|%d" % (tag, seq)).encode())
    token = hmac.new(key, ("ACK|%s|%d" % (tag, seq)).encode(), hashlib.sha256).hexdigest()
    return token, {"v": 1, "id": os.urandom(8).hex(), "tag": tag, "t": typ, "s": seq, "h": 3, "mh": 10,
                   "p": path, "ch": sha(cancel_secret), "ah": sha(token), "tk": "", "epk": epk,
                   "n": b64(nonce), "pl": b64(ct), "gw": "NODE-DDDDDDDDDDDD"}


for seq in range(1, 4 if a.chase else 2):
    token, p = packet(1 if seq == 1 else 2, seq)
    r = call(a.server + "/api/sos", p)
    ok = r.get("ack", {}).get("token") == token
    print("seq", seq, "decrypted:", r.get("decrypted"), "ack token matches phone's:", ok)
    print("   ", r.get("summary", ""))
if a.cancel:
    r = call(a.server + "/api/sos", {"v": 1, "id": os.urandom(8).hex(), "tag": tag, "t": 3, "s": 9, "h": 3,
                                     "mh": 10, "p": path, "tk": cancel_secret, "gw": "NODE-DDDDDDDDDDDD"})
    print("cancel accepted:", r.get("cancelled"))
print("Now look at", a.server)
