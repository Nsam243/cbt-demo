"""Builds index.html: encrypts every student's name with a key made from their own username+password.
Run:  python3 build.py   (needs: pip install cryptography)
Edit students.csv to fix a password, then run again. Do NOT upload students.csv to GitHub."""
import csv, json, os, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ITER = 150000
b64 = lambda b: base64.b64encode(b).decode()
data = {}
for r in csv.DictReader(open("students.csv", encoding="utf-8")):
    user = f"DOM/2Y25/{int(r['sn']):02d}"
    pw = r["password"].strip().upper()
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(f"{user}|{pw}".encode())
    prof = json.dumps({"l": r["last"], "f": r["first"], "o": r["other"]})
    data[user] = {"s": b64(salt), "i": b64(iv), "c": b64(AESGCM(key).encrypt(iv, prof.encode(), None))}
html = open("template.html", encoding="utf-8").read().replace("/*DATA*/", json.dumps(data, separators=(",", ":")))
open("index.html", "w", encoding="utf-8").write(html)
print("Built index.html with", len(data), "students")
