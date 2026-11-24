"""Confere se a senha abre o index.html publicado (sem mostrar a senha). Sai 0 se abre, 3 se não."""
import sys, re, json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
pw = open(sys.argv[1], encoding="utf-8-sig").read().strip().encode()
D = json.loads(re.search(r"const D=(\{.*?\}),K=", open(sys.argv[2], encoding="utf-8").read()).group(1))
u = base64.b64decode
k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=u(D["s"]), iterations=D["n"]).derive(pw)
try: AESGCM(k).decrypt(u(D["i"]), u(D["c"]), None); print("senha confere")
except Exception: print("SENHA NAO CONFERE com o site atual"); sys.exit(3)
