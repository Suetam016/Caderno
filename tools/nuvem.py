"""Cifra/decifra o painel pra publicar sem o PC.
A chave privada é derivada da senha (só existe dentro do GitHub Actions, via secret PAINEL_SENHA).
A chave pública (tools/nuvem.pub) pode ficar no repo: com ela só dá pra cifrar.
  python3 nuvem.py pub <arquivo-senha> <saida.pub>
  python3 nuvem.py enc <nuvem.pub> <entrada.html> <saida.enc>
  python3 nuvem.py dec <arquivo-senha> <entrada.enc> <saida.html>"""
import sys, os, hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
here = os.path.dirname(os.path.abspath(__file__))
def priv(pwfile):
    pw = open(pwfile, encoding="utf-8-sig").read().strip().encode()
    salt = b"caderno-nuvem-v1" + open(os.path.join(here, "salt.bin"), "rb").read()
    return X25519PrivateKey.from_private_bytes(PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(pw))
def key(shared, eph, rcpt): return hashlib.sha256(shared + eph + rcpt).digest()
cmd = sys.argv[1]
if cmd == "pub":
    open(sys.argv[3], "wb").write(priv(sys.argv[2]).public_key().public_bytes(**RAW))
elif cmd == "enc":
    rcpt = open(sys.argv[2], "rb").read(); e = X25519PrivateKey.generate()
    ep = e.public_key().public_bytes(**RAW); iv = os.urandom(12)
    k = key(e.exchange(X25519PublicKey.from_public_bytes(rcpt)), ep, rcpt)
    open(sys.argv[4], "wb").write(ep + iv + AESGCM(k).encrypt(iv, open(sys.argv[3], "rb").read(), None))
elif cmd == "dec":
    p = priv(sys.argv[2]); b = open(sys.argv[3], "rb").read(); rcpt = p.public_key().public_bytes(**RAW)
    k = key(p.exchange(X25519PublicKey.from_public_bytes(b[:32])), b[:32], rcpt)
    open(sys.argv[4], "wb").write(AESGCM(k).decrypt(b[32:44], b[44:], None))
