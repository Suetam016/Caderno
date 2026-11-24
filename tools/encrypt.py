"""Gera a versão com senha do painel (pra abrir no celular).
Uso: python3 encrypt.py <painel-tinder.html> <arquivo-com-senha> <saida/index.html>
A senha nunca é gravada na saída: só salt + iv + conteúdo cifrado (AES-256-GCM, chave PBKDF2-SHA256 600k)."""
import sys, os, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

src, pwfile, out = sys.argv[1:4]
pw = open(pwfile, encoding="utf-8-sig").read().strip()
if len(pw) < 12:
    sys.exit("senha curta demais (min 12 caracteres)")
ITER = 600000
sf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "salt.bin")  # salt não é segredo; fixo pra "lembrar" continuar valendo
if not os.path.exists(sf): open(sf, "wb").write(os.urandom(16))
salt, iv = open(sf, "rb").read(), os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())
ct = AESGCM(key).encrypt(iv, open(src, "rb").read(), None)
b = lambda x: base64.b64encode(x).decode()
payload = json.dumps({"s": b(salt), "i": b(iv), "n": ITER, "c": b(ct)})

page = r"""<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive"><title>·</title>
<style>
:root{--bg:#111;--fg:#eee;--mu:#888;--ac:#fd5068}
@media (prefers-color-scheme: light){:root:not([data-theme="dark"]){--bg:#f6f6f6;--fg:#111;--mu:#666}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:0 16px;box-sizing:border-box}
form{width:100%;max-width:320px;display:grid;gap:12px}
input[type=password]{font-size:18px;padding:12px;border-radius:10px;border:1px solid var(--mu);background:transparent;color:var(--fg)}
button{font-size:17px;padding:12px;border:0;border-radius:10px;background:var(--ac);color:#fff}
label{color:var(--mu);font-size:14px;display:flex;gap:8px;align-items:center}
#e{color:var(--ac);min-height:1.2em;font-size:14px}
</style></head><body>
<form id="f" hidden><input id="p" type="password" placeholder="senha" autocomplete="current-password" autofocus>
<label><input id="r" type="checkbox" checked> lembrar neste aparelho</label>
<button>Abrir</button><div id="e"></div></form>
<script>
const D=__P__,K="cad.k."+D.s;
const u=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0)),b64=a=>btoa(String.fromCharCode(...new Uint8Array(a)));
async function open_(raw){
  const k=await crypto.subtle.importKey("raw",raw,"AES-GCM",false,["decrypt"]);
  const h=new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:u(D.i)},k,u(D.c)));
  return h;
}
function show(h,k){window.__CADKEY=k;document.querySelectorAll("style").forEach(x=>x.remove());document.body.removeAttribute("style");document.open();document.write(h);document.close()}
async function derive(pw){
  const b=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveBits"]);
  return crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:u(D.s),iterations:D.n},b,256);
}
(async()=>{
  let saved=null;try{saved=localStorage.getItem(K)}catch(e){}
  if(saved){try{show(await open_(u(saved)),saved);return}catch(e){}}
  f.hidden=false;
})();
f.onsubmit=async ev=>{ev.preventDefault();e.textContent="abrindo…";
  try{const raw=await derive(p.value);
    const h=await open_(raw);
    try{if(r.checked)localStorage.setItem(K,b64(raw))}catch(_){}
    show(h,b64(raw));
  }catch(_){e.textContent="senha errada"}};
</script></body></html>"""
os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
open(out, "w", encoding="utf-8").write(page.replace("__P__", payload))
print("ok", out, len(payload))
