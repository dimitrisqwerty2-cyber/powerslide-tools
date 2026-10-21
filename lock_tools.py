"""Password-protects some tools on the Powerslide Tools site.

Run "Lock tools.bat" (or: python lock_tools.py). It asks for the password, then for every tool in PROTECT:
  - encrypts its page and data files from ../Powerslide_Tools_private/tools/<tool>/ into <file>.enc here
    (AES-256-GCM, key from the password with PBKDF2-SHA256, 600,000 rounds, a new random salt each run);
  - copies the tool's plain assets (fonts, logos, flags) as they are;
  - writes a small index.html that asks for the password and opens the tool in the browser.
The password itself is never stored anywhere. Finally it uploads the site as a single fresh commit, so no
unencrypted copy stays in the repository's history.

Options: --no-push   only build the files here (nothing is uploaded)
         --password-stdin   read the password from standard input (for testing)"""
import base64, getpass, json, os, secrets, shutil, subprocess, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
PRIVATE = os.path.join(os.path.dirname(HERE), 'Powerslide_Tools_private', 'tools')
ROUNDS = 600_000
# tool folder -> (title, files to encrypt; everything else in the folder is copied as it is)
PROTECT = {
    'site-builder': ('Post Builder', ['index.html', 'targets.json']),
    'rally-doc': ('Rally Doc Builder', ['index.html', 'library.json', 'template.json', 'py/export_docx.py', 'py/import_docx.py']),
}

LOCK_PAGE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>__TITLE__ | Powerslide Tools</title>
<style>
  :root{--bg:#1e1e1e;--panel:#2c2c2c;--head:#383838;--line:#161616;--line2:#444;--text:#d6d6d6;--muted:#8e8e8e;--accent:#2f8be6}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
  form{width:min(360px,92vw);background:var(--panel);border:1px solid var(--line)}
  h1{margin:0;padding:7px 14px;background:var(--head);border-top:1px solid var(--line2);border-bottom:1px solid var(--line);font-size:12.5px;font-weight:600;color:#e4e4e4}
  .in{padding:16px 14px}
  label{display:block;margin-bottom:4px;font-size:12px;color:var(--muted)}
  input[type=password]{width:100%;height:30px;padding:3px 8px;background:#1c1c1c;color:var(--text);border:1px solid #111;border-radius:2px;font:inherit;outline:none}
  input[type=password]:focus{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
  .row{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:12px}
  .row label{display:flex;align-items:center;gap:6px;margin:0;color:var(--text);cursor:pointer}
  button{height:28px;padding:0 16px;background:var(--accent);border:1px solid #1b5ea3;border-radius:2px;color:#fff;font:inherit;font-weight:600;cursor:pointer}
  button:disabled{opacity:.6;cursor:default}
  #msg{min-height:18px;margin-top:10px;font-size:12.5px;color:#e0786b}
  a{color:var(--muted);font-size:12px}
</style>
</head>
<body>
<form id="f" autocomplete="on">
  <h1>__TITLE__</h1>
  <div class="in">
    <label for="pw">This tool is password protected</label>
    <input type="text" name="username" value="Powerslide Tools" autocomplete="username" hidden>
    <input type="password" id="pw" autocomplete="current-password" autofocus>
    <div class="row"><label><input type="checkbox" id="keep">Remember on this device</label><button id="go">Open</button></div>
    <div id="msg"></div>
    <a href="../../">← All tools</a>
  </div>
</form>
<script>
(() => {   // kept in its own scope: the tool opens in this same window and must not meet these names
'use strict';
// The tool's page and data are stored encrypted (AES-256-GCM; key from the password with PBKDF2-SHA256).
// The right password decrypts them here, in the browser, and the tool opens in place.
const CFG = __CFG__;
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const KEEP = 'pwlock:' + location.pathname + ':' + CFG.salt;
const TYPES = {html: 'text/html', json: 'application/json', py: 'text/plain', js: 'text/javascript'};
async function derive(pw) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'PBKDF2', salt: b64(CFG.salt), iterations: CFG.rounds, hash: 'SHA-256'}, km, {name: 'AES-GCM', length: 256}, true, ['decrypt']);
}
const realFetch = window.fetch.bind(window);
async function dec(key, rel) {
  const r = await realFetch(rel + '.enc', {cache: 'no-cache'});
  if (!r.ok) throw new Error('missing ' + rel);
  const b = new Uint8Array(await r.arrayBuffer());
  return crypto.subtle.decrypt({name: 'AES-GCM', iv: b.slice(0, 12)}, key, b.slice(12));
}
async function open(key) {
  const html = await dec(key, 'index.html');            // throws on a wrong password
  const base = new URL('.', location.href).href;
  window.fetch = (input, init) => {                      // the tool's own data files are decrypted as it asks for them
    const u = new URL(typeof input === 'string' ? input : input.url, location.href).href.split(/[?#]/)[0];
    const rel = u.startsWith(base) ? decodeURIComponent(u.slice(base.length)) : '';
    if (rel && rel !== 'index.html' && CFG.files.includes(rel))
      return dec(key, rel).then(buf => new Response(buf, {headers: {'Content-Type': TYPES[rel.split('.').pop()] || 'application/octet-stream'}}));
    return realFetch(input, init);
  };
  document.open(); document.write(new TextDecoder().decode(html)); document.close();
}
const msg = t => { document.getElementById('msg').textContent = t; };
document.getElementById('f').addEventListener('submit', async e => {
  e.preventDefault();
  const pw = document.getElementById('pw').value, go = document.getElementById('go');
  if (!pw) return;
  go.disabled = true; msg('');
  try {
    const key = await derive(pw);
    if (document.getElementById('keep').checked) {
      try { localStorage.setItem(KEEP, btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', key))))); } catch (_) {}
    }
    await open(key);
  } catch (err) { go.disabled = false; msg(err && /missing/.test(err.message) ? 'The tool files are missing on the site.' : 'Wrong password.'); }
});
(async () => {                                            // remembered on this device: open straight away
  let k = null; try { k = localStorage.getItem(KEEP); } catch (_) {}
  if (!k) return;
  try { await open(await crypto.subtle.importKey('raw', b64(k), 'AES-GCM', false, ['decrypt'])); }
  catch (_) { try { localStorage.removeItem(KEEP); } catch (__) {} }
})();
})();
</script>
</body>
</html>
'''


def ask_password():
    if '--password-stdin' in sys.argv:
        return sys.stdin.readline().rstrip('\r\n')
    while True:
        a = getpass.getpass('Password for the protected tools (nothing shows while you type): ')
        if len(a) < 8:
            print('Use at least 8 characters.'); continue
        if getpass.getpass('Same password again: ') != a:
            print('The two did not match, try again.'); continue
        return a


def lock_tool(name, title, enc_files, password):
    src = os.path.join(PRIVATE, name)
    dst = os.path.join(HERE, 'tools', name)
    if not os.path.isfile(os.path.join(src, 'index.html')):
        raise SystemExit(f'Missing {src}\\index.html (the unencrypted copy of {title}).')
    salt = secrets.token_bytes(16)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ROUNDS).derive(password.encode('utf8'))
    aes = AESGCM(key)
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    for root, _, files in os.walk(src):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), src).replace(os.sep, '/')
            out = os.path.join(dst, *rel.split('/'))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            data = open(os.path.join(root, f), 'rb').read()
            if rel in enc_files:
                iv = secrets.token_bytes(12)
                open(out + '.enc', 'wb').write(iv + aes.encrypt(iv, data, None))
            else:
                shutil.copyfile(os.path.join(root, f), out)
    cfg = {'salt': base64.b64encode(salt).decode(), 'rounds': ROUNDS, 'files': enc_files}
    page = LOCK_PAGE.replace('__TITLE__', title).replace('__CFG__', json.dumps(cfg))
    open(os.path.join(dst, 'index.html'), 'w', encoding='utf8', newline='\n').write(page)
    print(f'  {title}: {len(enc_files)} files encrypted')


def git(*a):
    r = subprocess.run(['git', *a], cwd=HERE, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit('git ' + ' '.join(a) + ' failed:\n' + r.stderr)
    return r.stdout.strip()


def push():
    # one fresh commit, so the history holds no unencrypted copy of a protected tool
    branch = git('rev-parse', '--abbrev-ref', 'HEAD')
    git('checkout', '-q', '--orphan', 'publish-tmp')
    git('add', '-A')
    git('commit', '-q', '-m', 'Powerslide Tools')
    git('branch', '-D', branch)
    git('branch', '-m', branch)
    git('push', '-q', '--force', 'origin', branch)
    print('Uploaded. GitHub needs about a minute before the site shows the change.')


if __name__ == '__main__':
    print('Powerslide Tools: password protection\n')
    pw = ask_password()
    print('Encrypting…')
    for name, (title, files) in PROTECT.items():
        lock_tool(name, title, files, pw)
    if '--no-push' in sys.argv:
        print('Built here only (--no-push).')
    else:
        push()
