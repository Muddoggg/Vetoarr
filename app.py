"""Private, approval-gated Maintainerr deletion request portal."""
import hashlib
import logging
import os
import re
import secrets
import sqlite3
import time
from functools import wraps
from urllib.parse import quote, urlsplit, urlencode

import requests
from flask import Flask, abort, flash, g, redirect, render_template_string, request, session, url_for
from cryptography.fernet import Fernet, InvalidToken
import base64

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
DB = os.getenv('DATABASE_PATH', '/data/requests.sqlite3')
PLEX_URL = os.environ['PLEX_URL'].rstrip('/')
PLEX_TOKEN = os.environ['PLEX_TOKEN']
MAINTAINERR_URL = os.environ['MAINTAINERR_URL'].rstrip('/')
MOVIE_COLLECTION = int(os.environ['MOVIE_COLLECTION_ID'])
SHOW_COLLECTION = int(os.environ['SHOW_COLLECTION_ID'])
# Map exact Plex library names (and media types) to their Maintainerr collection IDs.
# Fail closed on missing, renamed, or duplicate libraries.
LIBRARY_COLLECTIONS = {
    ('Movies', 'movie'): MOVIE_COLLECTION,
    ('TV Shows', 'show'): SHOW_COLLECTION,
    ('Kids Movies', 'movie'): int(os.environ['KIDS_MOVIE_COLLECTION_ID']),
    ('Anime Movies', 'movie'): int(os.environ['ANIME_MOVIE_COLLECTION_ID']),
    ('Kids TV Shows', 'show'): int(os.environ['KIDS_SHOW_COLLECTION_ID']),
    ('Anime TV Shows', 'show'): int(os.environ['ANIME_SHOW_COLLECTION_ID']),
}
MIN_DELETE_DAYS = max(1, int(os.getenv('MIN_DELETE_DAYS', '7')))
MAX_SEARCH_LENGTH = 100
BROWSE_PAGE_SIZE = 30
MAX_BULK_ITEMS = 20
MAX_CONTENT_LENGTH = 4096
PLEX_SSO_CLIENT_ID = os.getenv('PLEX_SSO_CLIENT_ID', 'media-approval-portal-unraid-v6')
PLEX_CLOUD = 'https://plex.tv'
MEMBERSHIP_CHECK_SECONDS = 300
PORTAL_HOST = os.environ['PORTAL_HOST'].strip().lower()
if not re.fullmatch(r'[a-z0-9.-]+', PORTAL_HOST) or '.' not in PORTAL_HOST:
    raise RuntimeError('Invalid PORTAL_HOST')
# Plex is the only identity provider. Cloudflare proxy handles TLS/WAF only.
# Do not trust CF-Connecting-IP or X-Forwarded-* as an authentication signal.

for name, base in [('PLEX_URL', PLEX_URL), ('MAINTAINERR_URL', MAINTAINERR_URL)]:
    parts = urlsplit(base)
    if parts.scheme not in ('http', 'https') or not parts.netloc or parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('', '/'):
        raise RuntimeError(f'{name} must be an http(s) server origin without credentials or path')
if (any(type(x) is not int or x < 1 for x in LIBRARY_COLLECTIONS.values())
        or len(set(LIBRARY_COLLECTIONS.values())) != len(LIBRARY_COLLECTIONS)):
    raise RuntimeError('Provide six distinct positive Maintainerr collection IDs')
key = os.environ['SECRET_KEY']
if len(key) < 64 or key.startswith('REPLACE_'):
    raise RuntimeError('SECRET_KEY must be a random value at least 64 characters long')
app.secret_key = key
fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256((key + "plex-sso-v6").encode()).digest()))
app.config.update(
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',  # Required for return from Plex SSO
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_NAME='__Host-media_approval',
    PERMANENT_SESSION_LIFETIME=1800,
    TRUSTED_HOSTS=[PORTAL_HOST],
)

# Ignore host proxy environment and avoid forwarding Plex owner token across redirects.
http = requests.Session()
http.trust_env = False
http.max_redirects = 0


def conn():
    c = sqlite3.connect(DB, timeout=5)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=5000')
    return c


def setup():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    os.chmod(os.path.dirname(DB), 0o700)
    with conn() as c:
        # Keep the original users table and request history intact for rollback.
        c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, session_epoch INTEGER NOT NULL DEFAULT 0)')
        c.execute("""CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, requester TEXT NOT NULL, plex_id TEXT NOT NULL,
            media_type TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, decided_at TEXT, decided_by TEXT, error TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS plex_sessions (
            plex_user_id TEXT PRIMARY KEY, username TEXT NOT NULL, encrypted_token BLOB NOT NULL, encrypted_server_token BLOB,
            session_epoch INTEGER NOT NULL DEFAULT 0, last_validated INTEGER NOT NULL DEFAULT 0)""")
        cols = {r['name'] for r in c.execute('PRAGMA table_info(plex_sessions)')}
        if 'encrypted_server_token' not in cols:
            c.execute('ALTER TABLE plex_sessions ADD COLUMN encrypted_server_token BLOB')
        c.execute('CREATE TABLE IF NOT EXISTS portal_meta (name TEXT PRIMARY KEY, value INTEGER NOT NULL)')
        c.execute("INSERT OR IGNORE INTO portal_meta VALUES ('global_epoch',0)")
        c.execute('CREATE TABLE IF NOT EXISTS auth_attempts (access_subject TEXT NOT NULL, attempted_at INTEGER NOT NULL)')
        # One-time migration: revoke sessions that were bound to Cloudflare identities.
        migration = c.execute("SELECT value FROM portal_meta WHERE name='plex_only_migrated'").fetchone()
        if migration is None:
            c.execute("UPDATE portal_meta SET value=value+1 WHERE name='global_epoch'")
            c.execute("INSERT INTO portal_meta (name,value) VALUES ('plex_only_migrated',1)")
            c.execute('DELETE FROM auth_attempts')
        c.execute('CREATE INDEX IF NOT EXISTS idx_auth_attempts_time ON auth_attempts(attempted_at)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_requests_requester ON requests(requester,status)')
        # Migration guard: never discard/merge potentially destructive requests.
        duplicate = c.execute("""SELECT plex_id, COUNT(*) AS n FROM requests
            WHERE status IN ('pending','processing','approved','review')
            GROUP BY plex_id HAVING COUNT(*) > 1 LIMIT 1""").fetchone()
        if duplicate is not None:
            raise RuntimeError('Duplicate active requests detected; back up and resolve manually before starting')
        # SQLite enforces the uniqueness rule even across simultaneous workers.
        c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS uq_requests_active_plex_media
            ON requests(plex_id)
            WHERE status IN ('pending','processing','approved','review')""")
    if os.path.exists(DB):
        os.chmod(DB, 0o600)

setup()

# A restart may interrupt an approval after Maintainerr committed its change.
# Fail closed: mark it for manual review, NEVER resubmit automatically.
def quarantine_interrupted_approvals():
    with conn() as c:
        c.execute("""UPDATE requests SET status='review',
                   error='Interrupted approval: check collection membership before resolving'
                   WHERE status='processing'""")


BASE = """<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Vetoarr</title><link rel="icon" type="image/svg+xml" href="/static/icon.svg"><style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;color:#edf1f8;background:#090d15}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 65% -12%,#1b3154 0,transparent 48%),#090d15}a{color:#92c5ff;text-decoration:none}a:hover{text-decoration:underline}.shell{max-width:1120px;margin:0 auto;padding:26px 26px 90px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding-bottom:25px;border-bottom:1px solid #283242}.logo{display:flex;align-items:center;gap:10px}.logo img{width:28px;height:28px;display:block}.logo{font-weight:800;font-size:19px;letter-spacing:-.6px}.logo b{color:#6aafff}.userbar{display:flex;align-items:center;gap:14px;color:#a4b2c8;font-size:13px}.userbar form{display:inline}.hero{padding:42px 0 20px}.eyebrow,.auth-badge{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#8abfff;font-weight:800}.hero h1,.auth h1{font-size:clamp(32px,5vw,52px);line-height:1.1;letter-spacing:-1.8px;margin:14px 0}.hero p,.auth p{color:#9cacc1;max-width:640px;line-height:1.65}.layout{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(270px,1fr);gap:20px}.panel{background:#131c2a;border:1px solid #2a3748;border-radius:18px;padding:23px;margin:18px 0;box-shadow:0 10px 32px #0002}.panel h2,.panel h3{margin:0 0 16px;font-size:19px;letter-spacing:-.4px}.muted,small{color:#9baabd}.tiny{font-size:12px}.notice{padding:13px 18px;background:#19334e;border:1px solid #355473;border-radius:12px;margin:16px 0}.fields{display:flex;gap:10px}.fields input{flex:1;min-width:0}input[type=text],input[name=q]{padding:13px 15px;background:#0e1622;border:1px solid #36465b;border-radius:11px;color:#f0f4fc;font:inherit;min-width:0}button,.pill{padding:11px 15px;background:#25344a;border:1px solid #3c516d;color:#f1f5ff;border-radius:10px;font:inherit;font-size:13px;font-weight:700;cursor:pointer}button:hover{filter:brightness(1.17)}button.primary{background:#427ee7;border-color:#5597f9}button.danger{background:#4f2531;border-color:#a64a60;color:#ffc4ce}.big{padding:15px 22px;font-size:16px}.line{display:flex;gap:12px;align-items:center;padding:13px 2px;border-bottom:1px solid #293547}.line:last-child{border:0}.line label{flex:1;cursor:pointer}.line small{display:block;margin-top:4px}.line input[type=checkbox]{accent-color:#75adff;width:18px;height:18px}.line form{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap}.line button{padding:8px 11px}.tag{display:inline-block;background:#273c59;color:#add1ff;border:1px solid #35547b;border-radius:8px;padding:4px 9px;font-size:11px;margin:0 3px 4px 0}.pending{background:#55451e;color:#f9da92}.approved{background:#1c4637;color:#a3ecd1}.rejected{background:#4d2830;color:#ffd1db}.review{background:#523627;color:#ffbe94}details{border:1px solid #2f4156;border-radius:12px;padding:14px;margin:10px 0;background:#111a28}summary{cursor:pointer;font-weight:750;font-size:17px;list-style-position:inside}summary::marker{color:#7aaaff}.library-link{display:inline-block;padding:9px 13px;border-radius:10px;margin:9px 6px 6px 0;background:#243851}.pager{display:flex;gap:15px;padding-top:15px}.auth{max-width:560px;margin:11vh auto;border:1px solid #31445c;border-radius:22px;padding:48px;background:#111c2b}.auth h1 span{color:#8cbcff}form{margin:0}.section-head{display:flex;align-items:center;justify-content:space-between;gap:10px}.request-title{font-size:14px;font-weight:750}.request-panel{overflow:hidden}.request-list{max-height:540px;overflow-y:auto;overscroll-behavior:contain;scrollbar-gutter:stable;padding-right:5px}.request-panel .section-head{position:sticky;top:0;background:#131c2a;z-index:1;padding-bottom:12px;flex-wrap:wrap}.request-panel .section-head h2{margin:0}.request-meta{font-size:12px;color:#a5b3c8;line-height:1.6;margin-top:3px}.batchbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:15px;flex-wrap:wrap}.empty{padding:14px;color:#8c9fb8}@media(max-width:820px){.layout{grid-template-columns:1fr}.shell{padding:18px 15px 50px}.panel{padding:17px}.userbar{gap:6px;flex-wrap:wrap;justify-content:flex-end}.request-list{max-height:390px}.hero{padding:25px 0 10px}.fields{flex-direction:column}.auth{padding:28px;margin:8vh auto}}
</style></head><body><div class="shell"><header class="topbar"><a class="logo" href="/"><img src="/static/icon.png" alt="" aria-hidden="true">Vetoarr</a>{% if user %}<div class="userbar"><span>{{user}}</span><a href="{{url_for('index')}}">Library</a><a href="{{url_for('my_requests')}}">My requests</a>{% if role=='admin' %}<a href="{{url_for('all_requests')}}">All requests</a>{% endif %}<form method="post" action="{{url_for('logout')}}"><input type="hidden" name="csrf" value="{{csrf}}"><button>Sign out</button></form></div>{% endif %}</header>{% for msg in get_flashed_messages() %}<p class="notice">{{msg}}</p>{% endfor %}{{content|safe}}</div></body></html>"""


def page(html, **ctx):
    csrf = get_csrf()
    inner = render_template_string(html, csrf=csrf, **ctx)
    return render_template_string(BASE, content=inner, user=session.get('username'), role=session.get('role'), csrf=csrf)


def get_csrf():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    return session['csrf']


def csrf_check():
    submitted = request.form.get('csrf', '')
    if not submitted or not secrets.compare_digest(submitted, session.get('csrf', '')):
        abort(403)


def plex_headers(token=None):
    h = {'Accept': 'application/json', 'X-Plex-Product': 'Vetoarr',
         'X-Plex-Client-Identifier': PLEX_SSO_CLIENT_ID}
    if token:
        h['X-Plex-Token'] = token
    return h


def plex_cloud(method, path, *, token=None, **kwargs):
    # All cloud destinations are constant and TLS-verified; never follow redirects.
    resp = http.request(method, PLEX_CLOUD + path, headers=plex_headers(token),
                        timeout=(4, 12), allow_redirects=False, **kwargs)
    resp.raise_for_status()
    if resp.is_redirect:
        raise ValueError('Unexpected Plex cloud redirect')
    return resp.json()


def plex_identity(token):
    user = plex_cloud('GET', '/api/v2/user', token=token)
    uid = str(user.get('id', ''))
    if not re.fullmatch(r'[0-9]{1,18}', uid):
        raise ValueError('Invalid Plex account identity')
    return {'id': uid, 'username': str(user.get('username') or user.get('title') or 'Plex user')[:120]}


def server_identifier():
    item = plex_get('/identity')
    machine = item.get('machineIdentifier')
    if not isinstance(machine, str) or not machine or len(machine) > 150:
        raise ValueError('Cannot identify Plex server')
    return machine


def plex_server_token(token):
    machine = server_identifier()
    resources = plex_cloud('GET', '/api/v2/resources?includeHttps=1', token=token)
    if not isinstance(resources, list):
        raise ValueError('Invalid Plex resource response')
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        if (str(resource.get('clientIdentifier', '')) == machine and
            resource.get('provides') and 'server' in str(resource.get('provides')).split(',')):
            return resource.get('accessToken') or token
    return None


def plex_owner_id():
    # The configured Plex token must own this specific server, not merely be shared.
    machine = server_identifier()
    resources = plex_cloud('GET', '/api/v2/resources?includeHttps=1', token=PLEX_TOKEN)
    owned = any(isinstance(r, dict) and
                str(r.get('clientIdentifier', '')) == machine and
                r.get('owned') is True for r in resources)
    if not owned:
        raise ValueError('Configured PLEX_TOKEN does not own this Plex server')
    return plex_identity(PLEX_TOKEN)['id']


def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        uid = session.get('plex_uid')
        if not uid:
            return redirect(url_for('login'))
        with conn() as c:
            row = c.execute('SELECT * FROM plex_sessions WHERE plex_user_id=?', (uid,)).fetchone()
            global_epoch = c.execute("SELECT value FROM portal_meta WHERE name='global_epoch'").fetchone()[0]
        if (not row or session.get('epoch') != row['session_epoch'] or
            session.get('global_epoch') != global_epoch):
            session.clear()
            return redirect(url_for('login'))
        now = int(time.time())
        if now - row['last_validated'] >= MEMBERSHIP_CHECK_SECONDS:
            try:
                token = fernet.decrypt(bytes(row['encrypted_token'])).decode()
                identity = plex_identity(token)
                if identity['id'] != uid or not plex_server_token(token):
                    raise ValueError('Plex access removed')
            except (requests.RequestException, ValueError, InvalidToken, KeyError, TypeError, UnicodeError):
                # Fail closed when Plex is unavailable or access was revoked.
                session.clear()
                abort(403)
            with conn() as c:
                c.execute('UPDATE plex_sessions SET last_validated=? WHERE plex_user_id=?', (now, uid))
        if not row['encrypted_server_token']:
            session.clear()
            abort(403)
        try:
            g.plex_server_token = fernet.decrypt(bytes(row['encrypted_server_token'])).decode()
        except (InvalidToken, UnicodeError):
            session.clear()
            abort(403)
        session['user'] = 'plex:' + uid
        session['username'] = row['username']
        session['role'] = 'admin' if uid == plex_owner_id() else 'requester'
        return f(*args, **kwargs)
    return decorated


@app.before_request
def enforce_portal_security():
    # TRUSTED_HOSTS checks the configured public hostname; session cookie is
    # __Host- scoped, Secure and HttpOnly. No proxy identity headers are trusted.
    if request.path.startswith('/auth/') or request.path == '/login':
        # Initialize a per-browser anonymous identifier for pre-login throttling.
        if not session.get('browser_nonce'):
            session['browser_nonce'] = secrets.token_urlsafe(24)
    return None

@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    resp.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    return resp


def service_json(method, url, *, token=False, **kwargs):
    headers = {'Accept': 'application/json'}
    if token:
        headers['X-Plex-Product'] = 'Vetoarr'
        headers['X-Plex-Client-Identifier'] = 'media-approval-portal-unraid'
    if token:
        headers['X-Plex-Token'] = PLEX_TOKEN
    response = http.request(method, url, headers=headers, timeout=(3, 12), allow_redirects=False, **kwargs)
    response.raise_for_status()
    if response.status_code in (301, 302, 303, 307, 308):
        raise ValueError('Service sent unexpected redirect')
    if not response.content:
        if method == 'POST' and response.status_code == 201:
            return None  # Maintainerr may intentionally return an empty success body.
        raise ValueError('Unexpected empty API response')
    return response.json()


def plex_get(path, params=None, *, user_scoped=False):
    if user_scoped:
        user_token = getattr(g, 'plex_server_token', None)
        if not user_token:
            raise ValueError('Missing authorized server access')
        response = http.get(PLEX_URL + path, params=params, headers=plex_headers(user_token), timeout=(3, 12), allow_redirects=False)
        response.raise_for_status()
        if response.is_redirect:
            raise ValueError('Unexpected Plex redirect')
        result = response.json()
    else:
        result = service_json('GET', PLEX_URL + path, params=params, token=True)
    if not isinstance(result, dict) or not isinstance(result.get('MediaContainer'), dict):
        raise ValueError('Unexpected Plex response')
    return result['MediaContainer']


def plex_item(media_id, *, user_scoped=True):
    if not re.fullmatch(r'[0-9]{1,18}', media_id):
        raise ValueError('Invalid Plex ID')
    entries = plex_get('/library/metadata/' + quote(media_id, safe=''), user_scoped=user_scoped).get('Metadata', [])
    if not isinstance(entries, list) or not entries:
        raise ValueError('Plex item unavailable')
    item = entries[0]
    if item.get('type') not in ('movie', 'show') or str(item.get('ratingKey')) != media_id:
        raise ValueError('Media type or identity mismatch')
    section_id = str(item.get('librarySectionID', ''))
    if not re.fullmatch(r'[0-9]{1,10}', section_id):
        raise ValueError('Plex item has no valid library section ID')
    return {'id': media_id, 'title': item.get('title', 'Untitled'),
            'type': item['type'], 'section_id': section_id}


def check_collection(collection_id, expected_type, expected_library_id):
    collection = service_json('GET', MAINTAINERR_URL + f'/api/collections/collection/{collection_id}')
    if not isinstance(collection, dict):
        raise ValueError('Maintainerr collection is missing')
    # The Maintainerr libraryId must match Plex's verified librarySectionID.
    # Maintainerr documents libraryId as a string; accept a numeric JSON int as well.
    library_id = collection.get('libraryId')
    if (type(library_id) not in (str, int)
            or not re.fullmatch(r'[0-9]{1,10}', str(library_id))
            or str(int(library_id)) != str(int(expected_library_id))):
        raise ValueError('Maintainerr collection libraryId does not match Plex section')
    # Fail closed: unknown/empty settings or unexpectedly dangerous zero-day timer.
    days = collection.get('deleteAfterDays')
    if (collection.get('type') != expected_type or collection.get('isActive') is not True
            or type(collection.get('arrAction')) is not int or collection['arrAction'] != 0
            or type(days) is not int or days < MIN_DELETE_DAYS):
        raise ValueError('Collection type, active status, delete action, or safety delay is incorrect')
    if int(collection.get('id', -1)) != collection_id:
        raise ValueError('Collection ID mismatch')
    return collection


def has_membership(collection_id, media_id):
    members = service_json('GET', MAINTAINERR_URL + '/api/collections/media', params={'collectionId': collection_id})
    if not isinstance(members, list):
        raise ValueError('Unverifiable Maintainerr membership response')
    return any(isinstance(member, dict) and str(member.get('mediaServerId')) == media_id for member in members)


@app.get('/login')
def login():
    if session.get('plex_uid'):
        return redirect(url_for('index'))
    return page("""<section class="auth"><div class="auth-badge">PLEX ACCESS</div><h1>One library.<br><span>Cleaner together.</span></h1><p class="muted">Sign in with the Plex account that has access to this server. Anyone can request; only the server owner can approve.</p><form method="post" action="{{url_for('start_plex')}}"><input type="hidden" name="csrf" value="{{csrf}}"><button class="primary big">Sign in with Plex <span>↗</span></button></form><p class="muted tiny">Protected by Plex sign-in and server-specific permissions</p></section>""")


@app.post('/auth/plex/start')
def start_plex():
    csrf_check()
    # Browser-session rate limit; do not trust spoofable forwarding headers.
    # Cloudflare edge WAF rate limiting is required to deter cookie rotation.
    now = int(time.time())
    sub_hash = hashlib.sha256(session['browser_nonce'].encode()).hexdigest()
    with conn() as c:
        c.execute('DELETE FROM auth_attempts WHERE attempted_at < ?', (now - 600,))
        count = c.execute('SELECT COUNT(*) FROM auth_attempts WHERE access_subject=?', (sub_hash,)).fetchone()[0]
        if count >= 10:
            abort(429)
        c.execute('INSERT INTO auth_attempts VALUES (?,?)', (sub_hash, now))
    try:
        pin = plex_cloud('POST', '/api/v2/pins?strong=true')
        pin_id = int(pin['id'])
        pin_code = str(pin['code'])
        if not 0 < pin_id < 10**15 or not 8 <= len(pin_code) <= 100:
            raise ValueError('Invalid PIN')
    except (requests.RequestException, ValueError, KeyError, TypeError):
        flash('Plex sign-in is unavailable. Try again later.')
        return redirect(url_for('login'))
    session['plex_pin_id'] = pin_id
    session['plex_pin_started'] = int(time.time())
    session['pin_browser_nonce'] = session['browser_nonce']
    session['pin_nonce'] = secrets.token_urlsafe(24)
    forward = 'https://' + PORTAL_HOST + url_for('plex_callback') + '?nonce=' + quote(session['pin_nonce'], safe='')
    args = urlencode({'clientID': PLEX_SSO_CLIENT_ID, 'code': pin_code,
                      'context[device][product]': 'Vetoarr', 'forwardUrl': forward})
    # Do not redirect a POST form submission across origins. Browsers enforce
    # form-action on the entire form navigation, including redirect targets.
    # Instead render a local confirmation with a normal user-activated link.
    # This preserves form-action 'self' without weakening the CSP.
    plex_auth_url = 'https://app.plex.tv/auth#?' + args
    return page("""<section class="auth"><div class="auth-badge">PLEX ACCESS</div>
      <h1>Continue to <span>Plex</span></h1>
      <p class="muted">Your secure Plex sign-in request is ready. Continue to Plex to authorize access.</p>
      <p><a class="pill primary big" href="{{plex_auth_url}}" rel="noreferrer">Continue to Plex ↗</a></p>
      <p class="muted tiny">After authorization, Plex will return you to Vetoarr.</p>
      </section>""", plex_auth_url=plex_auth_url)


@app.get('/auth/plex/callback')
def plex_callback():
    pin_id = session.get('plex_pin_id')
    started = session.get('plex_pin_started', 0)
    if (not pin_id or int(time.time()) - started > 600 or
        session.get('pin_browser_nonce') != session.get('browser_nonce') or
        not secrets.compare_digest(str(request.args.get('nonce', '')), str(session.get('pin_nonce', '')))):
        session.clear()
        abort(403)
    # Consume the PIN before contacting external services; no replay on failure.
    session.pop('plex_pin_id', None)
    session.pop('plex_pin_started', None)
    session.pop('pin_nonce', None)
    session.pop('pin_browser_nonce', None)
    try:
        result = plex_cloud('GET', f'/api/v2/pins/{int(pin_id)}')
        token = result.get('authToken')
        if not isinstance(token, str) or not (10 <= len(token) <= 4096):
            raise ValueError('Plex login not completed')
        identity = plex_identity(token)
        server_token = plex_server_token(token)
        if not server_token:
            raise ValueError('Plex user lacks access to this server')
        # Verify actual server permission before accepting access to browsing.
        trial = http.get(PLEX_URL + '/library/sections',
                         headers=plex_headers(server_token), timeout=(3, 12), allow_redirects=False)
        trial.raise_for_status()
        if trial.is_redirect or not isinstance(trial.json().get('MediaContainer'), dict):
            raise ValueError('No library access on selected Plex server')
    except (requests.RequestException, ValueError, KeyError, TypeError):
        flash('Plex authentication failed or this account does not have access to the server.')
        return redirect(url_for('login'))
    uid = identity['id']
    with conn() as c:
        existing = c.execute('SELECT session_epoch FROM plex_sessions WHERE plex_user_id=?', (uid,)).fetchone()
        epoch = existing['session_epoch'] if existing else 0
        c.execute("""INSERT INTO plex_sessions (plex_user_id,username,encrypted_token,encrypted_server_token,session_epoch,last_validated)
                     VALUES (?,?,?,?,?,?) ON CONFLICT(plex_user_id) DO UPDATE SET
                     username=excluded.username, encrypted_token=excluded.encrypted_token,
                     encrypted_server_token=excluded.encrypted_server_token,
                     last_validated=excluded.last_validated""",
                  (uid, identity['username'], fernet.encrypt(token.encode()), fernet.encrypt(server_token.encode()), epoch, int(time.time())))
        global_epoch = c.execute("SELECT value FROM portal_meta WHERE name='global_epoch'").fetchone()[0]
    session.clear()
    session.update(plex_uid=uid, user='plex:' + uid, username=identity['username'],
                   role='admin' if uid == plex_owner_id() else 'requester',
                   csrf=secrets.token_urlsafe(32), epoch=epoch,
                   global_epoch=global_epoch)
    session.permanent = True
    return redirect(url_for('index'))


@app.post('/logout')
@require_login
def logout():
    csrf_check()
    session.clear()
    return redirect(url_for('login'))


@app.post('/admin/revoke-sessions')
@require_login
def revoke_sessions():
    csrf_check()
    if session['role'] != 'admin':
        abort(403)
    with conn() as c:
        c.execute("UPDATE portal_meta SET value=value+1 WHERE name='global_epoch'")
        c.execute('DELETE FROM plex_sessions')
    session.clear()
    flash('All portal sessions revoked. Users must sign in to Plex again.')
    return redirect(url_for('login'))


def plex_libraries(*, user_scoped=True):
    """Only allow explicitly configured Plex libraries; reject duplicate names."""
    raw = plex_get('/library/sections', user_scoped=user_scoped).get('Directory', [])
    if not isinstance(raw, list):
        raise ValueError('Invalid Plex library list')
    result = []
    seen = set()
    for section in raw:
        if not isinstance(section, dict) or section.get('type') not in ('movie', 'show'):
            continue
        sid = str(section.get('key', ''))
        title = str(section.get('title', ''))
        library_type = section['type']
        key = (title, library_type)
        if key in LIBRARY_COLLECTIONS:
            if key in seen or not re.fullmatch(r'[0-9]{1,10}', sid):
                raise ValueError('Duplicate or invalid mapped Plex library')
            seen.add(key)
            result.append({'id': sid, 'title': title, 'type': library_type})
    return result


def collection_for_item(item, *, user_scoped=True):
    """Match an item to an allowed Plex library, never trust submitted section IDs."""
    matches = [library for library in plex_libraries(user_scoped=user_scoped)
               if library['id'] == str(item['section_id']) and library['type'] == item['type']]
    if len(matches) != 1:
        raise ValueError('Media does not belong to a configured Plex library')
    return LIBRARY_COLLECTIONS[(matches[0]['title'], matches[0]['type'])]


def normalize_items(raw, limit):
    if not isinstance(raw, list):
        raise ValueError('Invalid Plex media list')
    items = []
    for item in raw:
        if not isinstance(item, dict) or item.get('type') not in ('movie', 'show'):
            continue
        key = str(item.get('ratingKey', ''))
        if re.fullmatch(r'[0-9]{1,18}', key):
            items.append({'id': key, 'title': str(item.get('title', 'Untitled'))[:180],
                          'year': str(item.get('year', '')), 'type': item['type']})
        if len(items) >= limit:
            break
    return items


def browse_library(section_id, offset):
    if not re.fullmatch(r'[0-9]{1,10}', section_id) or not 0 <= offset <= 100000:
        raise ValueError('Invalid page or section')
    # Query parameters rather than Plex-specific headers are supported for paging.
    media = plex_get('/library/sections/' + section_id + '/all', {
        'X-Plex-Container-Start': offset,
        'X-Plex-Container-Size': BROWSE_PAGE_SIZE,
        'sort': 'titleSort:asc',
    }, user_scoped=True)
    items = normalize_items(media.get('Metadata', []), BROWSE_PAGE_SIZE)
    total = media.get('totalSize')
    if isinstance(total, int) and total >= 0:
        has_more = offset + BROWSE_PAGE_SIZE < total
    else:
        has_more = len(items) == BROWSE_PAGE_SIZE
    return items, has_more


def search_plex(term):
    # Plex's /search can respond with grouped results or no top-level Metadata.
    # Search each movie/show library instead, using Plex's documented title filter.
    results = []
    for section in plex_libraries():
        if len(results) >= 40:
            break
        media = plex_get('/library/sections/' + section['id'] + '/all', {
            'title': term,
            'X-Plex-Container-Start': 0,
            'X-Plex-Container-Size': 40,
        }, user_scoped=True)
        matches = normalize_items(media.get('Metadata', []), 40)
        # Client-side check prevents displaying unrelated results if a Plex
        # server/version ignores the title filter.
        results.extend(x for x in matches if term.casefold() in x['title'].casefold())
    return results[:40]


@app.get('/')
@require_login
def index():
    term = request.args.get('q', '').strip()[:MAX_SEARCH_LENGTH]
    selected_section = request.args.get('library', '').strip()
    try:
        offset = max(0, min(100000, int(request.args.get('offset', '0'))))
    except ValueError:
        abort(400)
    found, libraries, listed, has_more, error = [], [], [], False, None
    try:
        libraries = plex_libraries()
        if term:
            found = search_plex(term)
        if selected_section:
            chosen = next((x for x in libraries if x['id'] == selected_section), None)
            if chosen is None:
                abort(400)
            listed, has_more = browse_library(selected_section, offset)
            # Only display full movies/shows in matching section.
            listed = [x for x in listed if x['type'] == chosen['type']]
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        app.logger.warning('Plex search/browse failed: %s', type(exc).__name__)
        error = 'Plex library connection failed. Check Plex URL, token and JSON response in server logs.'
    with conn() as c:
        if session['role'] == 'admin':
            rows = c.execute('SELECT * FROM requests ORDER BY id DESC LIMIT 10').fetchall()
        else:
            rows = c.execute('SELECT * FROM requests WHERE requester=? ORDER BY id DESC LIMIT 10', (session['user'],)).fetchall()
    return page("""<section class="hero">{% if role=='admin' %}<span class="eyebrow">PLEX SERVER ADMINISTRATION</span><h1>Manage media requests.</h1><p>Review requests from people sharing your Plex server, or select titles to remove yourself. Your own requests are approved automatically and scheduled through Maintainerr.</p>{% else %}<span class="eyebrow">YOUR SHARED PLEX LIBRARY</span><h1>Request a cleanup.</h1><p>Find a movie or show you no longer need and send a removal request to the server owner. Track its status in My requests.</p>{% endif %}</section>
    <div class="layout"><main>
      <section class="panel"><div class="section-head"><h2>Find media</h2><span class="tag">Plex connected</span></div>
      <form method="get" class="fields"><input name="q" value="{{term}}" placeholder="Search movies or TV shows..." required maxlength="100"><button class="primary">Search</button></form>
      {% if error %}<p class="notice">{{error}}</p>{% endif %}
      {% if term and not found and not error %}<p class="empty">No matching titles. Try the library browser below.</p>{% endif %}
      {% if found %}<form method="post" action="{{url_for('review_bulk')}}"><input type="hidden" name="csrf" value="{{csrf}}">
      {% for m in found %}<label class="line"><input type="checkbox" name="plex_ids" value="{{m.id}}"><span><strong>{{m.title}}</strong><small>{{m.year}} · {{m.type|title}}</small></span></label>{% endfor %}
      <div class="batchbar"><small>Choose up to 20 titles</small><button class="primary">Request selected titles</button></div></form>{% endif %}</section>
      <section class="panel"><h2>Browse your library</h2><p class="muted">Choose a library, select titles, and {% if role=='admin' %}schedule their removal{% else %}send them to the server owner for approval{% endif %}.</p>
      {% for kind,label in [('movie','Movies'),('show','TV Shows')] %}<details {% if selected_type==kind %}open{% endif %}><summary>{{label}}</summary>
      <div>{% for library in libraries if library.type==kind %}<a class="library-link" href="{{url_for('index',library=library.id)}}">{{library.title}}</a>{% else %}<p class="empty">No matching library found.</p>{% endfor %}</div>
      {% if selected_type==kind and selected_section %}<form method="post" action="{{url_for('review_bulk')}}"><input type="hidden" name="csrf" value="{{csrf}}">
      {% for m in listed %}<label class="line"><input type="checkbox" name="plex_ids" value="{{m.id}}"><span><strong>{{m.title}}</strong><small>{{m.year}} · {{m.type|title}}</small></span></label>{% else %}<p class="empty">No items on this page.</p>{% endfor %}
      {% if listed %}<div class="batchbar"><small>Max 20 items per batch</small><button class="primary">Submit deletion requests</button></div>{% endif %}</form>
      <nav class="pager">{% if offset>0 %}<a href="{{url_for('index',library=selected_section,offset=[0,offset-page_size]|max)}}">← Previous</a>{% endif %}{% if has_more %}<a href="{{url_for('index',library=selected_section,offset=offset+page_size)}}">Next →</a>{% endif %}</nav>{% endif %}</details>{% endfor %}</section>
      {% if role=='admin' %}<section class="panel"><h3>Security</h3><p class="muted">Revoke all portal sessions to require fresh Plex sign-in.</p><form method="post" action="{{url_for('revoke_sessions')}}"><input type="hidden" name="csrf" value="{{csrf}}"><button class="danger">Revoke all sessions</button></form></section>{% endif %}
    </main><aside><section class="panel request-panel"><div class="section-head"><h2>{% if role=='admin' %}Recent requests{% else %}Your recent requests{% endif %}</h2><a href="{% if role=='admin' %}{{url_for('all_requests')}}{% else %}{{url_for('my_requests')}}{% endif %}">{% if role=='admin' %}All requests{% else %}Full history{% endif %}</a></div><div class="request-list">
    {% for r in rows %}<div class="line"><div style="min-width:0;flex:1"><div class="request-title">{{r['title']}}</div><div class="request-meta">#{{r['id']}} · {{r['requester']}} · {{r['created_at']}} UTC<br><span class="tag {{r['status']}}">{{r['status']}}</span></div>{% if r['error'] %}<small>{{r['error']}}</small>{% endif %}</div>
    {% if role=='admin' and r['status']=='pending' %}<form method="post" action="{{url_for('decide',req_id=r['id'])}}"><input type="hidden" name="csrf" value="{{csrf}}"><button class="primary" name="decision" value="approve">Approve</button><button class="danger" name="decision" value="reject">Reject</button></form>{% endif %}
    {% if role=='admin' and r['status']=='review' %}<form method="post" action="{{url_for('reconcile',req_id=r['id'])}}"><input type="hidden" name="csrf" value="{{csrf}}"><button>Reconcile</button></form>{% endif %}
    </div>{% else %}<p class="empty">No deletion requests yet.</p>{% endfor %}</div></section>
    </aside></div>""", term=term, found=found, rows=rows, role=session['role'], libraries=libraries,
                selected_section=selected_section, selected_type=next((x['type'] for x in libraries if x['id']==selected_section), None),
                listed=listed, has_more=has_more, offset=offset, page_size=BROWSE_PAGE_SIZE, error=error)



@app.get('/admin/requests')
@require_login
def all_requests():
    if session.get('role') != 'admin':
        abort(403)
    try:
        page_num = int(request.args.get('page', '1'))
    except ValueError:
        abort(400)
    if not 1 <= page_num <= 10000:
        abort(400)
    per_page = 25
    with conn() as c:
        total = c.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
        rows = c.execute('SELECT id,title,requester,media_type,status,created_at,decided_at,error FROM requests ORDER BY id DESC LIMIT ? OFFSET ?',
                         (per_page, (page_num-1)*per_page)).fetchall()
    return page("""<section class="hero"><span class="eyebrow">ADMINISTRATOR</span><h1>All requests</h1><p>Review all submitted titles, approve pending requests, and handle items that need reconciliation. Approved means Maintainerr accepted the request, not that files have been deleted.</p></section>
    <section class="panel"><div class="section-head"><h2>Request history</h2><span class="tag">{{total}} total</span></div>
    {% for r in rows %}<div class="line"><div style="min-width:0;flex:1"><div class="request-title">{{r['title']}}</div><div class="request-meta">#{{r['id']}} · {{r['requester']}} · {{r['media_type']|title}} · {{r['created_at']}} UTC<br><span class="tag {{r['status']}}">{{r['status']}}</span></div>{% if r['error'] %}<small>{{r['error']}}</small>{% endif %}</div>
    {% if r['status']=='pending' %}<form method="post" action="{{url_for('decide',req_id=r['id'])}}"><input type="hidden" name="csrf" value="{{csrf}}"><button class="primary" name="decision" value="approve">Approve</button><button class="danger" name="decision" value="reject">Reject</button></form>{% endif %}
    {% if r['status']=='review' %}<form method="post" action="{{url_for('reconcile',req_id=r['id'])}}"><input type="hidden" name="csrf" value="{{csrf}}"><button>Reconcile</button></form>{% endif %}
    </div>{% else %}<p class="empty">No requests yet.</p>{% endfor %}
    <nav class="pager">{% if page_num > 1 %}<a href="{{url_for('all_requests',page=page_num-1)}}">← Previous</a>{% endif %}{% if page_num * per_page < total %}<a href="{{url_for('all_requests',page=page_num+1)}}">Next →</a>{% endif %}</nav></section>""", rows=rows, page_num=page_num, per_page=per_page, total=total)


@app.get('/my-requests')
@require_login
def my_requests():
    try:
        page_num = int(request.args.get('page', '1'))
    except ValueError:
        abort(400)
    if not 1 <= page_num <= 10000:
        abort(400)
    per_page = 25
    with conn() as c:
        total = c.execute('SELECT COUNT(*) FROM requests WHERE requester=?', (session['user'],)).fetchone()[0]
        rows = c.execute('SELECT id,title,media_type,status,created_at,decided_at,error FROM requests WHERE requester=? ORDER BY id DESC LIMIT ? OFFSET ?', (session['user'], per_page, (page_num-1)*per_page)).fetchall()
    return page("""<section class="hero"><span class="eyebrow">YOUR REQUEST HISTORY</span><h1>My requests</h1><p>Track your own deletion requests and whether they are pending, approved, rejected, or require manual review. Approval schedules deletion; it does not prove the files were deleted.</p></section>
    <section class="panel"><div class="section-head"><h2>Submitted titles</h2><span class="tag">{{total}} total</span></div>
    {% for r in rows %}<div class="line"><div><div class="request-title">{{r['title']}}</div><div class="request-meta">#{{r['id']}} · {{r['media_type']|title}} · Submitted {{r['created_at']}} UTC · <span class="tag {{r['status']}}">{{r['status']}}</span></div>{% if r['error'] %}<small>{{r['error']}}</small>{% endif %}</div></div>{% else %}<p class="empty">No requests submitted yet.</p>{% endfor %}
    <nav class="pager">{% if page_num > 1 %}<a href="{{url_for('my_requests',page=page_num-1)}}">← Previous</a>{% endif %}{% if page_num * per_page < total %}<a href="{{url_for('my_requests',page=page_num+1)}}">Next →</a>{% endif %}</nav></section>""", rows=rows, page_num=page_num, per_page=per_page, total=total)


@app.post('/request/bulk/review')
@require_login
def review_bulk():
    csrf_check()
    ids = request.form.getlist('plex_ids')
    if not ids or len(ids) > MAX_BULK_ITEMS or len(ids) != len(set(ids)):
        abort(400)
    if any(not re.fullmatch(r'[0-9]{1,18}', item) for item in ids):
        abort(400)
    try:
        items = [plex_item(item) for item in ids]
        for item in items:
            collection_for_item(item)
    except (requests.RequestException, ValueError, KeyError, TypeError):
        flash('Unable to verify the selected Plex items.')
        return redirect(url_for('index'))
    return page("""<section class="hero"><span class="eyebrow">REVIEW YOUR REQUESTS</span><h1>Ready to submit?</h1><p>These titles will be submitted. Shared users require owner approval. If you are the server owner, submitting immediately starts the Maintainerr deletion schedule.</p></section>
        <section class="panel"><form method="post" action="{{url_for('submit_bulk')}}"><input type="hidden" name="csrf" value="{{csrf}}">
        {% for m in items %}<div class="line"><span><strong>{{m.title}}</strong><small>{{m.type|title}}</small></span><input type="hidden" name="plex_ids" value="{{m.id}}"></div>{% endfor %}
        <div class="batchbar"><a href="{{url_for('index')}}">Cancel</a><button class="primary big">Submit {{items|length}} deletion request(s)</button></div></form></section>""", items=items)


@app.post('/request/bulk')
@require_login
def submit_bulk():
    csrf_check()
    ids = request.form.getlist('plex_ids')
    if not ids or len(ids) > MAX_BULK_ITEMS or len(set(ids)) != len(ids):
        abort(400)
    if any(not re.fullmatch(r'[0-9]{1,18}', item) for item in ids):
        abort(400)
    try:
        # Validate every item before creating any requests. This performs GETs
        # against Plex, never POSTs to Plex or Maintainerr.
        items = [plex_item(item) for item in ids]
        for item in items:
            collection_for_item(item)
    except (requests.RequestException, ValueError, KeyError, TypeError):
        flash('Could not validate all selected Plex items; no requests created')
        return redirect(url_for('index'))
    created = 0
    created_ids = []
    with conn() as c:
        c.execute('BEGIN IMMEDIATE')
        count = c.execute("SELECT count(*) FROM requests WHERE requester=? AND status IN ('pending','processing','review')", (session['user'],)).fetchone()[0]
        if count + len(items) > 20:
            abort(429)
        for item in items:
            existing = c.execute("SELECT 1 FROM requests WHERE plex_id=? AND status IN ('pending','processing','approved','review')", (item['id'],)).fetchone()
            if not existing:
                try:
                    c.execute('INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)',
                              (session['user'], item['id'], item['type'], item['title']))
                    created += 1
                    created_ids.append(c.execute('SELECT last_insert_rowid()').fetchone()[0])
                except sqlite3.IntegrityError:
                    # Another writer has already created an active request.
                    continue
    if session['role'] == 'admin':
        outcomes = [process_approval(req_id, session['user']) for req_id in created_ids]
        flash(f'{created} request(s) recorded; {outcomes.count("approved")} approved, {outcomes.count("pending")} pending, {outcomes.count("review")} need review. Verify Maintainerr before retrying any review item.')
    else:
        flash(f'{created} removal request(s) submitted for administrator approval; nothing deleted')
    return redirect(url_for('index'))


@app.post('/request')
@require_login
def submit_request():
    csrf_check()
    media_id = request.form.get('plex_id', '')
    try:
        item = plex_item(media_id)
        collection_for_item(item)
    except (requests.RequestException, ValueError, KeyError, TypeError):
        flash('Unable to verify that item in Plex')
        return redirect(url_for('index'))
    new_id = None
    with conn() as c:
        c.execute('BEGIN IMMEDIATE')
        # Rate-limit portal requests and cap the per-user outstanding count.
        count = c.execute("SELECT count(*) FROM requests WHERE requester=? AND status IN ('pending','processing','review')", (session['user'],)).fetchone()[0]
        if count >= 20:
            abort(429)
        existing = c.execute("SELECT 1 FROM requests WHERE plex_id=? AND status IN ('pending','processing','approved','review')", (item['id'],)).fetchone()
        if existing:
            flash('This item already has an active or previously approved request')
        else:
            try:
                c.execute('INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)', (session['user'], item['id'], item['type'], item['title']))
                new_id = c.execute('SELECT last_insert_rowid()').fetchone()[0]
            except sqlite3.IntegrityError:
                flash('This item already has an active or previously approved request')
    if new_id is not None:
        if session['role'] == 'admin':
            outcome = process_approval(new_id, session['user'])
            flash('Owner request: ' + ('approved and Maintainerr membership confirmed' if outcome == 'approved' else 'not completed; check status before any retry'))
        else:
            flash('Request submitted for administrator approval')
    return redirect(url_for('index'))


def process_approval(req_id, actor):
    """Shared, one-shot approval engine; caller must have verified owner role.

    DB is claimed and committed before external calls. An ambiguous POST
    produces review rather than a retry.
    """
    with conn() as c:
        c.execute('BEGIN IMMEDIATE')
        row = c.execute('SELECT * FROM requests WHERE id=?', (req_id,)).fetchone()
        if row is None or row['status'] != 'pending':
            abort(409)
        # Claim once, commit, then call upstream APIs *without* holding a DB transaction.
        c.execute("UPDATE requests SET status='processing',decided_at=CURRENT_TIMESTAMP,decided_by=?,error=NULL WHERE id=?", (actor, req_id))
    call_attempted = False
    try:
        current = plex_item(row['plex_id'], user_scoped=False)
        if current['type'] != row['media_type'] or current['title'] != row['title']:
            raise ValueError('Plex item no longer matches the original request')
        collection_id = collection_for_item(current, user_scoped=False)
        check_collection(collection_id, row['media_type'], current['section_id'])
        if has_membership(collection_id, row['plex_id']):
            raise ValueError('Item already belongs to the deletion collection; inspect manually')
        # API may perform the action even when the response is lost; never blindly retry.
        call_attempted = True
        payload = {'action': 0, 'mediaId': row['plex_id'], 'collectionId': collection_id,
                   'context': {'id': row['plex_id'], 'type': row['media_type']}}
        service_json('POST', MAINTAINERR_URL + '/api/collections/media/add', json=payload)
        if not has_membership(collection_id, row['plex_id']):
            raise ValueError('Maintainerr did not confirm membership')
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        app.logger.warning('Approval %d needs review: %s', req_id, type(exc).__name__)
        with conn() as c:
            c.execute('UPDATE requests SET status=?, error=? WHERE id=? AND status=\'processing\'',
                      ('review' if call_attempted else 'pending',
                       'Check Maintainerr membership before any retry' if call_attempted else 'Preflight validation failed; check Plex and Maintainerr settings', req_id))
        return 'review' if call_attempted else 'pending'
    with conn() as c:
        c.execute("UPDATE requests SET status='approved',error=NULL WHERE id=? AND status='processing'", (req_id,))
    return 'approved'




@app.post('/decide/<int:req_id>')
@require_login
def decide(req_id):
    csrf_check()
    if session['role'] != 'admin':
        abort(403)
    decision = request.form.get('decision')
    if decision not in ('approve', 'reject'):
        abort(400)
    if decision == 'reject':
        with conn() as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT status FROM requests WHERE id=?', (req_id,)).fetchone()
            if row is None or row['status'] != 'pending':
                abort(409)
            c.execute("UPDATE requests SET status='rejected',decided_at=CURRENT_TIMESTAMP,decided_by=? WHERE id=?", (session['user'], req_id))
        flash('Request rejected')
    else:
        outcome = process_approval(req_id, session['user'])
        flash('Approved; Maintainerr membership confirmed. Deletion follows its configured delay.' if outcome == 'approved' else 'Approval incomplete. Check status and Maintainerr before retrying.')
    return redirect(url_for('index'))


@app.post('/admin/reconcile/<int:req_id>')
@require_login
def reconcile(req_id):
    csrf_check()
    if session['role'] != 'admin':
        abort(403)
    with conn() as c:
        row = c.execute('SELECT * FROM requests WHERE id=?', (req_id,)).fetchone()
    if not row or row['status'] != 'review' or row['media_type'] not in ('movie', 'show'):
        abort(409)
    try:
        current = plex_item(row['plex_id'], user_scoped=False)
        if current['type'] != row['media_type'] or current['title'] != row['title']:
            raise ValueError('Plex item no longer matches original request')
        collection_id = collection_for_item(current, user_scoped=False)
        present = has_membership(collection_id, row['plex_id'])
    except (requests.RequestException, ValueError, TypeError):
        flash('Could not verify membership. Request remains under review.')
        return redirect(url_for('index'))
    if present:
        with conn() as c:
            c.execute("""UPDATE requests SET status='approved',error=NULL
                       WHERE id=? AND status='review'""", (req_id,))
        flash('Membership found. Approval recorded; verify Maintainerr deletion schedule.')
    else:
        # Absence does not prove that a previous POST was never processed.
        flash('Not present in collection. No automatic retry: inspect Maintainerr logs before any new request.')
    return redirect(url_for('index'))


@app.get('/health')
def health():
    return {'status': 'ok'}


if __name__ == '__main__':
    raise RuntimeError('Use gunicorn, not the Flask development server')
