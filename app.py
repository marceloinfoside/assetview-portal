import hmac
import hashlib
import datetime
import os
import json
from functools import wraps

import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret-mude-em-producao')

# ── Configurações Absolute ─────────────────────────────────────
ABSOLUTE_TOKEN_ID = os.environ.get('ABSOLUTE_TOKEN_ID', '')
ABSOLUTE_SECRET   = os.environ.get('ABSOLUTE_SECRET', '')
ABSOLUTE_HOST     = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')
ABSOLUTE_REGION   = os.environ.get('ABSOLUTE_REGION', 'cadc')

# ── Usuários ───────────────────────────────────────────────────
# Adicione clientes aqui. group_filter = nome do grupo no Absolute (None = todos)
USERS = {
    'admin': {
        'password': os.environ.get('ADMIN_PASSWORD', 'admin123'),
        'name': 'Administrador',
        'group_filter': None,
        'is_admin': True,
    }
}

# ── Assinatura HMAC Absolute ───────────────────────────────────
def build_absolute_headers(method, path, query_string=''):
    dt  = datetime.datetime.now(datetime.timezone.utc)
    now        = dt.strftime('%Y%m%dT%H%M%SZ')
    date_short = dt.strftime('%Y%m%d')

    # 1. Canonical request
    empty_hash = hashlib.sha256(b'').hexdigest()
    canonical_headers = (
        f'content-type:application/json\n'
        f'host:{ABSOLUTE_HOST}\n'
        f'x-abs-date:{now}\n'
    )
    canonical_request = '\n'.join([method, path, query_string, canonical_headers, empty_hash])

    # 2. Signing string  — CredentialScope = date/region/abs1
    cr_hash          = hashlib.sha256(canonical_request.encode()).hexdigest()
    credential_scope = f'{date_short}/{ABSOLUTE_REGION}/abs1'
    signing_string   = f'ABS1-HMAC-SHA-256\n{now}\n{credential_scope}\n{cr_hash}'

    # 3. Signing key — kSecret = UTF8("ABS1" + secret_string)
    k_secret  = ('ABS1' + ABSOLUTE_SECRET).encode('utf-8')
    k_date    = hmac.new(k_secret,  date_short.encode(),  hashlib.sha256).digest()
    k_signing = hmac.new(k_date,    b'abs1_request',      hashlib.sha256).digest()
    signature = hmac.new(k_signing, signing_string.encode(), hashlib.sha256).hexdigest()

    # 4. Authorization header
    auth = (
        f'ABS1-HMAC-SHA-256 '
        f'Credential={ABSOLUTE_TOKEN_ID}/{credential_scope}, '
        f'SignedHeaders=host;content-type;x-abs-date, '
        f'Signature={signature}'
    )

    return {
        'Content-Type':  'application/json',
        'Host':          ABSOLUTE_HOST,
        'x-abs-date':    now,
        'Authorization': auth,
    }

# ── Buscar dispositivos ────────────────────────────────────────
def fetch_devices(group_filter=None):
    params = {
        '$top':    '200',
        '$select': 'id,esn,systemName,username,systemModel,serial,osName,osVersion,'
                   'lastConnectedUtc,geoData,systemDiskInfo,memoryInfo,cpuInfo,groupName,agentStatus',
    }
    if group_filter:
        params['$filter'] = f"groupName eq '{group_filter}'"

    # Ordenar e encodar query string conforme spec Absolute
    from urllib.parse import quote
    qs = '&'.join(
        f"{quote(k, safe='')}={quote(v, safe='')}"
        for k, v in sorted(params.items())
    )

    headers = build_absolute_headers('GET', '/v3/devices', qs)
    url = f'https://{ABSOLUTE_HOST}/v3/devices?{qs}'

    print(f'[Absolute] GET {url}')
    resp = requests.get(url, headers=headers, timeout=15)
    print(f'[Absolute] Status: {resp.status_code}')

    if not resp.ok:
        print(f'[Absolute] Error body: {resp.text[:300]}')
        return None, f'API error {resp.status_code}: {resp.text[:200]}'

    data = resp.json()
    devices = data if isinstance(data, list) else data.get('value', data)
    return devices, None

# ── Auth decorator ─────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Não autenticado'}), 401
        return f(*args, **kwargs)
    return decorated

# ── Rotas API ──────────────────────────────────────────────────
@app.post('/api/login')
def api_login():
    data     = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    user     = USERS.get(username)
    if not user or user['password'] != password:
        return jsonify({'error': 'Usuário ou senha inválidos'}), 401
    session['user'] = {
        'username':     username,
        'name':         user['name'],
        'group_filter': user['group_filter'],
        'is_admin':     user['is_admin'],
    }
    return jsonify({'success': True, 'name': user['name'], 'isAdmin': user['is_admin']})

@app.post('/api/logout')
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.get('/api/me')
def api_me():
    if 'user' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    u = session['user']
    return jsonify({'name': u['name'], 'isAdmin': u['is_admin']})

@app.get('/api/devices')
@login_required
def api_devices():
    u      = session['user']
    group  = request.args.get('group') if u['is_admin'] else u['group_filter']
    devices, err = fetch_devices(group)
    if err:
        return jsonify({'error': err}), 500
    return jsonify({'devices': devices})

# ── Frontend ───────────────────────────────────────────────────
@app.get('/', defaults={'path': ''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public', 'index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
