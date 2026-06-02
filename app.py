import hmac
import hashlib
import datetime
import os
from functools import wraps

import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret-mude')

ABSOLUTE_TOKEN_ID = os.environ.get('ABSOLUTE_TOKEN_ID', '')
ABSOLUTE_SECRET   = os.environ.get('ABSOLUTE_SECRET', '')
ABSOLUTE_HOST     = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')

USERS = {
    'admin': {
        'password':     os.environ.get('ADMIN_PASSWORD', 'admin123'),
        'name':         'Administrador',
        'group_filter': None,
        'is_admin':     True,
    }
}

# ── URL encode específico do Absolute (do módulo oficial) ──────
def _url_encode(value):
    value = value.replace('$', '%24')
    value = value.replace(' ', '%20')
    value = value.replace("'", '%27')
    value = value.replace('(', '%28')
    value = value.replace(')', '%29')
    value = value.replace(',', '%2C')
    value = value.replace(':', '%3A')
    return value

# ── Requisição assinada ao Absolute (implementação oficial) ────
def absolute_request(path, query='', method='GET', body=''):
    content_type = 'application/json;charset=utf-8'
    date = datetime.datetime.utcnow()
    date_yyyymmdd = date.strftime('%Y%m%d')
    x_abs_date    = date_yyyymmdd + 'T' + date.strftime('%H%M%S') + 'Z'

    # Canonical request — ORDEM: host, content-type, x-abs-date
    canonical = (
        method.upper() + '\n' +
        path + '\n' +
        _url_encode(query) + '\n' +
        'host:' + ABSOLUTE_HOST + '\n' +
        'content-type:' + content_type + '\n' +
        'x-abs-date:' + x_abs_date + '\n' +
        hashlib.sha256(body.encode('utf-8')).hexdigest()
    )

    req_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    if ABSOLUTE_HOST == 'api.us.absolute.com':
        scope = date_yyyymmdd + '/usdc/abs1'
    elif ABSOLUTE_HOST == 'api.eu.absolute.com':
        scope = date_yyyymmdd + '/eudc/abs1'
    else:
        scope = date_yyyymmdd + '/cadc/abs1'

    string_to_sign = 'ABS1-HMAC-SHA-256\n' + x_abs_date + '\n' + scope + '\n' + req_hash

    ksecret    = ('ABS1' + ABSOLUTE_SECRET).encode('utf-8')
    kdate      = hmac.new(ksecret, date_yyyymmdd.encode('utf-8'), hashlib.sha256).digest()
    signingkey = hmac.new(kdate, 'abs1_request'.encode('utf-8'), hashlib.sha256).digest()
    signature  = hmac.new(signingkey, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    credentials = ABSOLUTE_TOKEN_ID + '/' + scope
    headers = {
        'host':          ABSOLUTE_HOST,
        'Content-Type':  content_type,
        'x-abs-date':    x_abs_date,
        'Authorization': 'ABS1-HMAC-SHA-256 Credential=' + credentials +
                         ', SignedHeaders=host;content-type;x-abs-date, Signature=' + signature,
    }

    url = 'https://' + ABSOLUTE_HOST + path
    if query:
        url += '?' + _url_encode(query)

    print(f'[Absolute] GET {url}')
    if method.upper() == 'GET':
        resp = requests.get(url, headers=headers, timeout=20)
    elif method.upper() == 'POST':
        resp = requests.post(url, data=body, headers=headers, timeout=20)
    else:
        resp = requests.put(url, data=body, headers=headers, timeout=20)

    print(f'[Absolute] Status {resp.status_code}')
    return resp

# ── Buscar dispositivos (usa v2/reporting/devices) ─────────────
def fetch_devices(group_filter=None):
    select = ('$select=esn,lastConnectedUtc,domain,username,systemName,serial,'
              'systemModel,systemManufacturer,os,localIp,publicIp')
    filter_ = "$filter=agentStatus eq 'A'"
    if group_filter:
        filter_ += f" and groupName eq '{group_filter}'"
    query = filter_ + '&' + select + '&$top=300'

    resp = absolute_request('/v2/reporting/devices', query, 'GET', '')
    if not resp.ok:
        return None, f'API {resp.status_code}: {resp.text[:200]}'
    return resp.json(), None

# ── Auth ───────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def dec(*a, **k):
        if 'user' not in session:
            return jsonify({'error': 'Não autenticado'}), 401
        return f(*a, **k)
    return dec

@app.post('/api/login')
def api_login():
    data = request.get_json()
    user = USERS.get(data.get('username', '').strip())
    if not user or user['password'] != data.get('password', ''):
        return jsonify({'error': 'Usuário ou senha inválidos'}), 401
    session['user'] = {'name': user['name'], 'isAdmin': user['is_admin'],
                       'group_filter': user['group_filter']}
    return jsonify({'success': True, 'name': user['name'], 'isAdmin': user['is_admin']})

@app.post('/api/logout')
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.get('/api/me')
def api_me():
    if 'user' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    return jsonify(session['user'])

@app.get('/api/devices')
@login_required
def api_devices():
    u = session['user']
    group = request.args.get('group') if u['isAdmin'] else u['group_filter']
    devices, err = fetch_devices(group)
    if err:
        return jsonify({'error': err}), 500
    return jsonify({'devices': devices})

@app.get('/diag')
def diag():
    resp = absolute_request('/v2/reporting/devices', "$filter=agentStatus eq 'A'&$top=3", 'GET', '')
    return jsonify({'status': resp.status_code, 'body': resp.text[:500]})

@app.get('/', defaults={'path': ''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public', 'index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
