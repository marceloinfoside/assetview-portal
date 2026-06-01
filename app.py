import hmac, hashlib, base64, datetime, os
import requests as req
from flask import Flask, jsonify, session, request, send_from_directory
from functools import wraps

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN_ID   = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET_KEY = os.environ.get('ABSOLUTE_SECRET', '')
HOST       = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')

USERS = {
    'admin': {
        'password':     os.environ.get('ADMIN_PASSWORD', 'admin123'),
        'name':         'Administrador',
        'group_filter': None,
        'is_admin':     True,
    }
}

# ── Diagnóstico: testa todas as combinações ────────────────────
@app.get('/diag')
def diag():
    dt         = datetime.datetime.now(datetime.timezone.utc)
    now        = dt.strftime('%Y%m%dT%H%M%SZ')
    date_short = dt.strftime('%Y%m%d')
    path       = '/v3/devices'
    qs         = '%24top=3'
    empty_hash = hashlib.sha256(b'').hexdigest()
    secret_bytes = base64.b64decode(SECRET_KEY)

    results = {}

    headers_variants = {
        'ct_host_date': f'content-type:application/json\nhost:{HOST}\nx-abs-date:{now}\n',
        'host_ct_date': f'host:{HOST}\ncontent-type:application/json\nx-abs-date:{now}\n',
    }
    cr_variants = {}
    for hname, ch in headers_variants.items():
        cr_variants[f'{hname}_no_nl']  = f'GET\n{path}\n{qs}\n{ch}{empty_hash}'
        cr_variants[f'{hname}_yes_nl'] = f'GET\n{path}\n{qs}\n{ch}\n{empty_hash}'

    key_variants = {
        'ABS1_b64str': ('ABS1' + SECRET_KEY).encode('utf-8'),
        'ABS1_bytes':  b'ABS1' + secret_bytes,
        'bytes_only':  secret_bytes,
    }

    scope_variants = [
        f'{date_short}/cadc/abs1',
        f'{date_short}/usdc/abs1',
        date_short,
    ]

    for cr_name, canonical_request in cr_variants.items():
        cr_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
        for scope in scope_variants:
            ss = f'ABS1-HMAC-SHA-256\n{now}\n{scope}\n{cr_hash}'
            for kname, k in key_variants.items():
                kd  = hmac.new(k,  date_short.encode(), hashlib.sha256).digest()
                ks  = hmac.new(kd, b'abs1_request',     hashlib.sha256).digest()
                sig = hmac.new(ks, ss.encode(),          hashlib.sha256).hexdigest()
                auth = (f'ABS1-HMAC-SHA-256 Credential={TOKEN_ID}/{scope}, '
                        f'SignedHeaders=host;content-type;x-abs-date, Signature={sig}')
                key = f'{cr_name}|{scope}|{kname}'
                # Header order matters — use the same order as canonical
                if 'ct_host' in cr_name:
                    hdrs = {'Content-Type':'application/json','Host':HOST,'x-abs-date':now,'Authorization':auth}
                else:
                    hdrs = {'Host':HOST,'Content-Type':'application/json','x-abs-date':now,'Authorization':auth}
                try:
                    r = req.get(f'https://{HOST}{path}?{qs}', headers=hdrs, timeout=8)
                    results[key] = r.status_code
                    if r.status_code == 200:
                        results['__WINNER__'] = key
                except Exception as e:
                    results[key] = str(e)[:50]

    return jsonify(results)

# ── Auth ───────────────────────────────────────────────────────
@app.post('/api/login')
def api_login():
    data = request.get_json()
    user = USERS.get(data.get('username',''))
    if not user or user['password'] != data.get('password',''):
        return jsonify({'error': 'Inválido'}), 401
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
def api_devices():
    if 'user' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    return jsonify({'devices': [], 'error': 'Use /diag para diagnosticar'})

@app.get('/', defaults={'path': ''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public', 'index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)

