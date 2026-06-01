import hmac, hashlib, base64, datetime, os
import requests as req
from flask import Flask, jsonify, session, request, send_from_directory

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

@app.get('/diag')
def diag():
    results = {}
    path = '/v3/devices'
    qs   = '%24top=3'
    url  = f'https://{HOST}{path}?{qs}'

    dt         = datetime.datetime.now(datetime.timezone.utc)
    now        = dt.strftime('%Y%m%dT%H%M%SZ')
    date_short = dt.strftime('%Y%m%d')
    empty_hash = hashlib.sha256(b'').hexdigest()
    secret_bytes = base64.b64decode(SECRET_KEY)

    def try_auth(label, auth_header, extra_headers=None):
        hdrs = {
            'Content-Type': 'application/json',
            'Host': HOST,
            'x-abs-date': now,
            'Authorization': auth_header,
        }
        if extra_headers:
            hdrs.update(extra_headers)
        try:
            r = req.get(url, headers=hdrs, timeout=8)
            results[label] = {'status': r.status_code, 'body': r.text[:100]}
        except Exception as e:
            results[label] = {'error': str(e)}

    ch = f'content-type:application/json\nhost:{HOST}\nx-abs-date:{now}\n'
    cr = f'GET\n{path}\n{qs}\n{ch}{empty_hash}'
    cr_hash = hashlib.sha256(cr.encode()).hexdigest()

    # Testar com TokenId= vs Credential=
    for region in ['cadc', 'usdc']:
        scope = f'{date_short}/{region}/abs1'
        ss    = f'ABS1-HMAC-SHA-256\n{now}\n{scope}\n{cr_hash}'

        for kname, k in [
            ('ABS1_b64str', ('ABS1' + SECRET_KEY).encode()),
            ('ABS1_bytes',  b'ABS1' + secret_bytes),
        ]:
            kd  = hmac.new(k,  date_short.encode(), hashlib.sha256).digest()
            ks  = hmac.new(kd, b'abs1_request',     hashlib.sha256).digest()
            sig = hmac.new(ks, ss.encode(),          hashlib.sha256).hexdigest()

            # Formato 1: Credential= (atual)
            auth1 = (f'ABS1-HMAC-SHA-256 Credential={TOKEN_ID}/{scope}, '
                     f'SignedHeaders=host;content-type;x-abs-date, Signature={sig}')
            try_auth(f'Credential_{region}_{kname}', auth1)

            # Formato 2: TokenId= (formato antigo da doc)
            auth2 = f'ABS1-HMAC-SHA-256 TokenId={TOKEN_ID},Signature={sig}'
            try_auth(f'TokenId_{region}_{kname}', auth2)

    results['outbound_ip'] = req.get('https://api.ipify.org?format=json', timeout=5).json().get('ip')
    return jsonify(results)

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
    return jsonify({'devices': []})

@app.get('/', defaults={'path': ''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public', 'index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
