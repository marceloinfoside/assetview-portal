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
    dt         = datetime.datetime.now(datetime.timezone.utc)
    now        = dt.strftime('%Y%m%dT%H%M%SZ')
    date_short = dt.strftime('%Y%m%d')
    path       = '/v3/devices'
    qs         = '%24top=3'
    empty_hash = hashlib.sha256(b'').hexdigest()
    secret_bytes = base64.b64decode(SECRET_KEY)

    # Uma única tentativa com log completo
    ch = f'content-type:application/json\nhost:{HOST}\nx-abs-date:{now}\n'
    canonical_request = f'GET\n{path}\n{qs}\n{ch}{empty_hash}'
    cr_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
    scope = f'{date_short}/cadc/abs1'
    ss = f'ABS1-HMAC-SHA-256\n{now}\n{scope}\n{cr_hash}'
    k  = ('ABS1' + SECRET_KEY).encode('utf-8')
    kd = hmac.new(k,  date_short.encode(), hashlib.sha256).digest()
    ks = hmac.new(kd, b'abs1_request',     hashlib.sha256).digest()
    sig = hmac.new(ks, ss.encode(),         hashlib.sha256).hexdigest()
    auth = (f'ABS1-HMAC-SHA-256 Credential={TOKEN_ID}/{scope}, '
            f'SignedHeaders=host;content-type;x-abs-date, Signature={sig}')

    hdrs = {'Content-Type':'application/json','Host':HOST,'x-abs-date':now,'Authorization':auth}

    try:
        r = req.get(f'https://{HOST}{path}?{qs}', headers=hdrs, timeout=10)
        return jsonify({
            'status': r.status_code,
            'response_body': r.text,
            'response_headers': dict(r.headers),
            'request_url': f'https://{HOST}{path}?{qs}',
            'canonical_request': canonical_request,
            'signing_string': ss,
            'auth_header': auth,
            'token_id_used': TOKEN_ID,
            'secret_first_10': SECRET_KEY[:10],
        })
    except Exception as e:
        return jsonify({'error': str(e)})

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
