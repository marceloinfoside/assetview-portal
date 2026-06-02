import hmac, hashlib, json, time, base64, os
import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def make_jws(method, path, query, host, secret_mode):
    issued_at = int(time.time() * 1000)
    jose = {
        "alg": "HS256",
        "kid": TOKEN,
        "method": method,
        "content-type": "application/json",
        "uri": path,
        "query-string": query,
        "issuedAt": issued_at
    }
    eh = b64url(jose)
    ep = b64url({})
    si = f"{eh}.{ep}"
    key = SECRET.encode('utf-8') if secret_mode == 'string' else base64.b64decode(SECRET)
    sig = hmac.new(key, si.encode('utf-8'), hashlib.sha256).digest()
    return f"{eh}.{ep}.{b64url(sig)}", issued_at

@app.get('/diag')
def diag():
    out = {}
    path, q = '/v3/devices', '$top=3'

    # TESTE A: Validar JWS no endpoint dedicado (US e CADC)
    for host in ['api.us.absolute.com', 'api.absolute.com']:
        for sm in ['string', 'base64']:
            jws, _ = make_jws('GET', path, q, host, sm)
            try:
                r = requests.post(f'https://{host}/jws/validate',
                                  data=jws,
                                  headers={'Content-Type': 'text/plain'},
                                  timeout=10)
                out[f'validate_{host}_{sm}'] = {'status': r.status_code, 'body': r.text[:200]}
            except Exception as e:
                out[f'validate_{host}_{sm}'] = {'error': str(e)[:100]}

    # TESTE B: Chamar /v3/devices no host US
    for host in ['api.us.absolute.com', 'api.absolute.com']:
        for sm in ['string', 'base64']:
            jws, _ = make_jws('GET', path, q, host, sm)
            try:
                r = requests.get(f'https://{host}{path}?{q}',
                                 headers={'Authorization': jws, 'Content-Type': 'application/json'},
                                 timeout=10)
                out[f'devices_{host}_{sm}'] = {'status': r.status_code, 'body': r.text[:100]}
            except Exception as e:
                out[f'devices_{host}_{sm}'] = {'error': str(e)[:100]}

    return jsonify(out)

@app.post('/api/login')
def login():
    d = request.get_json()
    u = USERS.get(d.get('username','').strip())
    if not u or u['password'] != d.get('password',''):
        return jsonify({'error':'Inválido'}), 401
    session['user'] = {'name':u['name'],'isAdmin':u['is_admin'],'group_filter':u['group_filter']}
    return jsonify({'success':True,'name':u['name'],'isAdmin':u['is_admin']})

@app.post('/api/logout')
def logout():
    session.clear(); return jsonify({'success':True})

@app.get('/api/me')
def me():
    if 'user' not in session: return jsonify({'error':'Não autenticado'}), 401
    return jsonify(session['user'])

@app.get('/api/devices')
def devices():
    if 'user' not in session: return jsonify({'error':'Não autenticado'}), 401
    return jsonify({'devices':[]})

@app.get('/', defaults={'path':''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public','index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',3000)))
