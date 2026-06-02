import hmac, hashlib, json, time, base64, os
import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def make_jws(method, path, query, secret_mode):
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
    encoded_header = b64url(jose)
    encoded_payload = b64url({})
    signing_input = f"{encoded_header}.{encoded_payload}"

    if secret_mode == 'string':
        key = SECRET.encode('utf-8')
    else:  # base64 decoded
        key = base64.b64decode(SECRET)

    signature = hmac.new(key, signing_input.encode('utf-8'), hashlib.sha256).digest()
    encoded_sig = b64url(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_sig}", issued_at

def try_request(path, query, secret_mode, auth_format):
    jws, issued_at = make_jws('GET', path, query, secret_mode)
    if auth_format == 'bearer':
        auth = f"Bearer {jws}"
    else:
        auth = jws
    headers = {'Authorization': auth, 'Content-Type': 'application/json'}
    url = f'https://{HOST}{path}' + (f'?{query}' if query else '')
    try:
        r = requests.get(url, headers=headers, timeout=10)
        return r.status_code, r.text[:120]
    except Exception as e:
        return 'ERR', str(e)[:80]

@app.get('/diag')
def diag():
    out = {}
    path, q = '/v3/devices', '$top=3'
    for sm in ['string', 'base64']:
        for af in ['bearer', 'plain']:
            s, b = try_request(path, q, sm, af)
            out[f'secret={sm}|{af}'] = {'status': s, 'body': b}
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
    return jsonify({'devices':[], 'error':'Use /diag'})

@app.get('/', defaults={'path':''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public','index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',3000)))
