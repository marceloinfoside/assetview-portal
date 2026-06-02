import hmac, hashlib, json, time, base64, os
import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = 'api.absolute.com'

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def sign_jws(header, payload, key):
    si = f"{b64url(header)}.{b64url(payload)}"
    sig = b64url(hmac.new(key, si.encode(), hashlib.sha256).digest())
    return f"{si}.{sig}"

def validate(jws):
    try:
        r = requests.post(f'https://{HOST}/jws/validate', data=jws,
                         headers={'Content-Type':'text/plain'}, timeout=10)
        return r.status_code, r.text[:150]
    except Exception as e:
        return 'ERR', str(e)[:80]

@app.get('/diag')
def diag():
    out = {}
    now_ms = int(time.time() * 1000)
    jose = {"alg":"HS256","kid":TOKEN,"method":"GET","content-type":"application/json",
            "uri":"/v3/devices","query-string":"$top=3","issuedAt":now_ms}

    # Diferentes formas de derivar a chave HMAC
    keys = {
        'b64decode': base64.b64decode(SECRET),
        'ABS1+b64decode': b'ABS1' + base64.b64decode(SECRET),
        'ABS1+string': ('ABS1'+SECRET).encode(),
        'string_utf8': SECRET.encode('utf-8'),
        'b64url_decode': base64.urlsafe_b64decode(SECRET + '=='),
        'hex_decode': bytes.fromhex(SECRET) if all(c in '0123456789abcdefABCDEF' for c in SECRET) else b'',
    }

    for kname, key in keys.items():
        if not key:
            out[kname] = {'status':'skip','body':'chave vazia'}
            continue
        jws = sign_jws(jose, {}, key)
        out[kname] = dict(zip(['status','body'], validate(jws)))

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
