import time, base64, os, json
import jwt as pyjwt
import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = 'api.absolute.com'
VALIDATE_URL = f'https://{HOST}/jws/validate'

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

def validate(jws):
    try:
        r = requests.post(VALIDATE_URL, data=jws,
                         headers={'Content-Type':'text/plain'}, timeout=10)
        return r.status_code, r.text[:150]
    except Exception as e:
        return 'ERR', str(e)[:80]

@app.get('/diag')
def diag():
    out = {}
    now = int(time.time())

    payload = {"iss":TOKEN, "aud":VALIDATE_URL, "iat":now, "exp":now+300, "sub":TOKEN}

    # PyJWT com secret string (como exemplo da comunidade)
    try:
        t1 = pyjwt.encode(payload, SECRET, algorithm="HS256", headers={"kid":TOKEN})
        out['pyjwt_string_kid'] = dict(zip(['status','body'], validate(t1)))
    except Exception as e:
        out['pyjwt_string_kid'] = {'error': str(e)[:100]}

    # PyJWT secret string sem kid
    try:
        t2 = pyjwt.encode(payload, SECRET, algorithm="HS256")
        out['pyjwt_string_nokid'] = dict(zip(['status','body'], validate(t2)))
    except Exception as e:
        out['pyjwt_string_nokid'] = {'error': str(e)[:100]}

    # PyJWT com secret base64-decoded
    try:
        key = base64.b64decode(SECRET)
        t3 = pyjwt.encode(payload, key, algorithm="HS256", headers={"kid":TOKEN})
        out['pyjwt_b64_kid'] = dict(zip(['status','body'], validate(t3)))
    except Exception as e:
        out['pyjwt_b64_kid'] = {'error': str(e)[:100]}

    # PyJWT header estilo Manus (metadados) + payload claims, secret base64
    try:
        key = base64.b64decode(SECRET)
        hdr = {"kid":TOKEN, "method":"GET", "content-type":"application/json",
               "uri":"/v3/devices", "query-string":"$top=3"}
        t4 = pyjwt.encode(payload, key, algorithm="HS256", headers=hdr)
        out['pyjwt_meta_b64'] = dict(zip(['status','body'], validate(t4)))
    except Exception as e:
        out['pyjwt_meta_b64'] = {'error': str(e)[:100]}

    # PyJWT header Manus + secret string
    try:
        hdr = {"kid":TOKEN, "method":"GET", "content-type":"application/json",
               "uri":"/v3/devices", "query-string":"$top=3"}
        t5 = pyjwt.encode(payload, SECRET, algorithm="HS256", headers=hdr)
        out['pyjwt_meta_string'] = dict(zip(['status','body'], validate(t5)))
    except Exception as e:
        out['pyjwt_meta_string'] = {'error': str(e)[:100]}

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
