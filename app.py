import time, os
import jwt as pyjwt
import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = 'api.absolute.com'

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

@app.get('/diag')
def diag():
    out = {}
    uri = '/v3/devices'
    qs = '%24top=3'
    issued_at = int(time.time() * 1000)
    jose = {"alg":"HS256","kid":TOKEN,"method":"GET","content-type":"application/json",
            "uri":uri,"query-string":qs,"issuedAt":issued_at}
    jws = pyjwt.encode({}, SECRET, algorithm="HS256", headers=jose)

    out['jws_preview'] = jws[:60] + '...'

    # 1. Mandar ESSE JWS pro /jws/validate
    try:
        r = requests.post(f'https://{HOST}/jws/validate', data=jws,
                         headers={'Content-Type':'text/plain'}, timeout=10)
        out['validate'] = {'status': r.status_code, 'body': r.text[:200]}
    except Exception as e:
        out['validate'] = {'error': str(e)[:80]}

    # 2. Mandar o MESMO JWS pro /v3/devices
    try:
        r = requests.get(f'https://{HOST}{uri}?{qs}',
                        headers={'Authorization':jws,'Content-Type':'application/json'}, timeout=10)
        out['v3_devices'] = {'status': r.status_code, 'body': r.text[:200],
                             'resp_headers': dict(list(r.headers.items())[:6])}
    except Exception as e:
        out['v3_devices'] = {'error': str(e)[:80]}

    # 3. Testar outros endpoints v3 que talvez tenham permissão diferente
    for ep in ['/v3/reporting/devices', '/v2/devices', '/v3/device-fields']:
        try:
            j2 = pyjwt.encode({}, SECRET, algorithm="HS256",
                              headers={**jose, "uri":ep, "query-string":""})
            r = requests.get(f'https://{HOST}{ep}',
                           headers={'Authorization':j2,'Content-Type':'application/json'}, timeout=10)
            out[f'ep_{ep}'] = {'status': r.status_code, 'body': r.text[:100]}
        except Exception as e:
            out[f'ep_{ep}'] = {'error': str(e)[:60]}

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
