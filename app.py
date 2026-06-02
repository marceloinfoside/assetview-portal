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

def mk_jws(method, uri, query):
    nowms = int(time.time()*1000)
    headers = {"kid": TOKEN}
    # metadados no payload (header causou 403)
    payload = {
        "method": method,
        "uri": uri,
        "query-string": query,
        "content-type": "application/json",
        "issuedAt": nowms
    }
    return pyjwt.encode(payload, SECRET, algorithm="HS256", headers=headers)

def call_devices(method, uri, query, auth_style):
    jws = mk_jws(method, uri, query)
    if auth_style == 'bearer':
        auth = f"Bearer {jws}"
    else:
        auth = jws
    url = f'https://{HOST}{uri}' + (f'?{query}' if query else '')
    try:
        r = requests.get(url, headers={'Authorization': auth, 'Content-Type':'application/json'}, timeout=12)
        return r.status_code, r.text[:200]
    except Exception as e:
        return 'ERR', str(e)[:100]

@app.get('/diag')
def diag():
    out = {}
    # Chamar /v3/devices direto com a assinatura correta
    out['v3_bearer'] = dict(zip(['status','body'], call_devices('GET','/v3/devices','$top=3','bearer')))
    out['v3_plain']  = dict(zip(['status','body'], call_devices('GET','/v3/devices','$top=3','plain')))
    # Sem query
    out['v3_noquery_bearer'] = dict(zip(['status','body'], call_devices('GET','/v3/devices','','bearer')))
    out['v3_noquery_plain']  = dict(zip(['status','body'], call_devices('GET','/v3/devices','','plain')))
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
