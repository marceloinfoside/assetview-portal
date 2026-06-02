import time, os, json
import jwt as pyjwt
import requests
from urllib.parse import quote
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

def absolute_get(uri, query_string=''):
    """
    Chama a API v3 do Absolute usando JWS/HS256.
    A query_string deve estar URL-encoded conforme a doc.
    """
    issued_at = int(time.time() * 1000)  # milissegundos
    jose_header = {
        "alg": "HS256",
        "kid": TOKEN,
        "method": "GET",
        "content-type": "application/json",
        "uri": uri,
        "query-string": query_string,
        "issuedAt": issued_at
    }
    # Payload vazio para GET
    payload = {}
    # secret como string UTF-8 (confirmado nos testes)
    jws = pyjwt.encode(payload, SECRET, algorithm="HS256", headers=jose_header)

    url = f'https://{HOST}{uri}'
    if query_string:
        url += f'?{query_string}'

    headers = {'Authorization': jws, 'Content-Type': 'application/json'}
    print(f'[Absolute] GET {url}')
    r = requests.get(url, headers=headers, timeout=20)
    print(f'[Absolute] Status {r.status_code}')
    return r

def fetch_devices(group_filter=None):
    # Montar query string URL-encoded
    select = ('id,esn,systemName,username,systemModel,serial,osName,osVersion,'
              'lastConnectedUtc,geoData,systemDiskInfo,memoryInfo,cpuInfo,groupName,agentStatus')
    params = [('$top', '300'), ('$select', select)]
    if group_filter:
        params.append(('$filter', f"groupName eq '{group_filter}'"))
    # URL-encode cada valor (mantém estrutura key=value&key=value)
    qs = '&'.join(f'{quote(k, safe="")}={quote(v, safe="")}' for k, v in sorted(params))

    r = absolute_get('/v3/devices', qs)
    if not r.ok:
        return None, f'API {r.status_code}: {r.text[:200]}'
    data = r.json()
    devices = data if isinstance(data, list) else data.get('value', data)
    return devices, None

@app.get('/diag')
def diag():
    r = absolute_get('/v3/devices', '%24top=3')
    return jsonify({'status': r.status_code, 'body': r.text[:500]})

@app.post('/api/login')
def login():
    d = request.get_json()
    u = USERS.get(d.get('username','').strip())
    if not u or u['password'] != d.get('password',''):
        return jsonify({'error':'Usuário ou senha inválidos'}), 401
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
    u = session['user']
    group = request.args.get('group') if u['isAdmin'] else u['group_filter']
    devs, err = fetch_devices(group)
    if err:
        return jsonify({'error': err}), 500
    return jsonify({'devices': devs})

@app.get('/', defaults={'path':''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public','index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',3000)))
