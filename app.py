import time, os, json, base64, hmac, hashlib
import requests
from urllib.parse import quote
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')
VALIDATE_URL = f'https://{HOST}/jws/validate'

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')

def absolute_request(method, uri, query_string='', payload=None):
    issued_at = int(time.time() * 1000)
    header = {"alg":"HS256","kid":TOKEN,"method":method,"content-type":"application/json",
              "uri":uri,"query-string":query_string,"issuedAt":issued_at}
    data_payload = {"data": payload if payload is not None else {}}
    h_b64 = b64url(json.dumps(header, separators=(',',':')).encode())
    p_b64 = b64url(json.dumps(data_payload, separators=(',',':')).encode())
    signing_input = f"{h_b64}.{p_b64}"
    sig = hmac.new(SECRET.encode('utf-8'), signing_input.encode(), hashlib.sha256).digest()
    jws = f"{signing_input}.{b64url(sig)}"
    r = requests.post(VALIDATE_URL, data=jws, headers={'Content-Type':'text/plain'}, timeout=30)
    return r

def fetch_all_devices(group_filter=None):
    """Busca todos os dispositivos com paginação"""
    fields = ('esn,deviceName,fullSystemName,systemManufacturer,systemModel,serialNumber,'
              'systemType,agentStatus,platformOSType,operatingSystem,username,currentUsername,'
              'lastConnectedDateTimeUtc,geoData,localIpAddress,publicIpAddress,'
              'totalPhysicalRamBytes,availablePhysicalRamBytes,volumes,cpu,policyGroupName,domain')
    all_devices = []
    next_page = None
    for _ in range(20):  # máx 20 páginas (~2000 devices)
        qs = f'select={quote(fields, safe="")}&pageSize=100'
        if group_filter:
            qs += f'&policyGroupName={quote(group_filter, safe="")}'
        if next_page:
            qs += f'&nextPage={quote(next_page, safe="")}'
        r = absolute_request('GET', '/v3/reporting/devices', qs)
        if not r.ok:
            if all_devices:
                break
            return None, f'API {r.status_code}: {r.text[:200]}'
        body = r.json()
        page = body.get('data', [])
        all_devices.extend(page)
        next_page = body.get('metadata', {}).get('pagination', {}).get('nextPage')
        if not next_page or not page:
            break
    return all_devices, None

@app.get('/diag')
def diag():
    r = absolute_request('GET', '/v3/reporting/devices', 'pageSize=2')
    return jsonify({'status': r.status_code, 'body': r.text[:400]})

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
    devs, err = fetch_all_devices(group)
    if err:
        return jsonify({'error': err}), 500
    return jsonify({'devices': devs})

@app.get('/', defaults={'path':''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public','index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',3000)))
