import hmac, hashlib, datetime, os, ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

# Forçar TLS 1.2 (Absolute exige TLS 1.2)
class TLS12Adapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def enc(v):
    for a,b in [('$','%24'),(' ','%20'),("'",'%27'),('(','%28'),(')','%29'),(',','%2C'),(':','%3A')]:
        v = v.replace(a,b)
    return v

def build(path, query):
    date = datetime.datetime.utcnow()
    dymd = date.strftime('%Y%m%d')
    xdate = dymd + 'T' + date.strftime('%H%M%S') + 'Z'
    bhash = hashlib.sha256(b'').hexdigest()
    canon = f'GET\n{path}\n{enc(query)}\nhost:{HOST}\ncontent-type:application/json\nx-abs-date:{xdate}\n{bhash}'
    rhash = hashlib.sha256(canon.encode()).hexdigest()
    scope = dymd + '/cadc/abs1'
    sts = f'ABS1-HMAC-SHA-256\n{xdate}\n{scope}\n{rhash}'
    ks = ('ABS1'+SECRET).encode()
    kd = hmac.new(ks, dymd.encode(), hashlib.sha256).digest()
    sk = hmac.new(kd, b'abs1_request', hashlib.sha256).digest()
    sig = hmac.new(sk, sts.encode(), hashlib.sha256).hexdigest()
    headers = {'host':HOST,'Content-Type':'application/json','x-abs-date':xdate,
               'Authorization':f'ABS1-HMAC-SHA-256 Credential={TOKEN}/{scope}, SignedHeaders=host;content-type;x-abs-date, Signature={sig}'}
    return headers, canon, xdate, sig

@app.get('/diag')
def diag():
    out = {}
    path, q = '/v3/devices', '$top=3'
    headers, canon, xdate, sig = build(path, q)
    url = f'https://{HOST}{path}?{enc(q)}'

    # Tentativa COM TLS 1.2 forçado
    try:
        s = requests.Session()
        s.mount('https://', TLS12Adapter())
        r = s.get(url, headers=headers, timeout=10)
        out['tls12_forced'] = {'status': r.status_code, 'body': r.text[:100]}
    except Exception as e:
        out['tls12_forced'] = {'error': str(e)[:120]}

    # Tentativa normal
    try:
        r = requests.get(url, headers=headers, timeout=10)
        out['normal'] = {'status': r.status_code, 'body': r.text[:100]}
    except Exception as e:
        out['normal'] = {'error': str(e)[:120]}

    # Dados para Authentication Debugging do Absolute
    out['debug_info'] = {
        'tokenID': TOKEN,
        'X-Abs-Date': xdate,
        'Signature': sig,
        'CanonicalRequest': canon,
        'server_utc_now': datetime.datetime.utcnow().isoformat(),
    }
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
