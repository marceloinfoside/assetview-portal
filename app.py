import hmac, hashlib, datetime, os
import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

def enc(v):
    for a,b in [('$','%24'),(' ','%20'),("'",'%27'),('(','%28'),(')','%29'),(',','%2C'),(':','%3A')]:
        v = v.replace(a,b)
    return v

def sign(path, query, extra_headers=None):
    date = datetime.datetime.utcnow()
    dymd = date.strftime('%Y%m%d')
    xdate = dymd + 'T' + date.strftime('%H%M%S') + 'Z'
    bhash = hashlib.sha256(b'').hexdigest()
    ch = f'content-type:application/json\nhost:{HOST}\nx-abs-date:{xdate}\n'
    canon = f'GET\n{path}\n{enc(query)}\n{ch}{bhash}'
    rhash = hashlib.sha256(canon.encode()).hexdigest()
    scope = dymd + '/cadc/abs1'
    sts = f'ABS1-HMAC-SHA-256\n{xdate}\n{scope}\n{rhash}'
    ks = ('ABS1'+SECRET).encode()
    kd = hmac.new(ks, dymd.encode(), hashlib.sha256).digest()
    sk = hmac.new(kd, b'abs1_request', hashlib.sha256).digest()
    sig = hmac.new(sk, sts.encode(), hashlib.sha256).hexdigest()
    headers = {'host':HOST,'Content-Type':'application/json','x-abs-date':xdate,
               'Authorization':f'ABS1-HMAC-SHA-256 Credential={TOKEN}/{scope}, SignedHeaders=host;content-type;x-abs-date, Signature={sig}'}
    if extra_headers:
        headers.update(extra_headers)
    url = f'https://{HOST}{path}' + (f'?{enc(query)}' if query else '')
    try:
        r = requests.get(url, headers=headers, timeout=10)
        return r.status_code, r.text[:100]
    except Exception as e:
        return 'ERR', str(e)[:80]

@app.get('/diag')
def diag():
    out = {}
    path, q = '/v3/devices', '$top=3'
    # Teste 1: sem extras (baseline)
    out['baseline'] = dict(zip(['status','body'], sign(path, q)))
    # Teste 2: com User-Agent
    out['user_agent'] = dict(zip(['status','body'], sign(path, q, {'User-Agent':'AssetView/1.0'})))
    # Teste 3: com Accept
    out['accept'] = dict(zip(['status','body'], sign(path, q, {'Accept':'application/json'})))
    # Teste 4: UA + Accept
    out['ua_accept'] = dict(zip(['status','body'], sign(path, q, {'User-Agent':'Mozilla/5.0','Accept':'application/json'})))
    # Teste 5: requests default UA (remove host header manual)
    date = datetime.datetime.utcnow()
    dymd = date.strftime('%Y%m%d')
    xdate = dymd + 'T' + date.strftime('%H%M%S') + 'Z'
    bhash = hashlib.sha256(b'').hexdigest()
    ch = f'content-type:application/json\nhost:{HOST}\nx-abs-date:{xdate}\n'
    canon = f'GET\n{path}\n{enc(q)}\n{ch}{bhash}'
    rhash = hashlib.sha256(canon.encode()).hexdigest()
    scope = dymd + '/cadc/abs1'
    sts = f'ABS1-HMAC-SHA-256\n{xdate}\n{scope}\n{rhash}'
    ks = ('ABS1'+SECRET).encode()
    kd = hmac.new(ks, dymd.encode(), hashlib.sha256).digest()
    sk = hmac.new(kd, b'abs1_request', hashlib.sha256).digest()
    sig = hmac.new(sk, sts.encode(), hashlib.sha256).hexdigest()
    h2 = {'Content-Type':'application/json','x-abs-date':xdate,
          'Authorization':f'ABS1-HMAC-SHA-256 Credential={TOKEN}/{scope}, SignedHeaders=host;content-type;x-abs-date, Signature={sig}'}
    try:
        r = requests.get(f'https://{HOST}{path}?{enc(q)}', headers=h2, timeout=10)
        out['no_manual_host'] = {'status': r.status_code, 'body': r.text[:100]}
    except Exception as e:
        out['no_manual_host'] = {'status':'ERR','body':str(e)[:80]}
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
