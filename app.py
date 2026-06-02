import hmac, hashlib, datetime, os
import requests
from flask import Flask, request, jsonify, session, send_from_directory
from functools import wraps

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

def call(path, query, content_type, header_order):
    date = datetime.datetime.utcnow()
    dymd = date.strftime('%Y%m%d')
    xdate = dymd + 'T' + date.strftime('%H%M%S') + 'Z'
    body = ''
    bhash = hashlib.sha256(body.encode()).hexdigest()

    if header_order == 'host_first':
        ch = f'host:{HOST}\ncontent-type:{content_type}\nx-abs-date:{xdate}\n'
    else:
        ch = f'content-type:{content_type}\nhost:{HOST}\nx-abs-date:{xdate}\n'

    canon = f'GET\n{path}\n{enc(query)}\n{ch}{bhash}'
    rhash = hashlib.sha256(canon.encode()).hexdigest()
    scope = dymd + '/cadc/abs1'
    sts = f'ABS1-HMAC-SHA-256\n{xdate}\n{scope}\n{rhash}'
    ks = ('ABS1'+SECRET).encode()
    kd = hmac.new(ks, dymd.encode(), hashlib.sha256).digest()
    sk = hmac.new(kd, b'abs1_request', hashlib.sha256).digest()
    sig = hmac.new(sk, sts.encode(), hashlib.sha256).hexdigest()

    headers = {'host':HOST,'Content-Type':content_type,'x-abs-date':xdate,
               'Authorization':f'ABS1-HMAC-SHA-256 Credential={TOKEN}/{scope}, SignedHeaders=host;content-type;x-abs-date, Signature={sig}'}
    url = f'https://{HOST}{path}' + (f'?{enc(query)}' if query else '')
    try:
        r = requests.get(url, headers=headers, timeout=10)
        return r.status_code, r.text[:80]
    except Exception as e:
        return 'ERR', str(e)[:80]

@app.get('/diag')
def diag():
    out = {}
    cts = ['application/json', 'application/json;charset=utf-8']
    for ct in cts:
        for ho in ['host_first', 'ct_first']:
            for path, q in [('/v3/devices','$top=3'), ('/v2/reporting/devices','$top=3')]:
                s, b = call(path, q, ct, ho)
                ver = 'v3' if 'v3' in path else 'v2'
                key = f'{ver}|ct={"plain" if ct=="application/json" else "utf8"}|{ho}'
                out[key] = {'status': s, 'body': b}
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
    session.clear()
    return jsonify({'success':True})

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
