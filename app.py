import time, os, json
import jwt as pyjwt
import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = 'api.absolute.com'
VURL = f'https://{HOST}/jws/validate'

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

def mk(payload, extra_hdr=None):
    h = {"kid": TOKEN}
    if extra_hdr: h.update(extra_hdr)
    return pyjwt.encode(payload, SECRET, algorithm="HS256", headers=h)

def post_validate(jws, mode):
    try:
        if mode == 'json_assertion':
            r = requests.post(VURL, json={"assertion": jws}, timeout=10)
        elif mode == 'form_assertion':
            r = requests.post(VURL, data={"assertion": jws}, timeout=10)
        else:  # raw
            r = requests.post(VURL, data=jws, headers={'Content-Type':'text/plain'}, timeout=10)
        return r.status_code, r.text[:200]
    except Exception as e:
        return 'ERR', str(e)[:80]

@app.get('/diag')
def diag():
    out = {}
    now = int(time.time())
    nowms = int(time.time()*1000)

    # Combinações de campos que a doc pode exigir
    # Tentar method+uri+issuedAt como raw text
    p_full = {"method":"GET","uri":"/v3/devices","query-string":"$top=3",
              "content-type":"application/json","issuedAt":nowms}
    jws_full = mk(p_full)

    out['raw_full'] = dict(zip(['status','body'], post_validate(jws_full, 'raw')))
    out['json_assertion_full'] = dict(zip(['status','body'], post_validate(jws_full, 'json_assertion')))
    out['form_assertion_full'] = dict(zip(['status','body'], post_validate(jws_full, 'form_assertion')))

    # Variação: data como segundos (não ms)
    p_sec = {"method":"GET","uri":"/v3/devices","query-string":"$top=3",
             "content-type":"application/json","issuedAt":now}
    out['raw_issuedAt_sec'] = dict(zip(['status','body'], post_validate(mk(p_sec), 'raw')))

    # Variação: campos com nomes alternativos
    p_alt = {"httpMethod":"GET","requestUri":"/v3/devices","queryString":"$top=3","issuedAt":nowms}
    out['raw_altnames'] = dict(zip(['status','body'], post_validate(mk(p_alt), 'raw')))

    # Variação: data como ISO string
    iso = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    p_iso = {"method":"GET","uri":"/v3/devices","query-string":"$top=3",
             "content-type":"application/json","issuedAt":iso}
    out['raw_iso'] = dict(zip(['status','body'], post_validate(mk(p_iso), 'raw')))

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
