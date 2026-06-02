import time, os
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
        return r.status_code, r.text[:200]
    except Exception as e:
        return 'ERR', str(e)[:80]

def mk(payload, headers):
    h = {"kid": TOKEN}
    h.update(headers)
    return pyjwt.encode(payload, SECRET, algorithm="HS256", headers=h)

@app.get('/diag')
def diag():
    out = {}
    now = int(time.time())
    nowms = int(time.time()*1000)

    # Sabemos: secret=string, kid no header, assinatura OK. Faltam "required fields".
    # Testar metadados no PAYLOAD
    p1 = {"method":"GET","uri":"/v3/devices","query-string":"$top=3","issuedAt":nowms}
    out['meta_in_payload'] = dict(zip(['status','body'], validate(mk(p1, {}))))

    # Metadados no payload + content-type
    p2 = {"method":"GET","uri":"/v3/devices","query-string":"$top=3",
          "content-type":"application/json","issuedAt":nowms}
    out['meta_ct_payload'] = dict(zip(['status','body'], validate(mk(p2, {}))))

    # Metadados no HEADER (estilo Manus) mas secret=string
    hdr_meta = {"method":"GET","content-type":"application/json","uri":"/v3/devices",
                "query-string":"$top=3","issuedAt":nowms}
    out['meta_in_header'] = dict(zip(['status','body'], validate(mk({}, hdr_meta))))

    # Claims JWT padrão
    p4 = {"iss":TOKEN,"sub":TOKEN,"iat":now,"exp":now+300,"aud":VALIDATE_URL}
    out['jwt_claims'] = dict(zip(['status','body'], validate(mk(p4, {}))))

    # issuedAt no header + payload vazio
    out['issuedAt_header'] = dict(zip(['status','body'], validate(mk({}, {"issuedAt":nowms}))))

    # Tudo: header com metadados completos + issuedAt
    hdr_full = {"alg":"HS256","method":"GET","content-type":"application/json",
                "uri":"/v3/devices","query-string":"$top=3","issuedAt":nowms}
    out['header_full'] = dict(zip(['status','body'], validate(mk({}, hdr_full))))

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
