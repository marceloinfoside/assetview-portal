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

def build_jws(uri, qs_in_header):
    issued_at = int(time.time() * 1000)
    jose = {"alg":"HS256","kid":TOKEN,"method":"GET","content-type":"application/json",
            "uri":uri,"query-string":qs_in_header,"issuedAt":issued_at}
    return pyjwt.encode({}, SECRET, algorithm="HS256", headers=jose)

def test(uri, qs_header, qs_url, auth_prefix=''):
    jws = build_jws(uri, qs_header)
    url = f'https://{HOST}{uri}' + (f'?{qs_url}' if qs_url else '')
    auth = (auth_prefix + jws) if auth_prefix else jws
    try:
        r = requests.get(url, headers={'Authorization':auth,'Content-Type':'application/json'}, timeout=12)
        return r.status_code, r.text[:120]
    except Exception as e:
        return 'ERR', str(e)[:80]

@app.get('/diag')
def diag():
    out = {}
    uri = '/v3/devices'

    # A: header e url ambos "$top=3" (não encoded)
    out['both_plain'] = dict(zip(['status','body'], test(uri, '$top=3', '$top=3')))
    # B: header e url ambos "%24top=3" (encoded)
    out['both_encoded'] = dict(zip(['status','body'], test(uri, '%24top=3', '%24top=3')))
    # C: header plain, url encoded
    out['hdr_plain_url_enc'] = dict(zip(['status','body'], test(uri, '$top=3', '%24top=3')))
    # D: header encoded, url plain
    out['hdr_enc_url_plain'] = dict(zip(['status','body'], test(uri, '%24top=3', '$top=3')))
    # E: sem query nenhuma
    out['no_query'] = dict(zip(['status','body'], test(uri, '', '')))
    # F: com Bearer prefix
    out['bearer_both_plain'] = dict(zip(['status','body'], test(uri, '$top=3', '$top=3', 'Bearer ')))

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
