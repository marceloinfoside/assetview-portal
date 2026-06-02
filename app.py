import hmac, hashlib, json, time, base64, os
import requests
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = 'api.absolute.com'

USERS = {'admin': {'password': os.environ.get('ADMIN_PASSWORD','admin123'),
                   'name':'Administrador','group_filter':None,'is_admin':True}}

def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def validate(jws):
    """Usa o endpoint /jws/validate para checar a assinatura"""
    try:
        r = requests.post(f'https://{HOST}/jws/validate', data=jws,
                          headers={'Content-Type':'text/plain'}, timeout=10)
        return r.status_code, r.text[:150]
    except Exception as e:
        return 'ERR', str(e)[:80]

@app.get('/diag')
def diag():
    out = {}
    path, q = '/v3/devices', '$top=3'
    key = base64.b64decode(SECRET)  # sabemos que é base64
    issued_at = int(time.time() * 1000)

    jose = {"alg":"HS256","kid":TOKEN,"method":"GET","content-type":"application/json",
            "uri":path,"query-string":q,"issuedAt":issued_at}
    eh = b64url(jose)

    # Variação 1: payload {} (atual)
    ep1 = b64url({})
    si1 = f"{eh}.{ep1}"
    sig1 = b64url(hmac.new(key, si1.encode(), hashlib.sha256).digest())
    out['payload_empty_obj'] = dict(zip(['status','body'], validate(f"{si1}.{sig1}")))

    # Variação 2: payload vazio (string vazia)
    ep2 = b64url("")
    si2 = f"{eh}.{ep2}"
    sig2 = b64url(hmac.new(key, si2.encode(), hashlib.sha256).digest())
    out['payload_empty_str'] = dict(zip(['status','body'], validate(f"{si2}.{sig2}")))

    # Variação 3: sem payload (header..sig)
    si3 = f"{eh}."
    sig3 = b64url(hmac.new(key, si3.encode(), hashlib.sha256).digest())
    out['payload_none'] = dict(zip(['status','body'], validate(f"{eh}..{sig3}")))

    # Variação 4: assinar só o header (sem o ponto)
    sig4 = b64url(hmac.new(key, eh.encode(), hashlib.sha256).digest())
    out['sign_header_only'] = dict(zip(['status','body'], validate(f"{eh}.{ep1}.{sig4}")))

    # Variação 5: secret string + base64 no signing (híbrido)
    si5 = f"{eh}.{ep1}"
    sig5 = b64url(hmac.new(SECRET.encode(), si5.encode(), hashlib.sha256).digest())
    out['secret_string'] = dict(zip(['status','body'], validate(f"{si5}.{sig5}")))

    # Variação 6: jose header SEM os campos extras (JWT padrão)
    jose_min = {"alg":"HS256","kid":TOKEN}
    eh6 = b64url(jose_min)
    si6 = f"{eh6}.{ep1}"
    sig6 = b64url(hmac.new(key, si6.encode(), hashlib.sha256).digest())
    out['jose_minimal'] = dict(zip(['status','body'], validate(f"{si6}.{sig6}")))

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
