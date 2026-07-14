import time, os, json, base64, hmac, hashlib, random, smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from urllib.parse import quote
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')

TOKEN = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET = os.environ.get('ABSOLUTE_SECRET', '')
HOST = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')
VALIDATE_URL = f'https://{HOST}/jws/validate'

# Config SMTP (Gmail)
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')       # seu.email@gmail.com
SMTP_PASS = os.environ.get('SMTP_PASS', '')       # senha de app (16 caracteres)
SMTP_FROM = os.environ.get('SMTP_FROM', SMTP_USER)
SMTP_FROM_NAME = os.environ.get('SMTP_FROM_NAME', 'Infoside HaaS')

# ==== USUÁRIOS ====
# Admin vem de variáveis próprias; clientes vêm de USERS_JSON.
# USERS_JSON exemplo (uma linha na variável de ambiente):
# {"randon":{"password":"senha123","name":"Randoncorp","email":"ti@randon.com","group":"Randoncorp"}}
USERS = {}
_admin_user = os.environ.get('ADMIN_USER', 'admin')
USERS[_admin_user] = {
    'password': os.environ.get('ADMIN_PASSWORD', 'admin123'),
    'name': os.environ.get('ADMIN_NAME', 'Administrador'),
    'email': os.environ.get('ADMIN_EMAIL', ''),
    'group': None, 'is_admin': True
}
try:
    _extra = json.loads(os.environ.get('USERS_JSON', '{}'))
    for uname, info in _extra.items():
        USERS[uname] = {
            'password': info.get('password', ''),
            'name': info.get('name', uname),
            'email': info.get('email', ''),
            'group': info.get('group'),
            'is_admin': bool(info.get('is_admin', False))
        }
except Exception as e:
    print('[USERS_JSON] erro ao ler:', e)

# Códigos 2FA temporários em memória: {username: {'code':..,'exp':..,'tries':..}}
PENDING = {}
CODE_TTL = 300  # 5 minutos
MAX_TRIES = 5

def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')

def _build_html(code, user_name):
    return f"""<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;">
      <h2 style="color:#2563eb;margin-bottom:4px;">Infoside HaaS</h2>
      <p style="color:#333;">Olá, {user_name}.</p>
      <p style="color:#333;">Seu código de acesso é:</p>
      <div style="font-size:32px;font-weight:bold;letter-spacing:6px;color:#0a0c10;
        background:#f1f3f6;padding:16px;text-align:center;border-radius:8px;margin:16px 0;">{code}</div>
      <p style="color:#666;font-size:13px;">Este código expira em 5 minutos. Se você não tentou acessar o portal, ignore este e-mail.</p>
    </div>"""

RESEND_KEY = os.environ.get('RESEND_API_KEY', '')

def send_via_resend(to_email, code, user_name):
    try:
        r = requests.post('https://api.resend.com/emails',
            headers={'Authorization': f'Bearer {RESEND_KEY}', 'Content-Type': 'application/json'},
            json={'from': f'{SMTP_FROM_NAME} <{SMTP_FROM}>', 'to': [to_email],
                  'subject': f'Seu código de acesso: {code}', 'html': _build_html(code, user_name)},
            timeout=20)
        if r.status_code in (200, 201):
            return True, None
        return False, f'Resend {r.status_code}: {r.text[:150]}'
    except Exception as e:
        return False, f'Resend erro: {str(e)[:150]}'

def send_via_smtp(to_email, code, user_name):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'Seu código de acesso: {code}'
    msg['From'] = f'{SMTP_FROM_NAME} <{SMTP_FROM}>'
    msg['To'] = to_email
    msg.attach(MIMEText(_build_html(code, user_name), 'html'))
    ctx = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20, context=ctx) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls(context=ctx)
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
    return True, None

def send_2fa_email(to_email, code, user_name):
    # Prioridade: Resend (API, imune a bloqueio de porta) se configurado; senão SMTP
    if RESEND_KEY:
        return send_via_resend(to_email, code, user_name)
    if not SMTP_USER or not SMTP_PASS:
        print('[2FA] Nenhum método de e-mail configurado; código:', code)
        return False, 'E-mail não configurado no servidor.'
    try:
        return send_via_smtp(to_email, code, user_name)
    except Exception as e:
        print('[2FA] erro envio:', e)
        return False, 'Falha ao enviar o e-mail.'

def mask_email(e):
    if not e or '@' not in e: return '—'
    n, d = e.split('@', 1)
    if len(n) <= 2: nm = n[0] + '*'
    else: nm = n[0] + '*'*(len(n)-2) + n[-1]
    return nm + '@' + d

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
    fields = ('esn,deviceName,fullSystemName,systemManufacturer,systemModel,serialNumber,'
              'systemType,agentStatus,platformOSType,operatingSystem,username,currentUsername,'
              'lastConnectedDateTimeUtc,geoData,localIpAddress,publicIpAddress,'
              'totalPhysicalRamBytes,availablePhysicalRamBytes,volumes,cpu,policyGroupName,domain')
    all_devices = []
    next_page = None
    for _ in range(20):
        qs = f'select={quote(fields, safe="")}&pageSize=100&agentStatus=A'
        if group_filter:
            qs += f'&policyGroupName={quote(group_filter, safe="")}'
        if next_page:
            qs += f'&nextPage={quote(next_page, safe="")}'
        r = absolute_request('GET', '/v3/reporting/devices', qs)
        if not r.ok:
            if all_devices: break
            return None, f'API {r.status_code}: {r.text[:200]}'
        body = r.json()
        page = body.get('data', [])
        all_devices.extend(page)
        next_page = body.get('metadata', {}).get('pagination', {}).get('nextPage')
        if not next_page or not page: break
    return all_devices, None

@app.get('/diag')
def diag():
    r = absolute_request('GET', '/v3/reporting/devices', 'pageSize=2')
    return jsonify({'status': r.status_code, 'body': r.text[:400]})

@app.get('/diag-email')
def diag_email():
    info = {
        'SMTP_HOST': SMTP_HOST,
        'SMTP_PORT': SMTP_PORT,
        'SMTP_USER_preenchido': bool(SMTP_USER),
        'SMTP_USER_valor': SMTP_USER if SMTP_USER else '(vazio)',
        'SMTP_PASS_preenchido': bool(SMTP_PASS),
        'SMTP_PASS_tamanho': len(SMTP_PASS) if SMTP_PASS else 0,
        'SMTP_FROM': SMTP_FROM,
        'ADMIN_EMAIL': os.environ.get('ADMIN_EMAIL', '(vazio)'),
    }
    dest = request.args.get('to') or os.environ.get('ADMIN_EMAIL', '')
    info['metodo'] = 'Resend API' if RESEND_KEY else f'SMTP porta {SMTP_PORT}'
    if not dest:
        info['resultado'] = 'Sem destinatário. Use /diag-email?to=seu@email.com'
        return jsonify(info)
    try:
        ok, err = send_2fa_email(dest, '123456', 'Teste')
        if ok:
            info['resultado'] = f'SUCESSO - e-mail enviado para {dest}'
        else:
            info['resultado'] = 'ERRO'
            info['erro_detalhe'] = err
    except Exception as e:
        info['resultado'] = 'ERRO'
        info['erro_tipo'] = type(e).__name__
        info['erro_detalhe'] = str(e)[:300]
    return jsonify(info)

# ==== ETAPA 1: valida usuário/senha, envia código ====
@app.post('/api/login')
def login():
    d = request.get_json()
    username = d.get('username','').strip()
    u = USERS.get(username)
    if not u or u['password'] != d.get('password',''):
        return jsonify({'error':'Usuário ou senha inválidos'}), 401
    if not u.get('email'):
        return jsonify({'error':'Usuário sem e-mail cadastrado. Contate o administrador.'}), 400
    code = f'{random.randint(0, 999999):06d}'
    PENDING[username] = {'code':code, 'exp':time.time()+CODE_TTL, 'tries':0}
    ok, err = send_2fa_email(u['email'], code, u['name'])
    if not ok:
        return jsonify({'error':err or 'Falha ao enviar código.'}), 500
    return jsonify({'success':True, 'step':'2fa', 'email_hint':mask_email(u['email'])})

# ==== ETAPA 2: valida código, cria sessão ====
@app.post('/api/verify')
def verify():
    d = request.get_json()
    username = d.get('username','').strip()
    code = d.get('code','').strip()
    u = USERS.get(username)
    p = PENDING.get(username)
    if not u or not p:
        return jsonify({'error':'Sessão expirada. Faça login novamente.'}), 400
    if time.time() > p['exp']:
        PENDING.pop(username, None)
        return jsonify({'error':'Código expirado. Faça login novamente.'}), 400
    p['tries'] += 1
    if p['tries'] > MAX_TRIES:
        PENDING.pop(username, None)
        return jsonify({'error':'Muitas tentativas. Faça login novamente.'}), 429
    if code != p['code']:
        return jsonify({'error':'Código incorreto.'}), 401
    PENDING.pop(username, None)
    session['user'] = {'name':u['name'],'isAdmin':u['is_admin'],'group_filter':u['group']}
    return jsonify({'success':True, 'name':u['name'], 'isAdmin':u['is_admin']})

# ==== Reenviar código ====
@app.post('/api/resend')
def resend():
    d = request.get_json()
    username = d.get('username','').strip()
    u = USERS.get(username)
    if not u or not u.get('email'):
        return jsonify({'error':'Faça login novamente.'}), 400
    code = f'{random.randint(0, 999999):06d}'
    PENDING[username] = {'code':code, 'exp':time.time()+CODE_TTL, 'tries':0}
    ok, err = send_2fa_email(u['email'], code, u['name'])
    if not ok:
        return jsonify({'error':err or 'Falha ao reenviar.'}), 500
    return jsonify({'success':True, 'email_hint':mask_email(u['email'])})

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

@app.get('/api/groups')
def groups():
    if 'user' not in session: return jsonify({'error':'Não autenticado'}), 401
    if not session['user'].get('isAdmin'):
        return jsonify({'error':'Apenas administrador'}), 403
    devs, err = fetch_all_devices(None)
    if err:
        return jsonify({'error': err}), 500
    counts = {}
    for d in devs:
        g = d.get('policyGroupName') or '(sem grupo)'
        counts[g] = counts.get(g, 0) + 1
    ordered = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    return jsonify({'total_grupos': len(ordered),
                    'total_equipamentos': len(devs),
                    'grupos': [{'nome': g, 'equipamentos': c} for g, c in ordered]})

@app.get('/', defaults={'path':''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public','index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',3000)))
