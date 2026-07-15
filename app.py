import time, os, json, base64, hmac, hashlib, random, smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from urllib.parse import quote
from flask import Flask, request, jsonify, session, send_from_directory

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret')
# Sessão morre ao fechar o navegador (cookie de sessão, sem expiração salva)
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', 'true').lower() == 'true'
# Tempo máximo de inatividade (minutos) antes de exigir novo login
IDLE_TIMEOUT_MIN = int(os.environ.get('IDLE_TIMEOUT_MIN', '15'))

def sessao_valida():
    """Verifica se há sessão ativa e se não expirou por inatividade. Renova o relógio."""
    if 'user' not in session:
        return False
    last = session.get('last_seen', 0)
    if last and (time.time() - last) > IDLE_TIMEOUT_MIN * 60:
        session.clear()
        return False
    session['last_seen'] = time.time()
    return True

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
# Histórico de acessos em memória (últimos N). Zera se o servidor reiniciar.
ACCESS_LOG = []
ACCESS_LOG_MAX = 300

def registrar_acesso(username, nome, sucesso, motivo=''):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '')
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    ua = request.headers.get('User-Agent', '')[:120]
    ACCESS_LOG.insert(0, {
        'quando': time.time(),
        'usuario': username,
        'nome': nome,
        'sucesso': sucesso,
        'motivo': motivo,
        'ip': ip,
        'navegador': ua,
    })
    del ACCESS_LOG[ACCESS_LOG_MAX:]
    status = 'OK' if sucesso else 'FALHA'
    print(f'[ACESSO] {status} usuario={username} ip={ip} {motivo}')
CODE_TTL = 300  # 5 minutos
MAX_TRIES = 5
# 2FA desligado por padrão. Para ligar, defina ENABLE_2FA=true no Railway (requer Resend configurado).
ENABLE_2FA = os.environ.get('ENABLE_2FA', 'false').lower() in ('1', 'true', 'yes', 'sim')

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

# ==== DEVICE GROUPS (Device Group Tree API) ====
# Cache simples: {nome_lower: {'uid':..., 'ts':...}} e {uid: {'uids':set, 'ts':...}}
_DG_NODES_CACHE = {'data': None, 'ts': 0}
_DG_DEVICES_CACHE = {}
_DG_TTL = 300  # 5 min

def fetch_device_group_uid(group_name):
    """Busca o deviceGroupTreeUid pelo nome (displayName) do grupo."""
    now = time.time()
    if not _DG_NODES_CACHE['data'] or now - _DG_NODES_CACHE['ts'] > _DG_TTL:
        nodes = []
        next_page = None
        for _ in range(10):
            qs = 'pageSize=100'
            if next_page:
                qs += f'&nextPage={quote(next_page, safe="")}'
            r = absolute_request('GET', '/v3/configurations/devicegrouptree/nodes', qs)
            if not r.ok:
                return None, f'DeviceGroups API {r.status_code}: {r.text[:150]}'
            body = r.json()
            nodes.extend(body.get('data', []))
            next_page = body.get('metadata', {}).get('pagination', {}).get('nextPage')
            if not next_page: break
        _DG_NODES_CACHE['data'] = nodes
        _DG_NODES_CACHE['ts'] = now
    gf = group_name.strip().lower()
    for n in _DG_NODES_CACHE['data']:
        name = (n.get('displayName') or n.get('name') or '').strip().lower()
        if name == gf:
            uid = n.get('deviceGroupTreeUid') or n.get('uid') or n.get('id')
            return uid, None
    return None, f'Grupo "{group_name}" não encontrado nos Device Groups.'

def _child_uids(parent_uid):
    """Retorna os uids dos nós filhos de um nó (para pastas com subgrupos)."""
    children = []
    for n in (_DG_NODES_CACHE.get('data') or []):
        pr = n.get('parentRelation') or {}
        if pr.get('parentNodeId') == parent_uid:
            children.append(n.get('deviceGroupTreeUid'))
    return children

def fetch_device_group_device_uids(group_uid, _depth=0):
    """Busca o conjunto de deviceUids de um grupo, incluindo filhos (recursivo)."""
    now = time.time()
    cached = _DG_DEVICES_CACHE.get(group_uid)
    if cached and now - cached['ts'] < _DG_TTL:
        return cached['uids'], None
    uids = set()
    next_page = None
    for _ in range(30):
        qs = 'pageSize=500'
        if next_page:
            qs += f'&nextPage={quote(next_page, safe="")}'
        r = absolute_request('GET', f'/v3/configurations/devicegrouptree/nodes/{group_uid}/get-devices', qs)
        if not r.ok:
            if _depth == 0:
                return None, f'GroupDevices API {r.status_code}: {r.text[:150]}'
            break  # em filhos, ignora erro
        body = r.json()
        for d in body.get('data', []):
            u = d.get('deviceUid') or d.get('uid') or d.get('id')
            if u: uids.add(u)
        next_page = body.get('metadata', {}).get('pagination', {}).get('nextPage')
        if not next_page: break
    # se for pasta com filhos, agrega os dispositivos dos filhos também
    if _depth < 3:
        for cu in _child_uids(group_uid):
            if cu:
                child_uids, _ = fetch_device_group_device_uids(cu, _depth+1)
                if child_uids:
                    uids |= child_uids
    if _depth == 0:
        _DG_DEVICES_CACHE[group_uid] = {'uids': uids, 'ts': now}
    return uids, None

def fetch_all_devices(group_filter=None):
    fields = ('deviceUid,esn,deviceName,fullSystemName,systemManufacturer,systemModel,serialNumber,'
              'systemType,agentStatus,platformOSType,operatingSystem,username,currentUsername,'
              'lastConnectedDateTimeUtc,geoData,localIpAddress,publicIpAddress,'
              'totalPhysicalRamBytes,availablePhysicalRamBytes,volumes,cpu,policyGroupName,domain')
    all_devices = []
    next_page = None
    for _ in range(30):
        qs = f'select={quote(fields, safe="")}&pageSize=100&agentStatus=A'
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
    if group_filter:
        # 1) Tenta como Device Group (estrutura oficial de grupos de dispositivos)
        uid, err = fetch_device_group_uid(group_filter)
        if uid:
            guids, err2 = fetch_device_group_device_uids(uid)
            if err2:
                return None, err2
            all_devices = [d for d in all_devices if d.get('deviceUid') in guids]
        else:
            # 2) Fallback: tenta como Policy Group (compatibilidade)
            gf = group_filter.strip().lower()
            filtered = [d for d in all_devices
                        if (d.get('policyGroupName') or '').strip().lower() == gf]
            if not filtered:
                return None, err or f'Grupo "{group_filter}" não encontrado.'
            all_devices = filtered
    return all_devices, None

@app.get('/diag-dg')
def diag_dg():
    if not sessao_valida() or not session['user'].get('isAdmin'):
        return jsonify({'error':'Apenas administrador logado'}), 403
    out = {}
    candidatos = [
        '/v3/device-groups',
        '/v3/device-group-tree',
        '/v3/configurations/device-groups',
        '/v3/device-groups-tree',
        '/v3/reporting/device-groups',
    ]
    for ep in candidatos:
        try:
            r = absolute_request('GET', ep, '')
            out[ep] = {'status': r.status_code, 'body': r.text[:300]}
        except Exception as e:
            out[ep] = {'erro': str(e)[:100]}
    return jsonify(out)

@app.get('/diag-dominios')
def diag_dominios():
    if not sessao_valida() or not session['user'].get('isAdmin'):
        return jsonify({'error':'Apenas administrador logado'}), 403
    devs, err = fetch_all_devices(None)
    if err:
        return jsonify({'error': err}), 500
    doms = {}
    for d in devs:
        dm = d.get('domain')
        key = repr(dm)
        doms[key] = doms.get(key, 0) + 1
    ordered = dict(sorted(doms.items(), key=lambda x: -x[1]))
    return jsonify({'total_equipamentos': len(devs), 'dominios': ordered})

@app.get('/diag-grupos')
def diag_grupos():
    if not sessao_valida() or not session['user'].get('isAdmin'):
        return jsonify({'error':'Apenas administrador logado'}), 403
    devs, err = fetch_all_devices(None)
    if err:
        return jsonify({'error': err}), 500
    # Mostrar valores únicos exatos de policyGroupName (com aspas para ver espaços)
    grupos = {}
    for d in devs:
        g = d.get('policyGroupName')
        key = repr(g)  # repr mostra aspas e espaços
        grupos[key] = grupos.get(key, 0) + 1
    return jsonify({'total_equipamentos': len(devs),
                    'grupos_exatos': grupos})

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
        registrar_acesso(username or '(vazio)', '', False, 'senha inválida')
        return jsonify({'error':'Usuário ou senha inválidos'}), 401
    # 2FA desligado: cria sessão direto
    if not ENABLE_2FA:
        session['user'] = {'name':u['name'],'isAdmin':u['is_admin'],'group_filter':u['group']}
        session['last_seen'] = time.time()
        registrar_acesso(username, u['name'], True, 'login direto')
        return jsonify({'success':True, 'step':'done', 'name':u['name'], 'isAdmin':u['is_admin']})
    # 2FA ligado: envia código
    if not u.get('email'):
        registrar_acesso(username, u['name'], False, 'sem e-mail cadastrado')
        return jsonify({'error':'Usuário sem e-mail cadastrado. Contate o administrador.'}), 400
    code = f'{random.randint(0, 999999):06d}'
    PENDING[username] = {'code':code, 'exp':time.time()+CODE_TTL, 'tries':0}
    ok, err = send_2fa_email(u['email'], code, u['name'])
    if not ok:
        registrar_acesso(username, u['name'], False, 'falha envio 2FA')
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
        registrar_acesso(username, u['name'], False, 'código 2FA incorreto')
        return jsonify({'error':'Código incorreto.'}), 401
    PENDING.pop(username, None)
    session['user'] = {'name':u['name'],'isAdmin':u['is_admin'],'group_filter':u['group']}
    session['last_seen'] = time.time()
    registrar_acesso(username, u['name'], True, 'login com 2FA')
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
    if not sessao_valida(): return jsonify({'error':'Não autenticado'}), 401
    return jsonify(session['user'])

@app.get('/api/devices')
def devices():
    if not sessao_valida(): return jsonify({'error':'Não autenticado'}), 401
    u = session['user']
    group = request.args.get('group') if u['isAdmin'] else u['group_filter']
    devs, err = fetch_all_devices(group)
    if err:
        return jsonify({'error': err}), 500
    return jsonify({'devices': devs})

@app.get('/api/acessos')
def acessos():
    if not sessao_valida(): return jsonify({'error':'Não autenticado'}), 401
    if not session['user'].get('isAdmin'):
        return jsonify({'error':'Apenas administrador'}), 403
    return jsonify({'total': len(ACCESS_LOG), 'acessos': ACCESS_LOG})

@app.get('/api/groups')
def groups():
    if not sessao_valida(): return jsonify({'error':'Não autenticado'}), 401
    if not session['user'].get('isAdmin'):
        return jsonify({'error':'Apenas administrador'}), 403
    # Lista os Device Groups (nomes) a partir da árvore
    now = time.time()
    if not _DG_NODES_CACHE['data'] or now - _DG_NODES_CACHE['ts'] > _DG_TTL:
        # força atualização via função auxiliar
        fetch_device_group_uid('__forcar_carga__')
    nodes = _DG_NODES_CACHE.get('data') or []
    grupos = []
    for n in nodes:
        nome = n.get('displayName') or n.get('name') or '(sem nome)'
        tipo = n.get('nodeType') or ''
        grupos.append({'nome': nome, 'tipo': tipo,
                       'uid': n.get('deviceGroupTreeUid') or n.get('uid') or n.get('id')})
    grupos.sort(key=lambda x: x['nome'].lower())
    return jsonify({'total_grupos': len(grupos), 'grupos': grupos})

@app.get('/diag-dg2')
def diag_dg2():
    if not sessao_valida() or not session['user'].get('isAdmin'):
        return jsonify({'error':'Apenas administrador logado'}), 403
    r = absolute_request('GET', '/v3/configurations/devicegrouptree/nodes', 'pageSize=100')
    out = {'nodes_status': r.status_code}
    try:
        nodes = r.json().get('data', [])
        resumo = []
        for n in nodes:
            uid = n.get('deviceGroupTreeUid')
            nome = n.get('displayName')
            tipo = n.get('nodeType')
            gtype = (n.get('deviceGroup') or {}).get('groupType', '')
            # conta dispositivos do grupo
            cnt = '?'
            try:
                rd = absolute_request('GET', f'/v3/configurations/devicegrouptree/nodes/{uid}/get-devices', 'pageSize=10')
                if rd.ok:
                    cnt = len(rd.json().get('data', []))
                    # se tem exatamente 10, pode ter mais (é só amostra)
                    cnt = f'{cnt}+ (amostra)' if cnt == 10 else cnt
                else:
                    cnt = f'err {rd.status_code}'
            except Exception as e:
                cnt = f'exc {str(e)[:30]}'
            resumo.append({'nome': nome, 'tipo': tipo, 'groupType': gtype,
                           'uid': uid, 'dispositivos_amostra': cnt})
        out['grupos'] = resumo
    except Exception as e:
        out['erro'] = str(e)[:200]
        out['body'] = r.text[:500]
    return jsonify(out)

@app.get('/', defaults={'path':''})
@app.get('/<path:path>')
def serve(path):
    return send_from_directory('public','index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',3000)))
