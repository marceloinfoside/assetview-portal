
import hmac, hashlib, base64, datetime
from urllib.parse import quote
from flask import Flask, jsonify
import requests as req
import os

app = Flask(__name__)

TOKEN_ID   = os.environ.get('ABSOLUTE_TOKEN_ID', '')
SECRET_KEY = os.environ.get('ABSOLUTE_SECRET', '')
HOST       = os.environ.get('ABSOLUTE_HOST', 'api.absolute.com')

@app.get('/diag')
def diag():
    dt         = datetime.datetime.now(datetime.timezone.utc)
    now        = dt.strftime('%Y%m%dT%H%M%SZ')
    date_short = dt.strftime('%Y%m%d')
    path       = "/v3/devices"
    qs         = "%24top=3"
    empty_hash = hashlib.sha256(b"").hexdigest()
    canonical_headers = f"content-type:application/json\nhost:{HOST}\nx-abs-date:{now}\n"
    canonical_request = f"GET\n{path}\n{qs}\n{canonical_headers}{empty_hash}"
    cr_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
    
    results = {}
    secret_bytes = base64.b64decode(SECRET_KEY)
    
    for region in ['cadc', 'usdc', 'eudc']:
        scope = f"{date_short}/{region}/abs1"
        ss    = f"ABS1-HMAC-SHA-256\n{now}\n{scope}\n{cr_hash}"
        for kname, k in [
            ("ABS1_b64str", ("ABS1"+SECRET_KEY).encode()),
            ("ABS1_bytes",  b"ABS1"+secret_bytes),
            ("bytes_only",  secret_bytes),
        ]:
            kd  = hmac.new(k,  date_short.encode(), hashlib.sha256).digest()
            ks  = hmac.new(kd, b"abs1_request",     hashlib.sha256).digest()
            sig = hmac.new(ks, ss.encode(),          hashlib.sha256).hexdigest()
            auth = f"ABS1-HMAC-SHA-256 Credential={TOKEN_ID}/{scope}, SignedHeaders=host;content-type;x-abs-date, Signature={sig}"
            try:
                r = req.get(
                    f"https://{HOST}{path}?{qs}",
                    headers={"Content-Type":"application/json","Host":HOST,"x-abs-date":now,"Authorization":auth},
                    timeout=10
                )
                results[f"{region}_{kname}"] = r.status_code
            except Exception as e:
                results[f"{region}_{kname}"] = str(e)
    return jsonify(results)

@app.get('/', defaults={"path":""})
@app.get("/<path:path>")
def index(path):
    return app.send_static_file("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
