"""Dark demo UI on top of the REAL project server (server/main_server.py).

Nothing is re-implemented here. The UI backend only calls the project's own
endpoints, so the original rules apply exactly:

  Edge:   SecureGateway.encrypt_data()  -> POST /api/v1/telemetry/ingest   (X-API-Key)
  Athlete consent:                         POST /api/v1/athlete/consent    (X-API-Key)
  Access: POST /api/v1/telemetry/authorize-decrypt
          Gate 1 API key -> Gate 2 GDPR consent -> Gate 3 RBAC
          (AUTHORIZED_DECRYPT_ROLES = {"TEAM_DOCTOR"}) -> Gate 4 AES-GCM decrypt
  Everything is written to the real AuditLogger CSV.

Run:  ./venv/bin/python demo_ui.py   ->  http://127.0.0.1:8000
"""

from __future__ import annotations

import os

# Use separate demo files so the project's real mock_db/audit/ledger are untouched.
os.environ.setdefault("MOCK_DB_PATH", "mock_db_demo_ui.json")
os.environ.setdefault("AUDIT_LOG_PATH", "audit_log_demo_ui.csv")
os.environ.setdefault("LEDGER_FILE_PATH", "ledger_file_demo_ui.json")

import uvicorn  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from core.secure_gateway import SecureGateway  # noqa: E402
from server.cloud_server import AUTHORIZED_DECRYPT_ROLES  # noqa: E402
from server.config import settings  # noqa: E402
from server.main_server import app, audit_logger, consent_registry  # noqa: E402

PLAYER_ID = "PLAYER-001"
GATEWAY_ID = "GW-DEMO-01"
DEVICE_ID = "IOT-WEARABLE-01"
# Roles shown in the UI -> the exact role strings the server understands.
ROLE_HEADER = {"athlete": "ATHLETE", "coach": "HEAD_COACH", "doctor": "TEAM_DOCTOR"}

_gateway = SecureGateway(gateway_id=GATEWAY_ID)  # holds the AES-256 key
_client = TestClient(app)  # calls the real endpoints in-process
_api = {"X-API-Key": settings.CLOUD_API_KEY}
_last = {"packet": None}


class Biometrics(BaseModel):
    heart_rate: int
    fatigue_index: float
    glucose_level: float
    injury_risk: float


class Consent(BaseModel):
    consent: bool


class View(BaseModel):
    role: str


@app.post("/demo/submit")
def demo_submit(b: Biometrics):
    payload = {
        "heart_rate": b.heart_rate,
        "fatigue_index": b.fatigue_index,
        "glucose_level": b.glucose_level,
        "gps_telemetry": {"lat": 37.9838, "lon": 23.7275, "speed_kmh": 0.0},
        "injury_risk": b.injury_risk,
    }
    try:
        packet = _gateway.encrypt_data(payload, device_id=DEVICE_ID, player_id=PLAYER_ID)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    r = _client.post("/api/v1/telemetry/ingest", json=packet, headers=_api)
    if r.status_code != 201:
        raise HTTPException(r.status_code, str(r.json()))
    _last["packet"] = packet
    return {"ok": True, "ciphertext": packet["ciphertext"]}


@app.post("/demo/consent")
def demo_consent(c: Consent):
    r = _client.post(
        "/api/v1/athlete/consent",
        json={"player_id": PLAYER_ID, "privacy_toggle_consent": c.consent},
        headers=_api,
    )
    return {"consent": r.json()["privacy_toggle_consent"]}


@app.get("/demo/consent")
def demo_get_consent():
    return {"consent": consent_registry.is_consent_granted(PLAYER_ID)}


@app.post("/demo/view")
def demo_view(v: View):
    packet = _last["packet"]
    if packet is None:
        return {"status": "empty"}
    role = ROLE_HEADER[v.role]
    r = _client.post(
        "/api/v1/telemetry/authorize-decrypt",
        json={"record": packet, "aes_key_hex": _gateway.aes_key.hex()},
        headers={**_api, "X-User-Role": role, "X-Player-Id": PLAYER_ID},
    )
    if r.status_code == 200:
        return {"status": "decrypted", "role": role, "data": r.json()["decrypted_payload"]}
    return {
        "status": "denied",
        "role": role,
        "http": r.status_code,
        "detail": r.json().get("detail"),
        "ciphertext": packet["ciphertext"],  # what the outsider sees
    }


@app.get("/demo/audit")
def demo_audit():
    return audit_logger.read_audit_log(player_id=PLAYER_ID)[-8:]


@app.get("/demo/rules")
def demo_rules():
    return {"allowed_roles": sorted(AUTHORIZED_DECRYPT_ROLES)}


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML


HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Biometrics Vault</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,Segoe UI,sans-serif;background:#0b0d12;color:#e6e8ee;min-height:100vh}
.wrap{max-width:880px;margin:0 auto;padding:32px 20px}h1{font-weight:600;margin:0 0 6px}p.sub{color:#8a90a2;margin:0 0 20px;font-size:14px}
.card{background:#141822;border:1px solid #232938;border-radius:14px;padding:20px;margin-bottom:18px;animation:fade .4s ease}
@keyframes fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.roles{display:flex;gap:10px}
button{background:#1d2333;color:#e6e8ee;border:1px solid #2c3449;border-radius:10px;padding:10px 18px;cursor:pointer;font-size:14px;transition:all .2s}
button:hover{background:#2a3350;transform:translateY(-1px)}button.active{background:#5b6cff;border-color:#5b6cff}
button.primary{background:#5b6cff;border-color:#5b6cff}.hidden{display:none}
input{background:#0f1219;border:1px solid #2c3449;color:#e6e8ee;border-radius:8px;padding:8px;width:100%;transition:border .2s}input:focus{outline:none;border-color:#5b6cff}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:12px}label{font-size:12px;color:#8a90a2}
.switch{position:relative;width:52px;height:28px;background:#2c3449;border-radius:20px;cursor:pointer;transition:background .3s;display:inline-block;vertical-align:middle}
.switch::after{content:"";position:absolute;top:3px;left:3px;width:22px;height:22px;background:#fff;border-radius:50%;transition:transform .3s}
.switch.on{background:#27c07d}.switch.on::after{transform:translateX(24px)}
.badge{display:inline-block;padding:4px 10px;border-radius:20px;font-size:12px}.ok{background:#16382b;color:#4be0a0}.bad{background:#3b1c24;color:#ff7a8c}
.kv{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.kv div{background:#0f1219;padding:12px;border-radius:10px}.kv b{display:block;font-size:20px;margin-top:4px}
code{display:block;word-break:break-all;background:#0f1219;padding:12px;border-radius:10px;color:#ff9aa8;font-size:12px;max-height:110px;overflow:auto;margin-top:10px}
table{width:100%;font-size:12px;border-collapse:collapse}td{padding:6px;border-bottom:1px solid #232938;color:#8a90a2}
</style></head><body><div class="wrap">
<h1>🔐 Biometrics Vault</h1>
<p class="sub">Real project server · API key → GDPR consent → RBAC (<span id="rules"></span>) → AES-256-GCM decrypt</p>
<div class="card"><div class="roles">
<button data-r="athlete">🏃 Athlete</button><button data-r="coach">📋 Head Coach</button><button data-r="doctor">🩺 Team Doctor</button></div>
<p id="who" class="sub" style="margin:12px 0 0">Select a role to log in.</p></div>

<div id="athletePanel" class="card hidden"><h3>Athlete device: enter biometrics</h3>
<div class="grid">
<div><label>Heart rate (bpm)</label><input id="hr" type="number" value="172"></div>
<div><label>Fatigue index</label><input id="fi" type="number" step="0.01" value="91.42"></div>
<div><label>Glucose level</label><input id="gl" type="number" step="0.1" value="88.5"></div>
<div><label>Injury risk (0-1)</label><input id="ir" type="number" step="0.01" value="0.63"></div></div>
<button class="primary" onclick="submitData()">Encrypt &amp; Send</button><span id="msg" class="sub" style="margin-left:10px"></span></div>

<div class="card"><h3>GDPR consent <span class="sub">(athlete controls)</span></h3>
<div id="sw" class="switch" onclick="toggleConsent()"></div> <span id="cs" class="badge"></span></div>

<div class="card"><h3>Access result <span id="vb" class="badge"></span></h3><div id="view" class="sub">No data yet.</div></div>
<div class="card"><h3>Audit log</h3><table id="audit"></table></div>
</div>
<script>
let role=null,consent=true;const $=id=>document.getElementById(id);
const api=(u,m='GET',b)=>fetch(u,{method:m,headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined}).then(async r=>{const j=await r.json();if(!r.ok)throw new Error(j.detail);return j});
api('/demo/rules').then(r=>$('rules').textContent=r.allowed_roles.join(', '));
document.querySelectorAll('.roles button').forEach(b=>b.onclick=()=>{role=b.dataset.r;
 document.querySelectorAll('.roles button').forEach(x=>x.classList.toggle('active',x==b));
 $('who').textContent='Logged in as '+b.textContent.trim();$('athletePanel').classList.toggle('hidden',role!=='athlete');refresh()});
async function submitData(){try{await api('/demo/submit','POST',{heart_rate:+$('hr').value,fatigue_index:+$('fi').value,glucose_level:+$('gl').value,injury_risk:+$('ir').value});$('msg').textContent='Encrypted & stored ✔';refresh()}catch(e){$('msg').textContent=e.message}}
async function toggleConsent(){if(role!=='athlete'){alert('Only the athlete can change consent.');return}
 await api('/demo/consent','POST',{consent:!consent});refresh()}
async function status(){const c=await api('/demo/consent');consent=c.consent;
 $('sw').classList.toggle('on',consent);$('cs').textContent=consent?'Consent ON':'Consent OFF';$('cs').className='badge '+(consent?'ok':'bad');
 const a=await api('/demo/audit');$('audit').innerHTML=a.map(r=>'<tr><td>'+Object.values(r).slice(0,6).join('</td><td>')+'</td></tr>').join('')}
async function refresh(){await status();
 if(!role)return;const v=await api('/demo/view','POST',{role}),el=$('view');
 if(v.status==='empty'){el.textContent='No data yet.';$('vb').textContent=''}
 else if(v.status==='decrypted'){$('vb').textContent='Decrypted (HTTP 200)';$('vb').className='badge ok';const d=v.data;
  el.innerHTML='<div class="kv"><div>Heart rate<b>'+d.heart_rate+' bpm</b></div><div>Fatigue<b>'+d.fatigue_index+'</b></div><div>Glucose<b>'+d.glucose_level+'</b></div><div>Injury risk<b>'+d.injury_risk+'</b></div></div>'}
 else{$('vb').textContent='HTTP '+v.http+' · encrypted';$('vb').className='badge bad';el.innerHTML=v.detail+'<code>'+v.ciphertext+'</code>'}
 const a=await api('/demo/audit');$('audit').innerHTML=a.map(r=>'<tr><td>'+Object.values(r).slice(0,6).join('</td><td>')+'</td></tr>').join('')}
setInterval(status,3000);status();
</script></body></html>"""

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
