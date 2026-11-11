#!/usr/bin/env python3
"""WAF Dashboard - web GUI for waf_demo_manager.py (same folder). Standard library only.

Run on the Server VM:   sudo python3 waf_dashboard.py            (http://127.0.0.1:9000)
Reach it from the host: sudo python3 waf_dashboard.py --host 0.0.0.0   (no login - isolated lab network only!)
Everything the CLI menu does is available; the CLI itself is unchanged.
"""
import argparse, collections, contextlib, hmac, io, json, secrets, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import waf_demo_manager as W

ANSI = W.ANSI_RE
ACTIONS = {  # id -> (Lab method, needs_confirm)
    "setup": (lambda l, p: l.setup(), False),
    "protection_on": (lambda l, p: l.set_protection(True), False),
    "protection_off": (lambda l, p: l.set_protection(False), False),
    "paranoia": (lambda l, p: l.set_paranoia(int(p.get("level", 1))), False),
    "demo": (lambda l, p: l.guided_demo(), False),
    "summary": (lambda l, p: l.logs_summary(), False),
    "raw": (lambda l, p: l.logs_raw(), False),
    "cheatsheet": (lambda l, p: l.cheat_sheet(), False),
    "clear_logs": (lambda l, p: l.clear_logs(), False),
    "config": (lambda l, p: l.show_config(), False),
    "repair": (lambda l, p: l.repair(), False),
    "reset": (lambda l, p: l.reset(), True),
}

class Jobs:
    """Runs one CLI action at a time in a thread and captures what it prints."""
    def __init__(self, lab):
        self.lab, self.lock = lab, threading.Lock()
        self.job = {"name": "", "running": False, "output": "", "ok": None, "ts": 0}

    def start(self, name, params):
        if not self.lock.acquire(blocking=False):
            return False
        self.job = {"name": name, "running": True, "output": "", "ok": None, "ts": time.time()}
        threading.Thread(target=self._run, args=(name, params), daemon=True).start()
        return True

    def _run(self, name, params):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                ACTIONS[name][0](self.lab, params)
            ok = True
        except BaseException as e:          # CLI code may call sys.exit
            buf.write(f"\n[ERROR] {e}\n"); ok = False
        self.job.update(output=ANSI.sub("", buf.getvalue()), ok=ok, running=False)
        self.lock.release()

def status(lab):
    s = lab.s
    names = {"waf": W.WAF_CONTAINER, "target": W.TARGET_CONTAINER}
    try:
        cont = {k: lab.cstate(v) for k, v in names.items()}
    except Exception:
        cont = {k: "unknown" for k in names}
    host, port = lab.attacker_host(), s.get("waf_port")
    site = W.http_get(f"http://{host}:{port}/", 2) if cont["waf"] == "running" else None
    return {"url": f"http://{host}:{port}", "site": site, "installed": bool(s.get("installed", True)), "containers": cont,
            "protection": s.get("rule_engine") == "On", "paranoia": s.get("paranoia", 1),
            "port": port, "host": host,
            "version": W.VERSION}

def events(lab, n=300):
    try:
        ev, src = lab.fetch_events(3000)
    except Exception as e:
        return {"events": [], "source": str(e), "stats": {}}
    ev = ev[-n:]
    c = collections.Counter(e["verdict"] for e in ev)
    t = collections.Counter(e["attack"] for e in ev if e["verdict"] != "ALLOWED")
    for e in ev:
        e["rules"] = [list(r) if isinstance(r, (list, tuple)) else r for r in e.get("rules", [])]
    return {"events": ev[::-1], "source": src, "stats": {"verdicts": c, "types": t.most_common(8)}}

def make_handler(lab, jobs, token):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body, default=list)).encode()
            self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(data)
        def _auth(self):
            o = self.headers.get("Origin")          # no login: just block cross-site requests
            return not o or urlparse(o).netloc == self.headers.get("Host", "")
        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/":
                return self._send(200, PAGE, "text/html")
            if not self._auth():
                return self._send(401, {"error": "bad token"})
            if u.path == "/api/status":
                return self._send(200, status(lab))
            if u.path == "/api/events":
                return self._send(200, events(lab))
            if u.path == "/api/job":
                return self._send(200, jobs.job)
            self._send(404, {"error": "not found"})
        def do_POST(self):
            u = urlparse(self.path)
            if not self._auth():
                return self._send(401, {"error": "bad token"})
            name = u.path.rsplit("/", 1)[-1]
            if not u.path.startswith("/api/run/") or name not in ACTIONS:
                return self._send(404, {"error": "unknown action"})
            params = {k: v[0] for k, v in parse_qs(u.query).items()}
            started = jobs.start(name, params)
            self._send(200 if started else 409,
                       {"started": name} if started else {"error": "another action is running"})
    return H

def main():
    ap = argparse.ArgumentParser(description="WAF web dashboard")
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--dry-run", action="store_true"); a = ap.parse_args()
    if not W.IS_ROOT and not a.dry_run:
        print("Run with sudo so Docker can be installed/managed: sudo python3 waf_dashboard.py"); return 1
    W.LAB_HOME.mkdir(parents=True, exist_ok=True)
    args = W.parse_args(["--yes", "--accept-risk"] + (["--dry-run"] if a.dry_run else []))
    lab = W.Lab(args); lab.reconcile()
    token = None
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(lab, Jobs(lab), token))
    print(f"\nWAF Dashboard:  http://{a.host}:{a.port}\n(Ctrl+C to stop)\n")
    try: srv.serve_forever()
    except KeyboardInterrupt: print()
    return 0

PAGE = r"""<!doctype html><html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Dashboard</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Cutive+Mono&display=swap" rel="stylesheet">
<style>
:root{--bg:#0b1220;--bg2:#16233b;--card:#111b2e;--tx:#f8fafc;--mu:#b3c0d4;--bd:#2f4063;--ok:#34d399;--bad:#fb7185;--wn:#fbbf24;--ac:#fbbf24;--info:#7db3ff;--pur:#c4b5fd;--brand:#2563eb;--onbrand:#fff;--onac:#0b1220}
:root[data-theme=light]{--bg:#f3f5f9;--bg2:#f6f8fb;--card:#fff;--tx:#0f172a;--mu:#475569;--bd:#cfd7e3;--ok:#0f7b4a;--bad:#c62b3d;--wn:#b45309;--ac:#b45309;--info:#1d4ed8;--pur:#6d3fc4;--brand:#1d4ed8;--onac:#fff}
body[data-state=on]{--ac:var(--ok)}body[data-state=off]{--ac:var(--wn)}body[data-state=down]{--ac:var(--bad)}
[hidden]{display:none!important}*{box-sizing:border-box}html{color-scheme:dark}html[data-theme=light]{color-scheme:light}
body{margin:0;color:var(--tx);font:15px/1.55 'Cutive Mono','Courier New',monospace;-webkit-text-stroke:.3px currentColor;background:var(--bg)}
.app{display:grid;grid-template-columns:272px 1fr;min-height:100vh}
aside{--tx:#f1f5f9;--mu:#a9b6cc;--bd:#2a3c61;--bg2:#17284a;--ok:#4ade80;--bad:#ff8593;--wn:#fbbf24;--brand:#7db3ff;--ac:#7db3ff;background:#0e1a33;color:var(--tx);position:sticky;top:0;height:100vh;overflow:auto;display:flex;flex-direction:column;padding:22px 16px}
body[data-state=on] aside{--state:#4ade80}body[data-state=off] aside{--state:#fbbf24}body[data-state=down] aside{--state:#ff8593}
@media(max-width:900px){.app{grid-template-columns:1fr}aside{position:static;height:auto}}
.brand{display:flex;align-items:center;gap:12px;padding:0 4px 20px;margin-bottom:16px;border-bottom:1px solid var(--bd)}
.logo{color:var(--state,#7db3ff);flex:none}.brand b{display:block;font-weight:400;font-size:20px;letter-spacing:.05em;line-height:1.2}.brand small{display:block;color:var(--mu);font-size:12px}
nav a{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;margin:1px 0;border-radius:6px;color:var(--tx);cursor:pointer;text-decoration:none;opacity:.88}
nav a:hover{background:var(--bg2);opacity:1}nav a.on{background:var(--brand);color:#0e1a33;opacity:1}nav a.dng{color:var(--bad)}nav a.dng.on{color:#0e1a33}
nav a.one{border:1px solid var(--bd);padding:10px 12px;margin:0 0 10px}
.gb{width:100%;display:flex;align-items:center;gap:12px;margin:6px 0 2px;padding:10px 12px;border-radius:6px;background:transparent;border:1px solid var(--bd);color:var(--tx);font-size:15px;text-align:left}
.gb:hover:not(:disabled){background:var(--bg2);border-color:var(--brand);color:var(--tx)}.gb .gt{flex:1}.chev{transition:.2s;color:var(--mu)}.grp.open .gb{border-color:var(--brand)}.grp.open .chev{transform:rotate(180deg)}
.gn{width:22px;height:22px;border-radius:4px;background:var(--bg2);border:1px solid var(--bd);display:grid;place-items:center;font-size:12px;color:var(--mu)}
.opts{display:none;padding:4px 0 6px 10px;margin:2px 0 4px 22px;border-left:1px solid var(--bd)}.grp.open .opts{display:block}
.bdg{font-size:12px;background:#0b1428;border:1px solid var(--bd);border-radius:4px;padding:0 7px;color:var(--mu)}nav a.on .bdg{background:#0e1a33;color:#fff;border-color:#0e1a33}
.sf{margin-top:auto;padding-top:18px;display:flex;flex-direction:column;gap:10px;font-size:13px}.sf button{background:transparent}
main{padding:24px 32px 44px;min-width:0}
.top{display:flex;align-items:center;gap:16px;flex-wrap:wrap;background:var(--card);border:1px solid var(--bd);border-left:5px solid var(--ac);border-radius:8px;padding:14px 18px;margin-bottom:22px}
.top .g{flex:1;min-width:240px}.lbl{font-size:12px;letter-spacing:.14em;color:var(--mu);text-transform:uppercase}
.url{font-size:clamp(18px,2.4vw,26px);color:var(--info);text-decoration:none;word-break:break-all}.url:hover{text-decoration:underline}
h1.t{margin:0 0 4px;font-size:28px;font-weight:400}.sub{color:var(--mu);margin:0 0 18px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:18px;min-width:0}
h2{margin:0 0 12px;font-size:13px;font-weight:400;letter-spacing:.12em;text-transform:uppercase;color:var(--mu);display:flex;justify-content:space-between;gap:8px}
.mu{color:var(--mu)}.ok{color:var(--ok)}.bad{color:var(--bad)}.wn{color:var(--wn)}
.pill{display:inline-flex;align-items:center;gap:7px;padding:2px 10px;border-radius:4px;border:1px solid currentColor;font-size:13px;white-space:nowrap}.pill::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor}
button,select,input{font:inherit;padding:8px 14px;border-radius:6px;border:1px solid var(--bd);background:var(--card);color:var(--tx);transition:background .15s,border-color .15s}
button{cursor:pointer}button:hover:not(:disabled){border-color:var(--brand);color:var(--info)}button:disabled{opacity:.45;cursor:wait}
button.p{background:var(--brand);border-color:var(--brand);color:var(--onbrand)}button.p:hover:not(:disabled){color:var(--onbrand);filter:brightness(1.12)}
button.d{color:var(--bad);border-color:var(--bad)}button.d:hover:not(:disabled){background:var(--bad);color:#fff}
button.act{background:var(--brand);border-color:var(--brand);color:var(--onbrand)}input:focus,select:focus{outline:2px solid var(--brand);outline-offset:1px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.g3{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));margin-bottom:16px}.g2{display:grid;gap:16px;grid-template-columns:minmax(260px,1fr) 2fr;align-items:start}@media(max-width:1100px){.g2{grid-template-columns:1fr}}.stack{display:grid;gap:16px}
.g3 .card{border-top:4px solid var(--bd)}.g3 .card:nth-child(1){border-top-color:var(--ac)}.g3 .card:nth-child(2){border-top-color:var(--bad)}.g3 .card:nth-child(3){border-top-color:var(--wn)}.g3 .card:nth-child(4){border-top-color:var(--ok)}
.big{font-size:38px;line-height:1.1}#types{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:4px 28px}.bar{height:6px;border-radius:2px;background:var(--brand);margin:3px 0 10px}
.sw{position:relative;width:68px;height:36px;border-radius:99px;border:0;padding:0;background:var(--wn)}.sw.on{background:var(--ok)}
.sw::after{content:"";position:absolute;top:4px;left:4px;width:28px;height:28px;border-radius:50%;background:#fff;transition:.18s}.sw.on::after{left:36px}
pre{margin:14px 0 0;background:#0b1220;color:#86efac;border:1px solid var(--bd);border-radius:6px;padding:14px;max-height:600px;overflow:auto;font:14px/1.55 'Cutive Mono','Courier New',monospace;white-space:pre-wrap}
.spin{width:14px;height:14px;border-radius:50%;border:2px solid var(--bd);border-top-color:var(--brand);animation:sp .8s linear infinite;display:inline-block}@keyframes sp{to{transform:rotate(360deg)}}
.empty{display:grid;place-items:center;text-align:center;color:var(--mu);border:1px dashed var(--bd);border-radius:6px;padding:26px}
.fl{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}.fl input{flex:1;min-width:150px}.seg{display:flex}
.seg button{border-radius:0;margin-left:-1px;padding:7px 14px}.seg button:first-child{border-radius:6px 0 0 6px;margin:0}.seg button:last-child{border-radius:0 6px 6px 0}
.pks{display:flex;flex-direction:column;gap:8px;max-height:calc(100vh - 300px);min-height:200px;overflow:auto}
.pk{background:var(--bg2);border:1px solid var(--bd);border-left:5px solid var(--c);border-radius:6px;padding:10px 14px;cursor:pointer}
.pk.BLOCKED{--c:var(--bad)}.pk.WB,.pk.FLAGGED{--c:var(--wn)}.pk.ALLOWED{--c:var(--ok)}.pk:hover{border-color:var(--c)}
.t1,.t2{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.t2{margin-top:5px;font-size:14px;color:var(--mu)}.t1 .a{font-size:16px}.path{flex:1;min-width:120px;word-break:break-all;color:var(--tx)}
.m{padding:0 8px;border-radius:4px;font-size:13px;border:1px solid currentColor}.m.GET{color:var(--info)}.m.POST{color:var(--pur)}.m.o{color:var(--wn)}
.vd{padding:2px 10px;border-radius:4px;font-size:13px;background:var(--c);color:var(--onac);white-space:nowrap;margin-left:auto}
.chip{padding:0 8px;border-radius:4px;font-size:13px;border:1px solid var(--bd)}.chip.at{color:var(--wn);border-color:var(--wn)}
.chip.r{cursor:pointer;color:var(--info);border-color:var(--info)}.chip.r:hover{background:var(--info);color:var(--card)}
.sc{width:64px;height:6px;border-radius:2px;background:var(--bd);overflow:hidden;display:inline-block}.sc i{display:block;height:100%;background:var(--c)}
.dt{display:none;margin-top:12px;border-top:1px solid var(--bd);padding-top:12px;cursor:default}.pk.open .dt{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.dt h4{margin:0 0 6px;font-size:12px;font-weight:400;letter-spacing:.14em;text-transform:uppercase;color:var(--mu)}
.kv{display:grid;grid-template-columns:110px 1fr;gap:3px 10px;font-size:14px}.kv span:nth-child(odd){color:var(--mu)}.kv span{word-break:break-all}
.pr{background:var(--card);border:1px solid var(--bd);border-radius:4px;padding:5px 9px;margin-bottom:5px;word-break:break-all;font-size:14px}.pr b{font-weight:400;color:var(--info)}.pr.hot{border-color:var(--bad);color:var(--bad)}
.rd{margin-bottom:6px;font-size:14px;word-break:break-word}.dt .full{grid-column:1/-1}
.hint{padding:10px 14px;border:1px solid var(--bd);border-left:4px solid var(--info);border-radius:6px;margin-bottom:12px;display:flex;gap:10px;justify-content:space-between;align-items:center;flex-wrap:wrap;background:var(--bg2)}
.rl{display:flex;flex-direction:column;gap:6px;max-height:calc(100vh - 250px);overflow:auto}
.rr{display:grid;grid-template-columns:1fr auto;gap:2px 10px;padding:9px 12px;border:1px solid var(--bd);border-radius:6px;background:var(--bg2);cursor:pointer;text-align:left;width:100%}
.rr:hover{border-color:var(--info)}.rr.on{border-color:var(--info);background:var(--card);box-shadow:inset 4px 0 0 var(--info)}.rr b{font-weight:400;color:var(--info)}.rr .c{color:var(--wn);font-size:18px;grid-row:1/span 2;grid-column:2}.rr span{color:var(--mu);font-size:13px}
</style></head><body data-state="down"><div class="app">
<aside><div class="brand"><svg class="logo" viewBox="0 0 32 36" width="34" height="38" aria-hidden="true"><path d="M16 1.5 3 6v10.5c0 8.2 5.5 15.2 13 18 7.5-2.8 13-9.8 13-18V6L16 1.5z" fill="currentColor"/><path d="M9.8 17.8l4.4 4.4 8.2-9.4" fill="none" stroke="#0e1a33" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg><div><b>WAF Console</b><small>ModSecurity + OWASP CRS</small></div></div>
<nav>
<a class="one" data-v="overview">Dashboard</a>
<div class="grp"><button class="gb"><span class="gn">1</span><span class="gt">Deploy</span><span class="chev">&#9662;</span></button><div class="opts"><a data-v="setup">Setup / Install</a><a data-v="repair">Repair</a></div></div>
<div class="grp"><button class="gb"><span class="gn">2</span><span class="gt">Protection</span><span class="chev">&#9662;</span></button><div class="opts"><a data-v="protection">Protection ON / OFF</a><a data-v="paranoia">Paranoia level</a></div></div>
<div class="grp"><button class="gb"><span class="gn">3</span><span class="gt">Test</span><span class="chev">&#9662;</span></button><div class="opts"><a data-v="cheatsheet">Attacker cheat-sheet</a></div></div>
<div class="grp"><button class="gb"><span class="gn">4</span><span class="gt">Monitor</span><span class="chev">&#9662;</span></button><div class="opts"><a data-v="live">Live attack view <span class="bdg" id="bl">0</span></a><a data-v="filter">Filter &amp; inspect</a><a data-v="rules">Violated rules <span class="bdg" id="br">0</span></a><a data-v="summary">Summary</a><a data-v="raw">Raw WAF log</a><a data-v="clear_logs">Clear logs</a></div></div>
<div class="grp"><button class="gb"><span class="gn">5</span><span class="gt">Maintain</span><span class="chev">&#9662;</span></button><div class="opts"><a data-v="config">Health check</a><a data-v="reset" class="dng">Reset / uninstall</a></div></div>
</nav>
<div class="sf"><span id="cont" class="row"></span><button onclick="theme()">Dark / light mode</button><span class="mu" id="ver"></span></div></aside>
<main><div class="top"><div class="g"><div class="lbl">Website URL (through the WAF)</div><a class="url" id="url" target="_blank" rel="noopener">-</a></div>
<div class="row"><span class="pill" id="site">checking</span><button class="p" onclick="window.open(U,'_blank')">Open website</button><button onclick="copyUrl(this)">Copy URL</button></div></div>
<div id="view"></div></main></div>
<script>
const $=id=>document.getElementById(id);let prot=false,U='#',EV=[],VIEW='',OUTN='',last=null,ST={},F={v:'all',t:'',q:'',r:''};const OPEN=new Set();
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const dec=s=>{try{return decodeURIComponent(String(s).replace(/\+/g,' '))}catch(_){return String(s)}};
const ACT={setup:['Setup / Install','Installs Docker if needed, pulls Juice Shop and the WAF, and starts the lab.',[['Run setup','setup','p']]],
repair:['Repair','Detects unreachable or stopped containers and fixes them.',[['Run repair','repair','p']]],
cheatsheet:['Attacker cheat-sheet','Ready-to-copy commands for the attacker machine (Kali).',[]],summary:['Summary','Blocked vs passed totals, by attack type, top rules.',[['Refresh','summary','']]],
raw:['Raw WAF log','Last lines of the WAF container log, for troubleshooting.',[['Refresh','raw','']]],clear_logs:['Clear logs','Removes old events so only new traffic is shown.',[['Clear logs now','clear_logs','p']]],
config:['Health check','Shows configuration and container health, with automatic repair.',[['Run again','config','']]],reset:['Reset / uninstall','Removes all lab containers. This cannot be undone.',[['Remove the lab','reset','d']]]};
const AUTO=['cheatsheet','summary','raw','config'];
const NAMES={protection_on:'Protection ON',protection_off:'Protection OFF',paranoia:'Paranoia level'};
function theme(){const r=document.documentElement,t=r.dataset.theme=='light'?'dark':'light';r.dataset.theme=t;try{localStorage.setItem('wafTheme',t)}catch(_){}}
try{document.documentElement.dataset.theme=localStorage.getItem('wafTheme')||'light'}catch(_){}
async function api(p,m='GET'){return (await fetch(p,{method:m})).json()}
function copyUrl(b){navigator.clipboard?.writeText(U);b.textContent='Copied';setTimeout(()=>b.textContent='Copy URL',1200)}
/* ---------- navigation ---------- */
const FV=['filter','rules'],ek=e=>e.uid||e.time+e.ip+e.uri;let SNAP=[],SNAPT='',PAUSED=false,LSNAP=[],SB='';
function snap(){SNAP=EV.slice();SNAPT=new Date().toLocaleTimeString()}
function go(v){const prev=VIEW;VIEW=v;document.querySelectorAll('nav a').forEach(a=>{const on=a.dataset.v==v;a.classList.toggle('on',on);const g=a.closest('.grp');if(on&&g){document.querySelectorAll('.grp').forEach(x=>x.classList.remove('open'));g.classList.add('open')}});
if(FV.includes(v)&&!FV.includes(prev))snap();if(v=='live'&&prev!='live')PAUSED=false;SB='';$('view').innerHTML=tpl(v);last=null;
if(OUTN&&$('out')&&(OUTN==v||(v=='protection'&&OUTN.startsWith('protection_'))))job();if(AUTO.includes(v))run(v);paint();draw(true)}
document.querySelector('nav').onclick=e=>{const g=e.target.closest('.gb');if(g){const p=g.parentNode,o=p.classList.contains('open');document.querySelectorAll('.grp').forEach(x=>x.classList.remove('open'));if(!o)p.classList.add('open');return}const a=e.target.closest('a');if(a)go(a.dataset.v)};
function pause(){PAUSED=!PAUSED;if(PAUSED)LSNAP=EV.slice();draw(true)}
const head=(t,d)=>`<h1 class="t">${t}</h1><p class="sub">${d}</p>`;
const outbox='<div class="row" style="margin-top:6px"><span id="pst"></span></div><pre id="out" hidden></pre>';
function tpl(v){
if(v=='overview')return head('Dashboard','Live status of the WAF and the traffic it has seen.')+`<div class="g3"><div class="card"><h2>Protection</h2><div class="big" id="sp">-</div><div class="mu">WAF mode</div></div><div class="card"><h2>Blocked</h2><div class="big bad" id="nb">0</div><div class="mu">attacks stopped (403)</div></div><div class="card"><h2>Passed</h2><div class="big wn" id="np">0</div><div class="mu">attacks logged only</div></div><div class="card"><h2>Allowed</h2><div class="big ok" id="na">0</div><div class="mu">normal requests</div></div></div>
<div class="stack"><div class="card"><h2>Attacks by type</h2><div id="types" class="mu">No attacks yet</div></div><div class="card"><h2><span>Latest packets</span><a class="mu" style="cursor:pointer" onclick="go('live')">open live view &rarr;</a></h2><div class="pks" id="pks" style="max-height:640px"></div></div></div>`;
if(v=='protection')return head('Protection ON / OFF','Switch the WAF between blocking (ON) and log-only (OFF).')+`<div class="card"><div class="row" style="gap:18px"><button id="sw" class="sw" onclick="toggle()" aria-label="Toggle protection"></button><div><div class="big" id="pt" style="font-size:26px"></div><div class="mu" id="pd"></div></div></div>${outbox}</div>`;
if(v=='paranoia')return head('Paranoia level','Higher levels catch more attacks but may block legitimate requests.')+`<div class="card"><div class="row"><select id="pl"><option value="1">1 - normal</option><option value="2">2 - stricter</option><option value="3">3 - strictest</option></select><button class="p ab" onclick="run('paranoia','level='+$('pl').value)">Apply</button></div>${outbox}</div>`;
if(v=='live')return head('Live attack view','Packets stream in as they arrive. Pause to read one, or open Filter &amp; inspect to search.')+`<div class="card"><h2><span id="src"></span><span id="cnt"></span></h2><div class="fl"><span class="pill ok" id="lv">streaming</span><button id="pz" onclick="pause()">&#10073;&#10073; Pause</button><button onclick="go('filter')">Filter &amp; inspect &rarr;</button></div><div class="pks" id="pks"></div></div>`;
const SNB='<div id="snap" class="hint"></div>';
if(v=='filter')return head('Filter &amp; inspect','This list is frozen while you filter, so nothing moves while you read the packet details.')+`<div class="card">${SNB}<div class="fl"><span class="seg" id="seg"><button data-v="all">All</button><button data-v="BLOCKED">Blocked</button><button data-v="PASSED">Passed</button><button data-v="ALLOWED">Allowed</button></span><select id="ft"></select><input id="fq" placeholder="Search IP, path, parameter..." value="${esc(F.q)}"></div><div id="hint" class="hint" hidden></div><h2><span id="src"></span><span id="cnt"></span></h2><div class="pks" id="pks"></div></div>`;
if(v=='rules')return head('Violated rules','Pick a rule to see only the packets that violated it. The list is frozen while you inspect.')+SNB+`<div class="g2"><div class="card"><h2><span>Rules</span><span id="rcnt"></span></h2><div class="rl" id="rl"></div></div><div class="card"><h2><span>Packets</span><span id="cnt"></span></h2><div id="hint" class="hint" hidden></div><div class="pks" id="pks"></div></div></div>`;
const a=ACT[v];return head(a[0],a[1])+`<div class="card"><div class="row">${a[2].map(b=>`<button class="${b[2]} ab" onclick="${v=='reset'?"if(confirm('Remove all lab containers?'))":''}run('${b[1]}')">${b[0]}</button>`).join('')||'<span class="mu">Loading...</span>'}</div>${outbox}</div>`}
/* ---------- run a task and show it on the right ---------- */
async function run(n,q=''){OUTN=n;last=null;if($('out')){$('out').hidden=false;$('out').textContent='Working...'}const r=await api('/api/run/'+n+(q?'?'+q:''),'POST');if(r.error)alert(r.error);job()}
function toggle(){if(confirm('Switch protection '+(prot?'OFF (log only)':'ON (block attacks)')+'? The WAF container restarts.'))run(prot?'protection_off':'protection_on')}
async function job(){const j=await api('/api/job');if(!j.name||j.name!=OUTN&&!j.running)return;const o=$('out');if(!o)return;o.hidden=false;
if(j.output!==last){o.textContent=j.output||'Working...';o.scrollTop=o.scrollHeight;last=j.output}
$('pst').innerHTML=j.running?'<span class="spin"></span> <span class="mu">working...</span>':(j.ok?'':'<span class="pill bad">failed</span>');
document.querySelectorAll('.ab,.sw').forEach(b=>b.disabled=j.running);if(j.running)setTimeout(job,1200);else refresh()}
/* ---------- packets ---------- */
function act(m,u){const p=u.split('?')[0].toLowerCase();
if(/\/rest\/user\/login/.test(p))return 'Login attempt';if(/\/rest\/user\/(change|reset)-password/.test(p))return 'Password change / reset';if(/\/rest\/user\/whoami/.test(p))return 'Session check';
if(/\/api\/users/.test(p))return m=='POST'?'User registration':'User lookup';if(/\/rest\/products\/search/.test(p))return 'Product search';if(/\/rest\/products\/\d+\/reviews/.test(p))return 'Product review';
if(/\/api\/(products|quantitys)/.test(p))return 'Product API';if(/\/(rest\/basket|api\/basketitems)/.test(p))return 'Basket';if(/\/api\/feedbacks/.test(p))return m=='POST'?'Feedback submit':'Feedback list';
if(/\/rest\/(track-order|order)/.test(p))return 'Order tracking';if(/\/(ftp|\.git|\.env)|\.\.\/|etc\/passwd/.test(p))return 'File / path access';if(/\/(administration|admin)/.test(p))return 'Admin access';
if(/\/(socket\.io|rest\/admin)/.test(p))return 'Realtime / admin API';if(/^\/?$|\.(js|css|png|ico|svg|jpe?g|woff2?|map)$/.test(p))return 'Page / static load';return (m||'Request')+' request'}
const EXP={BLOCKED:'WAF answered 403. The request never reached Juice Shop.','WOULD BLOCK':'Score reached the threshold, but protection is OFF so it was forwarded (logged only).',FLAGGED:'A rule matched but the score stayed below the threshold, so it was forwarded.',ALLOWED:'No rule matched. Normal request, forwarded.'};
const VL={BLOCKED:'BLOCKED (403)','WOULD BLOCK':'PASSED - logged only',FLAGGED:'PASSED - flagged',ALLOWED:'ALLOWED'},vc=v=>v=='WOULD BLOCK'?'WB':v;
const hot=s=>/['"<>;]|union\s|select\s|script|\.\.\/|--|\/\*|\bor\b\s*\d|%00|etc\/passwd/i.test(s);
function pk(e){const key=(e.uid||e.time+e.ip+e.uri),u=e.uri||'',[p,...qr]=u.split('?'),qs=qr.join('?'),sc=e.score==null?0:e.score,a=act(e.method,u),mt=['GET','POST'].includes(e.method)?e.method:'o';
const prm=qs?qs.split('&').filter(Boolean).map(x=>{const i=x.indexOf('='),k=i<0?x:x.slice(0,i),v=i<0?'':x.slice(i+1);return [dec(k),dec(v)]}):[];
return `<div class="pk ${vc(e.verdict)} ${OPEN.has(key)?'open':''}" data-k="${esc(key)}"><div class="t1"><span class="m ${mt}">${esc(e.method||'?')}</span><b class="a" style="font-weight:400">${esc(a)}</b><span class="vd">${VL[e.verdict]||esc(e.verdict)}</span></div>
<div class="t2"><span class="path">${esc(dec(p))}${prm.length?' <span class="wn">?'+esc(prm.map(x=>x[0]+'='+x[1]).join('&').slice(0,80))+'</span>':''}</span><span>${esc(e.time)||'--'}</span><span>from ${esc(e.ip)||'?'}</span>${e.verdict!='ALLOWED'?`<span class="chip at">${esc(e.attack)}</span>`:''}<span class="sc"><i style="width:${Math.min(100,sc/5*100)}%"></i></span><span>${sc}/5</span></div>
<div class="dt" onclick="event.stopPropagation()"><div><h4>Request</h4><div class="kv"><span>Action</span><span>${esc(a)}</span><span>Method</span><span>${esc(e.method||'?')}</span><span>Path</span><span>${esc(dec(p))}</span><span>Raw URL</span><span>${esc(u)}</span></div></div>
<div><h4>Parameters (${prm.length})</h4>${prm.map(x=>`<div class="pr ${hot(x[1])?'hot':''}"><b>${esc(x[0])}</b> = ${esc(x[1])}</div>`).join('')||'<span class="mu">No query parameters.<br>Request body is not stored in the WAF event.</span>'}</div>
<div><h4>Verdict</h4><div class="kv"><span>HTTP status</span><span>${esc(e.status||'?')}</span><span>Result</span><span>${VL[e.verdict]||esc(e.verdict)}</span><span>Attack type</span><span>${e.verdict=='ALLOWED'?'none':esc(e.attack)}</span><span>Anomaly score</span><span>${sc} / 5 threshold</span></div><p class="mu" style="margin:8px 0 0">${EXP[e.verdict]||''}</p></div>
<div><h4>Source</h4><div class="kv"><span>Attacker IP</span><span>${esc(e.ip)||'?'}</span><span>Time</span><span>${esc(e.time)||'--'}</span><span>Transaction</span><span>${esc(e.uid)||'-'}</span></div></div>
<div class="full"><h4>Rules violated (${e.rules.length})</h4>${e.rules.map(r=>`<div class="rd"><span class="chip r" onclick="setRule('${esc(r[0])}')">${esc(r[0])}</span> ${esc(r[1])}</div>`).join('')||'<span class="mu">None</span>'}</div></div></div>`}
$('view').onclick=e=>{const c=e.target.closest('.pk');if(c&&!e.target.closest('.dt')){c.classList.toggle('open');const k=c.dataset.k;c.classList.contains('open')?OPEN.add(k):OPEN.delete(k)}};
function rmap(l){const m={};l.forEach(e=>e.rules.forEach(r=>{(m[r[0]]=m[r[0]]||{id:r[0],t:r[1],n:0}).n++}));return m}
function snapBar(){const s=$('snap');if(!s)return;const have=new Set(SNAP.map(ek)),n=EV.filter(e=>!have.has(ek(e))).length;
const h=`<span><b class="wn" style="font-weight:400">&#10073;&#10073; Frozen</b> at ${SNAPT} &middot; ${SNAP.length} packets${n?` &middot; <b class="bad" style="font-weight:400">+${n} new packets waiting</b>`:''}</span><span class="row"><button class="p" onclick="snap();draw(true)">Refresh snapshot</button><button onclick="go('live')">Back to live view</button></span>`;if(h!==SB){SB=h;s.innerHTML=h}}
function draw(force){$('br').textContent=Object.keys(rmap(EV)).length;const L=$('pks');if(!L)return;const fv=FV.includes(VIEW),ov=VIEW=='overview',lv=VIEW=='live';
if(fv){snapBar();if(!force)return}if(lv&&PAUSED&&!force)return;
if(lv&&$('lv')){$('lv').className='pill '+(PAUSED?'wn':'ok');$('lv').textContent=PAUSED?'paused':'streaming';$('pz').innerHTML=PAUSED?'&#9654; Resume':'&#10073;&#10073; Pause'}
const pass=e=>e.verdict=='WOULD BLOCK'||e.verdict=='FLAGGED',src=fv?SNAP:(lv&&PAUSED?LSNAP:EV),st=L.scrollTop;
const base=ov?EV.slice(0,8):lv?src:src.filter(e=>(F.v=='all'||(F.v=='PASSED'?pass(e):e.verdict==F.v))&&(!F.t||e.attack==F.t)&&(!F.q||(e.ip+' '+dec(e.uri)).toLowerCase().includes(F.q))&&(!F.r||e.rules.some(r=>r[0]==F.r)));
if($('cnt'))$('cnt').textContent=base.length+' of '+src.length+' packets';
const rm=rmap(src),rs=Object.values(rm).sort((a,b)=>b.n-a.n);
L.innerHTML=(VIEW=='rules'&&!F.r)?'<div class="empty">Select a rule on the left to see its packets.</div>':base.slice(0,150).map(pk).join('')||'<div class="empty">No packets match.</div>';L.scrollTop=st;
if($('rcnt'))$('rcnt').textContent=rs.length+' rules';
if($('rl'))$('rl').innerHTML=rs.map(r=>`<button class="rr ${r.id==F.r?'on':''}" onclick="setRule('${esc(r.id)}')"><b>Rule ${esc(r.id)}</b><span>${esc((r.t||'').slice(0,110))}</span><div class="c">${r.n}</div></button>`).join('')||'<div class="mu">No rules triggered yet</div>';
const h=$('hint');if(h){h.hidden=!F.r;if(F.r){const r=rm[F.r];h.innerHTML=`<span>Showing only packets that violated <b class="wn" style="font-weight:400">rule ${esc(F.r)}</b>${r?': '+esc((r.t||'').slice(0,90)):''}</span><button onclick="setRule('')">Clear rule filter</button>`}}
const ft=$('ft');if(ft){const ty=[...new Set(src.filter(e=>e.verdict!='ALLOWED').map(e=>e.attack))].sort();ft.innerHTML='<option value="">All attack types</option>'+ty.map(t=>`<option ${t==F.t?'selected':''}>${esc(t)}</option>`).join('')}
document.querySelectorAll('#seg button').forEach(b=>b.classList.toggle('act',b.dataset.v==F.v))}
function setRule(id){F.r=F.r==id?'':id;draw(true)}
$('view').addEventListener('change',e=>{if(e.target.id=='ft'){F.t=e.target.value;draw(true)}});
$('view').addEventListener('input',e=>{if(e.target.id=='fq'){F.q=e.target.value.toLowerCase();draw(true)}});
$('view').addEventListener('click',e=>{const b=e.target.closest('#seg button');if(b){F.v=b.dataset.v;draw(true)}});
/* ---------- status polling ---------- */
function paint(){const s=ST;if(!s.version)return;const up=s.containers.waf=='running',v=(s.stats||{}).verdicts||{};
const set=(i,t)=>$(i)&&($(i).textContent=t);set('nb',v.BLOCKED||0);set('np',(v['WOULD BLOCK']||0)+(v.FLAGGED||0));set('na',v.ALLOWED||0);
set('sp',!up?'DOWN':prot?'ON':'OFF');if($('sp'))$('sp').style.color=!up?'var(--bad)':prot?'var(--ok)':'var(--wn)';
if($('sw')){$('sw').className='sw'+(prot?' on':'');set('pt',prot?'Protection ON':'Protection OFF');set('pd',prot?'Matched attacks get 403 and never reach Juice Shop.':'Attacks reach Juice Shop, but the WAF still logs them.');if(document.activeElement!=$('pl'))$('pl').value=s.paranoia}
const ty=(s.stats||{}).types||[],mx=Math.max(1,...ty.map(x=>x[1]));if($('types'))$('types').innerHTML=ty.length?ty.map(([k,c])=>`<div>${esc(k)} <b class="wn" style="font-weight:400">${c}</b><div class="bar" style="width:${c/mx*100}%"></div></div>`).join(''):'No attacks yet';
if($('src'))$('src').textContent=s.source?'Source: '+s.source:''}
async function refresh(){try{const s=await api('/api/status');prot=s.protection;const up=s.containers.waf=='running';
document.body.dataset.state=!up?'down':prot?'on':'off';$('ver').textContent='v'+s.version;
let u=s.url;if(['127.0.0.1','localhost'].includes(s.host)&&!['127.0.0.1','localhost'].includes(location.hostname))u='http://'+location.hostname+':'+s.port;
U=u;$('url').textContent=u;$('url').href=u;$('site').textContent=s.site?'online ('+s.site+')':up?'not responding':'stopped';$('site').className='pill '+(s.site&&s.site<500?'ok':'bad');
$('cont').innerHTML=Object.entries(s.containers).map(([k,v])=>`<span class="pill ${v=='running'?'ok':'bad'}">${k}: ${esc(v)}</span>`).join('');
const e=await api('/api/events');EV=e.events;$('bl').textContent=EV.length;ST=Object.assign(s,{stats:e.stats,source:e.source});paint();draw()}catch(_){}}
go('overview');refresh();setInterval(refresh,2500);
</script></body></html>"""

if __name__ == "__main__":
    sys.exit(main())
