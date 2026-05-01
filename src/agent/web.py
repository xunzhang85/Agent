"""
CTF Agent Web Dashboard (Optimized)

Enhanced with real-time solve progress, better UI, challenge history,
and API endpoints for integration.
"""

import json
import asyncio
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from pathlib import Path

logger = logging.getLogger(__name__)

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🤖 CTF Agent - AI-Powered CTF Auto-Solver</title>
    <style>
        :root{--bg:#0a0e14;--card:#111820;--border:#1e2a3a;--text:#d4dae3;--dim:#6b7d93;--accent:#3b82f6;--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--purple:#8b5cf6;--cyan:#06b6d4}
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans SC',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
        .container{max-width:1400px;margin:0 auto;padding:20px}
        header{text-align:center;padding:32px 0 24px;border-bottom:1px solid var(--border);margin-bottom:24px}
        header h1{font-size:2.2em;background:linear-gradient(135deg,var(--accent),var(--purple),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px;letter-spacing:-0.5px}
        header p{color:var(--dim);font-size:0.95em}
        .badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:0.75em;font-weight:600;margin-left:8px}
        .badge-green{background:rgba(16,185,129,0.15);color:var(--green);border:1px solid rgba(16,185,129,0.3)}
        .stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}
        .stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center;transition:border-color 0.2s}
        .stat:hover{border-color:var(--accent)}
        .stat .num{font-size:1.8em;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
        .stat .lbl{color:var(--dim);font-size:0.8em;margin-top:4px}
        .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
        @media(max-width:900px){.stats{grid-template-columns:repeat(3,1fr)}.grid{grid-template-columns:1fr}}
        .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;overflow:hidden}
        .card h2{font-size:1.1em;margin-bottom:14px;display:flex;align-items:center;gap:8px;color:var(--text)}
        .form-group{margin-bottom:14px}
        .form-group label{display:block;margin-bottom:5px;color:var(--dim);font-size:0.82em;font-weight:500;text-transform:uppercase;letter-spacing:0.5px}
        input,select,textarea{width:100%;padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:13px;font-family:inherit;transition:border-color 0.2s}
        input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px rgba(59,130,246,0.15)}
        textarea{resize:vertical;min-height:70px}
        select{cursor:pointer}
        .btn{display:inline-flex;align-items:center;gap:6px;padding:10px 20px;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;transition:all 0.15s}
        .btn-primary{background:linear-gradient(135deg,var(--accent),var(--purple));color:#fff}
        .btn-primary:hover{opacity:0.9;transform:translateY(-1px);box-shadow:0 4px 12px rgba(59,130,246,0.3)}
        .btn-primary:disabled{opacity:0.4;cursor:not-allowed;transform:none;box-shadow:none}
        .btn-sm{padding:6px 12px;font-size:12px}
        .output{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;min-height:160px;max-height:450px;overflow-y:auto;font-family:'JetBrains Mono','Fira Code',monospace;font-size:12px;line-height:1.7;white-space:pre-wrap;word-break:break-all}
        .output .log-line{padding:2px 0;border-bottom:1px solid rgba(30,42,58,0.5)}
        .output .log-plan{color:var(--cyan)}
        .output .log-exec{color:var(--green)}
        .output .log-error{color:var(--red)}
        .output .log-flag{color:var(--yellow);font-weight:700;font-size:1.1em}
        .output .log-hint{color:var(--purple)}
        .tool-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:6px}
        .tool{display:flex;align-items:center;gap:5px;padding:6px 10px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font-size:0.78em;transition:border-color 0.2s}
        .tool:hover{border-color:var(--accent)}
        .dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
        .dot-on{background:var(--green);box-shadow:0 0 6px var(--green)}
        .dot-off{background:var(--red);opacity:0.5}
        .arch{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;font-family:monospace;font-size:11px;line-height:1.5;overflow-x:auto;white-space:pre;color:var(--dim)}
        .spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 0.7s linear infinite}
        @keyframes spin{to{transform:rotate(360deg)}}
        .pulse{animation:pulse 2s infinite}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
        footer{text-align:center;padding:24px 0;color:var(--dim);font-size:0.78em;border-top:1px solid var(--border);margin-top:32px}
        footer a{color:var(--accent);text-decoration:none}
        .hidden{display:none}
        .tabs{display:flex;gap:4px;margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:8px}
        .tab{padding:6px 14px;border-radius:6px 6px 0 0;font-size:0.82em;cursor:pointer;color:var(--dim);transition:all 0.15s}
        .tab:hover{color:var(--text);background:rgba(59,130,246,0.05)}
        .tab.active{color:var(--accent);background:rgba(59,130,246,0.1);border-bottom:2px solid var(--accent)}
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>🤖 CTF Agent <span class="badge badge-green">v0.2</span></h1>
        <p>AI-Powered Multi-Agent CTF Auto-Solver &nbsp;|&nbsp; Planner · Executor · Reviewer</p>
    </header>

    <div class="stats">
        <div class="stat"><div class="num" id="sTool">-</div><div class="lbl">Tools Ready</div></div>
        <div class="stat"><div class="num" id="sTotal">0</div><div class="lbl">Challenges</div></div>
        <div class="stat"><div class="num" id="sSolved">0</div><div class="lbl">Solved</div></div>
        <div class="stat"><div class="num" id="sRate">-</div><div class="lbl">Success Rate</div></div>
        <div class="stat"><div class="num">3</div><div class="lbl">Agent Roles</div></div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>🎯 Solve Challenge</h2>
            <form id="solveForm">
                <div class="form-group">
                    <label>Target URL</label>
                    <input type="text" id="fUrl" placeholder="http://challenge.ctf.com">
                </div>
                <div class="form-group">
                    <label>Challenge Description / Hints</label>
                    <textarea id="fText" placeholder="Paste challenge description, hints, or any context..."></textarea>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
                    <div class="form-group">
                        <label>Category</label>
                        <select id="fCat">
                            <option value="auto">🔍 Auto Detect</option>
                            <option value="web">🌐 Web</option>
                            <option value="crypto">🔐 Crypto</option>
                            <option value="pwn">💥 Pwn</option>
                            <option value="reverse">🔄 Reverse</option>
                            <option value="forensics">🔬 Forensics</option>
                            <option value="misc">📦 Misc</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Model</label>
                        <select id="fModel">
                            <option value="gpt-4o">GPT-4o</option>
                            <option value="gpt-4o-mini">GPT-4o Mini</option>
                            <option value="claude-3-5-sonnet">Claude 3.5 Sonnet</option>
                            <option value="deepseek-chat">DeepSeek</option>
                        </select>
                    </div>
                </div>
                <div style="display:flex;gap:8px;align-items:center">
                    <button type="submit" class="btn btn-primary" id="solveBtn">🚀 Solve</button>
                    <label style="font-size:0.82em;color:var(--dim);display:flex;align-items:center;gap:4px;cursor:pointer">
                        <input type="checkbox" id="fStream" checked> Stream
                    </label>
                </div>
            </form>
            <div id="resultBox" class="hidden" style="margin-top:14px">
                <div class="output" id="solveLog"></div>
            </div>
        </div>

        <div class="card">
            <div class="tabs">
                <div class="tab active" data-tab="tools">🔧 Tools</div>
                <div class="tab" data-tab="arch">📐 Architecture</div>
            </div>
            <div id="tab-tools">
                <div class="tool-grid" id="toolGrid"><div style="color:var(--dim)">Loading...</div></div>
            </div>
            <div id="tab-arch" class="hidden">
                <div class="arch">┌───────────────────────────────────────────────────┐
│              CTF Agent Framework v0.2              │
├───────────┬──────────────┬────────────┬────────────┤
│  Planner  │   Executor   │  Reviewer  │   Memory   │
│  (LLM)    │   (Async)    │  (Flags)   │ (SQLite)   │
│           │              │            │            │
│ Few-shot  │ Parallel     │ Weighted   │ Persistent │
│ CoT       │ Cached       │ Pattern    │ Search     │
│ Streaming │ Sandboxed    │ B64 Check  │ Compress   │
├───────────┴──────────────┴────────────┴────────────┤
│                  Plugin System                      │
├────────┬────────┬────────┬────────┬────────────────┤
│  Web   │ Crypto │  Pwn   │Reverse │   Forensics    │
│ 6 tools│ 3 tools│ 3 tools│ 3 tools│   5 tools      │
└────────┴────────┴────────┴────────┴────────────────┘

Solve: Input → Classify → [Plan → Execute → Review] × N → Flag!</div>
            </div>
        </div>
    </div>

    <div class="card" style="margin-top:16px">
        <h2>📊 Recent Solves</h2>
        <div id="historyTable" style="color:var(--dim);font-size:0.85em">No solves yet</div>
    </div>

    <footer>
        CTF Agent v0.2.0 &nbsp;|&nbsp; <a href="https://github.com/xunzhang85/Agent">GitHub</a> &nbsp;|&nbsp; Powered by Multi-Agent LLM Architecture
    </footer>
</div>

<script>
const $=s=>document.querySelector(s);
const API='';
let solveHistory=[];

// Tabs
document.querySelectorAll('.tab').forEach(t=>{
    t.addEventListener('click',()=>{
        document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
        t.classList.add('active');
        document.querySelectorAll('[id^="tab-"]').forEach(x=>x.classList.add('hidden'));
        $('#tab-'+t.dataset.tab).classList.remove('hidden');
    });
});

// Load tools
fetch(API+'/api/tools').then(r=>r.json()).then(data=>{
    const ready=data.filter(t=>t.installed).length;
    $('#sTool').textContent=ready+'/'+data.length;
    $('#toolGrid').innerHTML=data.map(t=>
        `<div class="tool"><span class="dot ${t.installed?'dot-on':'dot-off'}"></span>${t.name}</div>`
    ).join('');
}).catch(()=>$('#toolGrid').innerHTML='<div style="color:var(--red)">Failed to load</div>');

// Solve
$('#solveForm').addEventListener('submit',async e=>{
    e.preventDefault();
    const btn=$('#solveBtn'),log=$('#solveLog'),box=$('#resultBox');
    btn.disabled=true;btn.innerHTML='<span class="spinner"></span> Solving...';
    box.classList.remove('hidden');log.innerHTML='';
    const url=$('#fUrl').value,text=$('#fText').value,cat=$('#fCat').value,model=$('#fModel').value;

    addLog('🧠 Analyzing challenge...','log-plan');

    try{
        const resp=await fetch(API+'/api/solve',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({url,text,category:cat==='auto'?null:cat,model})});
        const data=await resp.json();

        if(data.success){
            addLog('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━','log-line');
            addLog('✅ FLAG: '+data.flag,'log-flag');
            addLog('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━','log-line');
            addLog(`Category: ${data.category} | Iterations: ${data.iterations} | Time: ${data.elapsed_time?.toFixed(1)}s`,'log-exec');
            $('#sSolved').textContent=parseInt($('#sSolved').textContent)+1;
            solveHistory.unshift({flag:data.flag,category:data.category,success:true});
        }else{
            addLog('❌ Failed: '+data.error,'log-error');
            addLog(`Iterations: ${data.iterations} | Time: ${data.elapsed_time?.toFixed(1)||0}s`,'log-line');
            solveHistory.unshift({category:data.category,success:false});
        }
        if(data.steps)data.steps.forEach((s,i)=>addLog(`  ${i+1}. ${s}`,'log-line'));
        updateStats();
    }catch(err){
        addLog('Error: '+err.message,'log-error');
    }
    btn.disabled=false;btn.innerHTML='🚀 Solve';
});

function addLog(text,cls=''){
    const log=$('#solveLog');
    const d=document.createElement('div');
    d.className='log-line '+(cls||'');
    d.textContent=text;
    log.appendChild(d);
    log.scrollTop=log.scrollHeight;
}

function updateStats(){
    const t=solveHistory.length,s=solveHistory.filter(x=>x.success).length;
    $('#sTotal').textContent=t;
    $('#sSolved').textContent=s;
    $('#sRate').textContent=t?Math.round(s/t*100)+'%':'-';
    $('#historyTable').innerHTML=solveHistory.slice(0,10).map((h,i)=>
        `<div style="padding:4px 0;border-bottom:1px solid var(--border)">${h.success?'✅':'❌'} ${h.category||'?'} — ${h.flag||'failed'}</div>`
    ).join('')||'No solves yet';
}
</script>
</body>
</html>"""


class WebHandler(BaseHTTPRequestHandler):
    """HTTP handler for web dashboard."""

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._respond(200, "text/html", HTML_TEMPLATE)
        elif self.path == "/api/tools":
            from agent.tools.registry import ToolRegistry
            self._respond(200, "application/json", json.dumps(ToolRegistry().list_tools()))
        elif self.path == "/api/health":
            self._respond(200, "application/json", json.dumps({"status": "ok", "version": "0.2.0"}))
        elif self.path == "/api/history":
            results = []
            results_dir = Path("results")
            if results_dir.exists():
                for f in sorted(results_dir.glob("*.json")):
                    try:
                        data = json.loads(f.read_text())
                        if isinstance(data, list):
                            results.extend(data)
                        else:
                            results.append(data)
                    except Exception:
                        pass
            self._respond(200, "application/json", json.dumps(results[-50:]))
        else:
            self._respond(404, "text/plain", "Not Found")

    def do_POST(self):
        if self.path == "/api/solve":
            content_length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_length))

            from agent.core.agent import CTFAgent
            agent = CTFAgent(model=body.get("model", "gpt-4o"))

            result = agent.solve(
                challenge_url=body.get("url"),
                challenge_text=body.get("text"),
                category=body.get("category"),
            )
            self._respond(200, "application/json", json.dumps(result.to_dict()))
        else:
            self._respond(404, "text/plain", "Not Found")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _respond(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {format % args}")


def start_web(port: int = 8080, host: str = "0.0.0.0"):
    """Start the web dashboard."""
    server = HTTPServer((host, port), WebHandler)
    print(f"\n  🌐 CTF Agent Web Dashboard")
    print(f"  ➜ Local:   http://localhost:{port}")
    print(f"  ➜ Network: http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  👋 Shutting down...")
        server.shutdown()
