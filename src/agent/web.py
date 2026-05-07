"""
CTF Agent Web Dashboard (Optimized)

Enhanced with real-time solve progress, better UI, challenge history,
and API endpoints for integration.
"""

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

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
        .toggles{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}
        .check{font-size:0.82em;color:var(--dim);display:flex;align-items:center;gap:5px;cursor:pointer}
        .check input{width:auto}
        .meta{color:var(--dim);font-size:0.78em;margin-bottom:10px;min-height:18px}
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
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px">
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
                            <option value="">Loading...</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Provider</label>
                        <select id="fProvider">
                            <option value="openai">OpenAI</option>
                            <option value="openai-compatible">OpenAI-compatible</option>
                            <option value="mimo">MiMo</option>
                            <option value="anthropic">Anthropic</option>
                            <option value="deepseek">DeepSeek</option>
                            <option value="ollama">Ollama</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Timeout</label>
                        <input type="number" id="fTimeout" min="10" max="3600" step="10" value="600">
                    </div>
                </div>
                <div class="meta" id="cfgMeta"></div>
                <div class="toggles">
                    <label class="check"><input type="checkbox" id="fNoCache"> No cache</label>
                    <label class="check"><input type="checkbox" id="fNoSandbox"> No sandbox</label>
                </div>
                <div style="display:flex;gap:8px;align-items:center">
                    <button type="submit" class="btn btn-primary" id="solveBtn">🚀 Solve</button>
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
const DEFAULT_MODELS=['gpt-4o','gpt-4o-mini','claude-3-5-sonnet','deepseek-chat','MiMo-V2.5-Pro'];

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

// Load runtime defaults and persisted history
fetch(API+'/api/config').then(r=>r.json()).then(data=>{
    const models=[data.model,...DEFAULT_MODELS].filter(Boolean);
    $('#fModel').innerHTML=[...new Set(models)].map(m=>`<option value="${m}">${m}</option>`).join('');
    $('#fModel').value=data.model||models[0];
    if(data.provider) $('#fProvider').value=data.provider;
    if(data.timeout) $('#fTimeout').value=data.timeout;
    $('#fNoSandbox').checked=data.sandbox_enabled===false;
    $('#cfgMeta').textContent=`Config: ${data.provider||'openai'} / ${data.model||'gpt-4o'}${data.base_url_configured?' / custom base_url':''}${data.api_key_configured?' / key set':' / no key'}`;
}).catch(()=>{
    $('#fModel').innerHTML=DEFAULT_MODELS.map(m=>`<option value="${m}">${m}</option>`).join('');
});

fetch(API+'/api/history').then(r=>r.json()).then(data=>{
    solveHistory=(Array.isArray(data)?data:[]).slice(-10).reverse();
    updateStats();
}).catch(()=>{});

// Solve
$('#solveForm').addEventListener('submit',async e=>{
    e.preventDefault();
    const btn=$('#solveBtn'),log=$('#solveLog'),box=$('#resultBox');
    btn.disabled=true;btn.innerHTML='<span class="spinner"></span> Solving...';
    box.classList.remove('hidden');log.innerHTML='';
    const url=$('#fUrl').value.trim(),text=$('#fText').value.trim(),cat=$('#fCat').value,model=$('#fModel').value,provider=$('#fProvider').value;
    const timeout=parseInt($('#fTimeout').value||'600',10),no_cache=$('#fNoCache').checked,sandbox_enabled=!$('#fNoSandbox').checked;

    addLog('🧠 Analyzing challenge...','log-plan');

    try{
        const resp=await fetch(API+'/api/solve',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({url,text,category:cat==='auto'?null:cat,model,provider,timeout,no_cache,sandbox_enabled})});
        const data=await resp.json();
        if(!resp.ok) throw new Error(data.error||'Request failed');

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
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._respond(200, "text/html", HTML_TEMPLATE)
        elif path == "/api/tools":
            from agent.tools.registry import ToolRegistry
            self._respond(200, "application/json", json.dumps(ToolRegistry().list_tools()))
        elif path == "/api/health":
            self._respond(200, "application/json", json.dumps({"status": "ok", "version": "0.2.0"}))
        elif path == "/api/config":
            self._respond(200, "application/json", json.dumps(self.server.safe_config()))
        elif path == "/api/history":
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
        path = urlparse(self.path).path
        if path == "/api/solve":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(content_length) or b"{}")
            except json.JSONDecodeError:
                self._respond(400, "application/json", json.dumps({"error": "Invalid JSON"}))
                return

            if not body.get("url") and not body.get("text"):
                self._respond(400, "application/json", json.dumps({"error": "Provide url or text"}))
                return

            from agent.core.agent import CTFAgent
            from agent.utils.config import load_config
            from agent.utils.config import get_bool, get_float, get_int

            config = load_config(getattr(self.server, "config_path", None))
            llm = config.get("llm", {})
            sandbox_cfg = config.get("sandbox", {})

            agent = CTFAgent(
                model=body.get("model") or llm.get("model") or "gpt-4o",
                provider=body.get("provider") or llm.get("provider") or "openai",
                api_key=llm.get("api_key"),
                base_url=llm.get("base_url"),
                temperature=get_float(config, ("llm", "temperature"), 0.1),
                max_tokens=get_int(config, ("llm", "max_tokens"), 4096),
                timeout=int(body.get("timeout") or get_int(config, ("agent", "timeout"), 600)),
                max_iterations=get_int(config, ("agent", "max_iterations"), 20),
                max_retries=get_int(config, ("agent", "max_retries"), 3),
                retry_on_failure=get_bool(config, ("agent", "retry_on_failure"), True),
                sandbox_enabled=body.get("sandbox_enabled", sandbox_cfg.get("enabled")),
                cache_enabled=not body.get("no_cache", False),
            )

            result = agent.solve(
                challenge_url=body.get("url"),
                challenge_text=body.get("text"),
                category=body.get("category"),
            )
            self._respond(200, "application/json", json.dumps(result.to_dict(), ensure_ascii=False))
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


class AgentHTTPServer(ThreadingHTTPServer):
    """HTTP server carrying runtime configuration path."""

    def __init__(self, server_address, handler_class, config_path=None):
        super().__init__(server_address, handler_class)
        self.config_path = config_path

    def safe_config(self) -> dict:
        from agent.utils.config import get_bool, get_int, load_config

        config = load_config(self.config_path)
        llm = config.get("llm", {})
        return {
            "model": llm.get("model") or "gpt-4o",
            "provider": llm.get("provider") or "openai",
            "timeout": get_int(config, ("agent", "timeout"), 600),
            "max_iterations": get_int(config, ("agent", "max_iterations"), 20),
            "sandbox_enabled": get_bool(config, ("sandbox", "enabled"), True),
            "api_key_configured": bool(llm.get("api_key")),
            "base_url_configured": bool(llm.get("base_url")),
        }


def start_web(port: int = 8080, host: str = "0.0.0.0", config_path: str | None = None):
    """Start the web dashboard."""
    server = AgentHTTPServer((host, port), WebHandler, config_path=config_path)
    print(f"\n  🌐 CTF Agent Web Dashboard")
    print(f"  ➜ Local:   http://localhost:{port}")
    print(f"  ➜ Network: http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  👋 Shutting down...")
        server.shutdown()
