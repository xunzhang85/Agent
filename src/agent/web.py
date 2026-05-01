"""
CTF Agent Web Dashboard

A lightweight web interface for the CTF Agent.
Run with: python3 -m agent.web
"""

import json
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from pathlib import Path

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🤖 CTF Agent - AI-Powered CTF Auto-Solver</title>
    <style>
        :root {
            --bg: #0d1117;
            --card: #161b22;
            --border: #30363d;
            --text: #e6edf3;
            --accent: #58a6ff;
            --green: #3fb950;
            --red: #f85149;
            --yellow: #d29922;
            --purple: #bc8cff;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header {
            text-align: center;
            padding: 40px 0 30px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 30px;
        }
        header h1 {
            font-size: 2.5em;
            background: linear-gradient(135deg, var(--accent), var(--purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        header p { color: #8b949e; font-size: 1.1em; }
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }
        .stat-card .number {
            font-size: 2em;
            font-weight: bold;
            color: var(--accent);
        }
        .stat-card .label { color: #8b949e; margin-top: 5px; }
        .main-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        @media (max-width: 768px) {
            .stats { grid-template-columns: repeat(2, 1fr); }
            .main-grid { grid-template-columns: 1fr; }
        }
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }
        .card h2 {
            font-size: 1.3em;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .form-group { margin-bottom: 16px; }
        .form-group label {
            display: block;
            margin-bottom: 6px;
            color: #8b949e;
            font-size: 0.9em;
        }
        input, select, textarea {
            width: 100%;
            padding: 10px 14px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 14px;
            font-family: inherit;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--accent);
        }
        textarea { resize: vertical; min-height: 80px; }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary {
            background: var(--accent);
            color: #000;
        }
        .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn-primary:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        .output-area {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            min-height: 200px;
            max-height: 500px;
            overflow-y: auto;
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 13px;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .tool-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 8px;
        }
        .tool-badge {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 8px 12px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 0.85em;
        }
        .tool-badge .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .dot-green { background: var(--green); }
        .dot-red { background: var(--red); }
        .spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid var(--border);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .result-flag {
            background: linear-gradient(135deg, rgba(63,185,80,0.1), rgba(88,166,255,0.1));
            border: 1px solid var(--green);
            border-radius: 8px;
            padding: 16px;
            margin-top: 16px;
            font-size: 1.2em;
            text-align: center;
        }
        .architecture-diagram {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            font-family: monospace;
            font-size: 12px;
            line-height: 1.4;
            overflow-x: auto;
            white-space: pre;
        }
        footer {
            text-align: center;
            padding: 30px 0;
            color: #8b949e;
            font-size: 0.85em;
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }
        footer a { color: var(--accent); text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🤖 CTF Agent</h1>
            <p>AI-Powered CTF Auto-Solver | Multi-Agent Architecture</p>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="number" id="toolCount">-</div>
                <div class="label">Tools Available</div>
            </div>
            <div class="stat-card">
                <div class="number" id="solvedCount">0</div>
                <div class="label">Challenges Solved</div>
            </div>
            <div class="stat-card">
                <div class="number">3</div>
                <div class="label">Agent Roles</div>
            </div>
            <div class="stat-card">
                <div class="number">6</div>
                <div class="label">CTF Categories</div>
            </div>
        </div>

        <div class="main-grid">
            <div class="card">
                <h2>🎯 Solve Challenge</h2>
                <form id="solveForm">
                    <div class="form-group">
                        <label>Challenge URL</label>
                        <input type="text" id="challengeUrl" placeholder="http://challenge.ctf.com">
                    </div>
                    <div class="form-group">
                        <label>Challenge Description</label>
                        <textarea id="challengeText" placeholder="Describe the challenge or paste the problem statement..."></textarea>
                    </div>
                    <div class="form-group">
                        <label>Category</label>
                        <select id="category">
                            <option value="auto">🔍 Auto Detect</option>
                            <option value="web">🌐 Web</option>
                            <option value="crypto">🔐 Crypto</option>
                            <option value="pwn">💥 Pwn</option>
                            <option value="reverse">🔄 Reverse</option>
                            <option value="forensics">🔬 Forensics</option>
                            <option value="misc">📦 Misc</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary" id="solveBtn">
                        🚀 Solve Challenge
                    </button>
                </form>
                <div id="resultArea" style="margin-top: 16px; display: none;">
                    <div class="output-area" id="solveOutput"></div>
                </div>
            </div>

            <div class="card">
                <h2>🔧 Available Tools</h2>
                <div class="tool-list" id="toolList">
                    <div style="color: #8b949e;">Loading tools...</div>
                </div>
            </div>
        </div>

        <div class="card" style="margin-top: 20px;">
            <h2>📐 Architecture</h2>
            <div class="architecture-diagram">
┌─────────────────────────────────────────────────────────────┐
│                     CTF Agent Framework                      │
├───────────┬──────────────┬───────────────┬──────────────────┤
│  Planner  │   Executor   │   Reviewer    │     Memory       │
│  (LLM)    │   (Tools)    │   (Flags)     │   (Context)      │
│           │              │               │                  │
│  Chain of │  20+ Security│  Pattern      │  Sliding Window  │
│  Thought  │  Tools       │  Matching     │  Importance      │
│  Planning │  Docker Box  │  Validation   │  Tracking        │
├───────────┴──────────────┴───────────────┴──────────────────┤
│                      Tool Registry                           │
├────────┬────────┬────────┬─────────┬─────────┬──────────────┤
│  Web   │ Crypto │  Pwn   │ Reverse │Forensic │    Misc      │
│ curl   │ openssl│ gdb    │ radare2 │ binwalk │  python3     │
│ sqlmap │ john   │ ropper │ ghidra  │ steghide│  bash        │
│ nikto  │ hashcat│ checksec│ angr   │ vola..  │              │
└────────┴────────┴────────┴─────────┴─────────┴──────────────┘

Solve Loop:  Input → Classify → Plan → Execute → Review → Flag!
                         ↑          │         │         │
                         └──────────┴─────────┘  Retry  │
                                                        ↓
                                                   ✅ flag{...}
            </div>
        </div>

        <footer>
            <p>CTF Agent v0.1.0 | Built with ❤️ by <a href="https://github.com/xunzhang85/Agent">xunzhang85</a></p>
            <p style="margin-top: 8px;">Powered by LLM Multi-Agent Architecture</p>
        </footer>
    </div>

    <script>
        // Load tools on startup
        fetch('/api/tools')
            .then(r => r.json())
            .then(data => {
                const list = document.getElementById('toolList');
                const count = data.filter(t => t.installed).length;
                document.getElementById('toolCount').textContent = count + '/' + data.length;
                list.innerHTML = data.map(t =>
                    `<div class="tool-badge">
                        <span class="dot ${t.installed ? 'dot-green' : 'dot-red'}"></span>
                        ${t.name}
                    </div>`
                ).join('');
            })
            .catch(() => {
                document.getElementById('toolList').innerHTML = '<div style="color:#f85149">Failed to load tools</div>';
            });

        // Solve form
        document.getElementById('solveForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('solveBtn');
            const resultArea = document.getElementById('resultArea');
            const output = document.getElementById('solveOutput');

            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Solving...';
            resultArea.style.display = 'block';
            output.textContent = '🧠 Analyzing challenge...\\n';

            const url = document.getElementById('challengeUrl').value;
            const text = document.getElementById('challengeText').value;
            const category = document.getElementById('category').value;

            try {
                const resp = await fetch('/api/solve', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, text, category: category === 'auto' ? null : category})
                });
                const data = await resp.json();

                if (data.success) {
                    output.innerHTML = `<span style="color:var(--green)">✅ Solved!</span>\\n\\n` +
                        `🏷️ Category: ${data.category}\\n` +
                        `🔄 Iterations: ${data.iterations}\\n` +
                        `⏱️ Time: ${data.elapsed_time.toFixed(1)}s\\n\\n` +
                        `📝 Steps:\\n${data.steps.map((s,i) => `  ${i+1}. ${s}`).join('\\n')}`;
                    document.getElementById('solvedCount').textContent =
                        parseInt(document.getElementById('solvedCount').textContent) + 1;
                } else {
                    output.innerHTML = `<span style="color:var(--red)">❌ Failed</span>\\n\\n` +
                        `Error: ${data.error}\\n` +
                        `🔄 Iterations: ${data.iterations}\\n` +
                        `⏱️ Time: ${data.elapsed_time?.toFixed(1) || 0}s`;
                }
            } catch (err) {
                output.innerHTML = `<span style="color:var(--red)">Error: ${err.message}</span>`;
            }

            btn.disabled = false;
            btn.innerHTML = '🚀 Solve Challenge';
        });
    </script>
</body>
</html>"""


class WebHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the web dashboard."""

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._respond(200, "text/html", HTML_TEMPLATE)
        elif self.path == "/api/tools":
            from agent.tools.registry import ToolRegistry
            registry = ToolRegistry()
            tools = registry.list_tools()
            self._respond(200, "application/json", json.dumps(tools))
        elif self.path == "/api/health":
            self._respond(200, "application/json", json.dumps({"status": "ok"}))
        else:
            self._respond(404, "text/plain", "Not Found")

    def do_POST(self):
        if self.path == "/api/solve":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)

            from agent.core.agent import CTFAgent
            agent = CTFAgent()

            result = agent.solve(
                challenge_url=data.get("url"),
                challenge_text=data.get("text"),
                category=data.get("category"),
            )

            response = {
                "success": result.success,
                "flag": result.flag,
                "category": result.category,
                "iterations": result.iterations,
                "elapsed_time": result.elapsed_time,
                "error": result.error,
                "steps": result.steps,
            }
            self._respond(200, "application/json", json.dumps(response))
        else:
            self._respond(404, "text/plain", "Not Found")

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
    print(f"🌐 CTF Agent Web Dashboard running at http://localhost:{port}")
    print(f"   Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    start_web()
