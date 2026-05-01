# 🤖 Agent - AI-Powered CTF Auto-Solver

[![CI](https://github.com/xunzhang85/Agent/actions/workflows/ci.yml/badge.svg)](https://github.com/xunzhang85/Agent/actions/workflows/ci.yml)
[![Deploy Pages](https://github.com/xunzhang85/Agent/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/xunzhang85/Agent/actions/workflows/deploy-pages.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](Dockerfile)

> **Agent** 是一个由 LLM 驱动的自动化 CTF (Capture The Flag) 解题框架。采用多智能体协作架构，支持 Web、Crypto、Pwn、Reverse、Forensics、Misc 等全品类 CTF 题目自动求解。

---

## 🎯 项目亮点 (Key Features)

- **🧠 多智能体协作架构** — Planner + Executor + Reviewer 三角色协同，模拟人类解题思维
- **🔧 内置安全工具链** — 集成 nmap、sqlmap、gdb、radare2、binwalk 等 20+ 安全工具
- **📦 沙箱隔离执行** — Docker 容器隔离，安全执行 Exploit 和逆向分析
- **🔄 自动化工作流** — GitHub Actions 驱动的 CI/CD，支持自动化测试和部署
- **📊 可视化仪表板** — GitHub Pages 托管的实时解题进度和统计面板
- **🔌 可扩展架构** — 模块化设计，轻松接入新的 LLM 或自定义工具
- **🏆 竞赛验证** — 架构参考 CAI (HackTheBox Top-10) 和 NYU CTF Bench

---

## 📐 架构设计 (Architecture)

```
┌─────────────────────────────────────────────────────────┐
│                    CTF Agent Framework                    │
├─────────┬─────────────┬──────────────┬───────────────────┤
│ Planner │  Executor   │   Reviewer   │     Memory        │
│ (规划器) │  (执行器)    │   (审查器)    │    (上下文记忆)    │
├─────────┴─────────────┴──────────────┴───────────────────┤
│                     Tool Registry                         │
├──────┬──────┬──────┬──────┬──────┬──────┬────────────────┤
│ Web  │Crypto│ Pwn  │Revers│Forens│ Misc │ Custom Tools   │
├──────┴──────┴──────┴──────┴──────┴──────┴────────────────┤
│                  Sandbox (Docker)                         │
└─────────────────────────────────────────────────────────┘
```

### 核心流程

```
题目输入 → [分类器] → [Planner 规划] → [Executor 执行] → [Reviewer 验证]
                ↑           │                │                │
                └───────────┴────────────────┘  失败时重新规划
```

1. **Classifier** — 自动识别题目类型 (Web/Crypto/Pwn/...)
2. **Planner** — LLM 分析题目，生成解题策略和步骤
3. **Executor** — 调用工具链执行具体操作（扫描、逆向、编写 Exploit）
4. **Reviewer** — 验证 Flag 格式，评估解题质量，失败时触发重试

---

## 🚀 快速开始 (Quick Start)

### 安装

```bash
# 克隆仓库
git clone https://github.com/xunzhang85/Agent.git
cd Agent

# 安装依赖
pip install -e ".[dev]"

# 配置 LLM API
cp configs/config.example.yaml configs/config.yaml
# 编辑 config.yaml，填入你的 API Key
```

### Docker 方式

```bash
docker-compose up -d
docker exec -it ctf-agent agent solve --challenge "http://target.ctf.com"
```

### 命令行使用

```bash
# 自动解题
agent solve --url http://challenge.ctf.com --category web

# 批量解题
agent batch --file challenges.txt --output results.json

# 交互模式
agent interactive

# 查看解题历史
agent history --stats
```

### Python API

```python
from agent import CTFAgent

agent = CTFAgent(model="gpt-4o")
result = agent.solve(
    challenge_url="http://challenge.ctf.com",
    category="web",
    timeout=300
)
print(f"Flag: {result.flag}")
print(f"Steps: {result.steps}")
```

---

## 📁 项目结构

```
Agent/
├── src/agent/
│   ├── core/              # 核心模块
│   │   ├── agent.py       # 主 Agent 循环
│   │   ├── planner.py     # 任务规划器
│   │   ├── executor.py    # 任务执行器
│   │   ├── reviewer.py    # 结果审查器
│   │   └── memory.py      # 上下文记忆管理
│   ├── tools/             # 安全工具封装
│   │   ├── registry.py    # 工具注册中心
│   │   ├── web.py         # Web 安全工具
│   │   ├── crypto.py      # 密码学工具
│   │   ├── pwn.py         # 二进制利用工具
│   │   ├── reverse.py     # 逆向工程工具
│   │   └── forensics.py   # 取证分析工具
│   ├── categories/        # 题目分类器
│   ├── utils/             # 工具函数
│   └── cli.py             # 命令行接口
├── configs/               # 配置文件
├── docs/                  # 文档 (GitHub Pages)
├── tests/                 # 测试套件
├── examples/              # 使用示例
├── .github/workflows/     # CI/CD 流水线
├── Dockerfile             # Docker 镜像
└── docker-compose.yml     # 容器编排
```

---

## 🛠️ 支持的 CTF 类别

| 类别 | 工具 | 能力 |
|------|------|------|
| **Web** | sqlmap, nikto, curl, requests | SQL注入、XSS、SSRF、文件上传 |
| **Crypto** | sage, openssl, custom scripts | RSA、AES、哈希碰撞、密码分析 |
| **Pwn** | pwntools, gdb, ropper | 栈溢出、格式化字符串、ROP链 |
| **Reverse** | radare2, ghidra, angr | 反编译、符号执行、动态分析 |
| **Forensics** | binwalk, volatility, steghide | 内存取证、隐写分析、文件恢复 |
| **Misc** | 自定义工具 | 编程题、算法题、杂项 |

---

## ⚙️ 配置

```yaml
# configs/config.yaml
llm:
  provider: openai  # openai / anthropic / deepseek / ollama
  model: gpt-4o
  api_key: ${OPENAI_API_KEY}
  temperature: 0.1
  max_tokens: 4096

agent:
  max_iterations: 20
  timeout: 600
  retry_on_failure: true
  max_retries: 3

sandbox:
  enabled: true
  image: "ctf-agent:sandbox"
  memory_limit: "2g"
  network: "ctf-net"

tools:
  enabled:
    - nmap
    - sqlmap
    - nikto
    - gdb
    - radare2
    - binwalk
    - pwntools
```

---

## 🧪 测试

```bash
# 运行所有测试
pytest

# 运行特定类别测试
pytest tests/test_web.py -v

# 生成覆盖率报告
pytest --cov=agent --cov-report=html
```

---

## 📖 文档

完整文档请访问：**[GitHub Pages](https://xunzhang85.github.io/Agent/)**

- [快速开始指南](https://xunzhang85.github.io/Agent/getting-started)
- [架构设计详解](https://xunzhang85.github.io/Agent/architecture)
- [工具链参考](https://xunzhang85.github.io/Agent/tools)
- [挑战赛题解](https://xunzhang85.github.io/Agent/challenges)

---

## 🤝 Contributing

欢迎贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详情。

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

---

## 📜 License

本项目采用 [MIT License](LICENSE) 开源。

---

## 🙏 Acknowledgements

- [CAI (Cybersecurity AI)](https://github.com/aliasrobotics/CAI) — 架构灵感来源
- [NYU CTF Agents](https://github.com/NYU-LLM-CTF/nyuctf_agents) — 多智能体架构参考
- [SWE-agent](https://github.com/swe-agent/swe-agent) — Agent 设计理念参考
- [pwntools](https://github.com/Gallopsled/pwntools) — CTF 工具链

---

<div align="center">
  <b>⭐ 如果这个项目对你有帮助，请给一个 Star！</b>
</div>
