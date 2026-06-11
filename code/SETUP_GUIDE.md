# SentinelForge AI — Complete Setup Guide
## Microsoft Build AI Hackathon 2025

---

## 📁 Final Folder Structure

```
sentinelforge-ai/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                    ← FastAPI app + full pipeline
│   │   ├── agents/
│   │   │   ├── __init__.py
│   │   │   └── swarm.py               ← AutoGen multi-agent (Auditor ‖ Optimizer → Synthesizer)
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   └── github_service.py      ← Real GitHub webhook + PR creation
│   │   ├── structures/
│   │   │   ├── __init__.py
│   │   │   ├── trie.py                ← Aho-Corasick threat signature trie
│   │   │   └── dag.py                 ← Async DAG scheduler
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── ast_engine.py          ← Deep AST analysis
│   │       ├── rag_engine.py          ← RAG + Azure AI Search
│   │       └── sandbox.py             ← Sandboxed code execution
│   ├── .env                           ← Your secrets (copy from .env.example)
│   ├── .env.example
│   └── requirements.txt
└── frontend/
    └── app/
        └── page.tsx                   ← Full React dashboard (6 tabs)
```

---

## 🚀 Step 1 — Backend Setup

### Create virtual environment
```powershell
cd sentinelforge-v2
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.venv\Scripts\Activate.ps1
```

### Install dependencies
```powershell
cd backend
pip install -r requirements.txt
```

### Configure .env
Copy `.env.example` to `.env` and fill in your keys:
```
AZURE_OPENAI_API_KEY=your-key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_API_VERSION=2024-05-01-preview
AZURE_OPTIMIZER_DEPLOYMENT=gpt-4o
AZURE_AUDITOR_DEPLOYMENT=gpt-4o-mini
GITHUB_TOKEN=ghp_xxxx           ← optional, enables real PR creation
GITHUB_WEBHOOK_SECRET=xxxx      ← optional, enables webhook verification
```

### Run backend
```powershell
cd backend
.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --port 8000
```

Verify: open http://localhost:8000/health → should return `{"status":"ok"}`

---

## 🎨 Step 2 — Frontend Setup

```powershell
cd ../frontend
npm install
npm run dev
```

Open http://localhost:3000

---

## 🔗 Step 3 — Real GitHub Webhook (for live demo)

### Install ngrok
Download from https://ngrok.com/download and run:
```powershell
ngrok http 8000
```
Copy the `https://xxxx.ngrok-free.app` URL.

### Add webhook to GitHub repo
1. Go to your repo → Settings → Webhooks → Add webhook
2. Payload URL: `https://xxxx.ngrok-free.app/webhook/github`
3. Content type: `application/json`
4. Secret: same as `GITHUB_WEBHOOK_SECRET` in your .env
5. Events: ✅ Just the push event
6. Save

Now every `git push` to that repo triggers the full SentinelForge pipeline!

---

## 🎮 Demo Flow for Judges

1. **Open** http://localhost:3000
2. **Show** the clean dark dashboard with 6 tabs
3. **Click** "▶ Simulate GitHub Push"
4. **Watch** the pipeline stages light up green one by one
5. **Click** "Trie Scan" tab → show 8 threat signatures detected with CWE IDs
6. **Click** "AST Analysis" tab → show cyclomatic complexity, loop depth, dangerous calls
7. **Click** "RAG Context" tab → show 3 knowledge base entries with similarity scores + historical fixes
8. **Click** "Agent Swarm" tab → show Auditor, Optimizer, Synthesizer dialogue + final patch
9. **Click** "PR Report" tab → show the auto-generated PR markdown

**Optional live demo**: Do a real `git push` with vulnerable code → watch it process live!

---

## 🏆 Hackathon Pitch Points

### Azure Tech Stack Used
- **Azure OpenAI GPT-4o** — CodeOptimizer + PatchSynthesizer agent
- **Azure OpenAI GPT-4o-mini** — SecurityAuditor agent (cost-efficient)
- **Azure AI Search** — Production RAG vector retrieval (optional, falls back to local KB)
- **Azure Key Vault** — Recommended for production secret management

### Key Technical Differentiators
- **Aho-Corasick Trie** — O(N) multi-pattern threat detection (vs O(N×M) naive)
- **Async DAG Scheduler** — Parallel agent execution (Auditor ‖ Optimizer)
- **3-Agent AutoGen Swarm** — Specialized roles with cross-validation
- **RAG Knowledge Base** — Historical vulnerability context injected into prompts
- **Real GitHub Integration** — Webhook → diff fetch → auto PR
- **AST Deep Analysis** — Cyclomatic complexity, loop depth, dangerous call detection
- **Sandboxed Execution** — Safe code testing with resource limits

### The Full Flow
```
Developer pushes code
       ↓
GitHub webhook → SentinelForge API
       ↓
[Ingest] → [Trie Scan] → [AST Analysis] → [RAG Lookup]
                                                ↓
                             [Auditor ‖ Optimizer] → [Synthesizer]
                                                ↓
                             [CI Check] → [Auto PR to GitHub]
```

---

## 🐛 Troubleshooting

| Issue | Fix |
|-------|-----|
| `AZURE_OPENAI_API_KEY not set` | Copy `.env.example` to `.env` and fill keys |
| `Cannot reach backend` | Make sure uvicorn is running on port 8000 |
| `Module not found` | Run `pip install -r requirements.txt` with venv activated |
| `PR not created` | Set `GITHUB_TOKEN` in .env with `repo` scope |
| `Webhook 401` | Set same `GITHUB_WEBHOOK_SECRET` in .env and GitHub |
| Next.js slow filesystem warning | Normal on Windows — ignore it |
