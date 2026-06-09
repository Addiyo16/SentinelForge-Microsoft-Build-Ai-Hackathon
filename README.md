# 🛡️ SentinelForge — AI-Powered Polyglot Code Security & DevOps Auto-Patch Pipeline
### 🚀 Microsoft Build AI Hackathon 2025 · scaled for Enterprise Integrations
---

**SentinelForge** is an industry-grade, automated **Lead Security Engineer & Code reviewer** that acts as an inline gatekeeper for repository main branches. When developers push code or open pull requests, SentinelForge intercepts the code, audits it across multiple dimensions (security, performance/complexity, and CI/CD health), and **automatically generates ready-to-merge secured patches** using a multi-agent AI swarm.

It supports multiple programming languages (Python, JS/TS, Go, Java, C/C++, YAML) and pluggable CI/CD platforms (GitHub Actions, GitLab CI/CD, and Azure Pipelines).

---

## 🏗️ System Architecture & Workflow

SentinelForge executes a rigorous **8-Stage Pipeline** to inspect and remediate incoming changes:

```
Developer Push / PR Event
       │
       ▼
[1. Ingest] ──► Standardizes code changes from GitHub, GitLab, or Azure DevOps
       │
       ▼
[2. Trie Scan] ──► Runs O(N) Aho-Corasick multi-pattern threat signature scan
       │
       ▼
[3. AST Scan] ──► Triggers pluggable language AST parsers for complexity & nesting limits
       │
       ▼
[4. RAG Lookup] ──► Queries Vector Space Model (TF-IDF) for historical OWASP/CWE fixes
       │
       ▼
[5. Sandbox] ──► Securely executes the code snippet to confirm execution boundaries
       │
       ▼
[6. AI Swarm] ──► SecurityAuditor & CodeOptimizer collaborate; PatchSynthesizer merges
       │
       ▼
[7. CI check] ──► Queries CI/CD status of the commit (GHA status, GitLab/Azure pipelines)
       │
       ▼
[8. Report] ──► Opens an Auto-Remediation Pull Request (PR) or Merge Request (MR)
```

---

## 🌟 Key Engineering Highlights

### 1. Pluggable VCS & CI/CD Layer
Instead of being tied to a single platform, SentinelForge utilizes a **Factory Design Pattern** to support major enterprise source-control systems:
*   **GitHub Actions Integration:** Authenticates, checks GitHub Actions run status, and creates Pull Requests.
*   **GitLab CI/CD Integration:** Parses project GitLab webhooks, verifies signatures, queries pipelines status, and submits Merge Requests.
*   **Azure DevOps (Pipelines):** Handles service hooks, downloads repo files, checks build runs, and opens ADO Pull Requests.

### 2. Pluggable Multi-Language AST Engines
The syntactic analysis utilizes a clean modular scanner plugin architecture:
*   **Python AST Scanner:** Uses Python's native `ast` compiler module to traverse node trees, detecting bare exceptions, loop-nesting, and dangerous calls.
*   **Polyglot Regex Scanners:** Customized modular analyzers for JavaScript/TypeScript, Java, Go, C/C++, and YAML configs.
*   **Dynamic Language Router:** Dynamically inspects file extensions and imports, routing code streams to the correct scanner class.

### 3. High-Performance Local Vector Space RAG
For local development and offline fallbacks, the project implements a **custom Vector Space Model (VSM)**:
*   **TF-IDF Weighting:** Precomputes Document Frequencies (DF) over a security knowledge base, computing Term Frequency (TF) weights to score similarity.
*   **Stopword Filtering:** Filters out programming syntax noise (`def`, `public`, `import`, etc.) to prevent ranking pollution.
*   **Matched Threat Boosting:** Dynamically applies score boosts (+15%) to documents matching Trie scan CWE metadata.
*   *Production Path:* Seamlessly upgrades to **Azure AI Search (Semantic + Hybrid Ranker)** when API endpoints are configured.

### 4. Collaborative AutoGen Agent Swarm
Three specialized LLM agents (GPT-4o) review the code:
*   **SecurityAuditor (GPT-4o-mini):** Inspects syntax, Trie signatures, and RAG data to compile a CWE security audit.
*   **CodeOptimizer (GPT-4o):** Refactors code to reduce cyclomatic complexity and remove performance bottlenecks.
*   **PatchSynthesizer (GPT-4o):** Merges recommendations, outputs the final secure patch, calculates original vs. mitigated risk scores, and makes the Approve/Request Changes decision.

---

## 📁 Repository Layout

```
SentinelForge-Microsoft-Build-Ai-Hackathon/
├── backend/                    # Original backend
├── frontend/                   # Original frontend
├── sentinelforge-v2/           # V2 Modular Workspace (Current Active Code)
│   ├── backend/
│   │   ├── app/
│   │   │   ├── agents/         # AutoGen Swarm (swarm.py)
│   │   │   ├── services/       # Pluggable CI (GitHub, GitLab, AzureDevOps)
│   │   │   ├── structures/     # Threat Trie (trie.py), DAG (dag.py)
│   │   │   ├── utils/          # AST Engines & RAG Vector Engine
│   │   │   └── main.py         # FastAPI Gateway & Routes
│   │   └── requirements.txt
│   └── frontend/
│       ├── app/
│       │   ├── page.tsx        # React Next.js Dashboard
│       │   └── globals.css
│       └── package.json
├── run_sentinelforge.bat       # One-click Windows Launcher
└── README.md                   # Project Documentation
```

---

## 🚀 Getting Started & Execution

### Prerequisites
*   Windows OS (PowerShell / Command Prompt)
*   Python 3.10+ installed
*   The workspace includes a **portable Node.js installation**; you do not need Node.js installed globally.

### Execution
1.  Navigate to the repository folder:
    ```powershell
    cd "E:\Adarsh\project Microsoft\SentinelForge-Microsoft-Build-Ai-Hackathon"
    ```
2.  Run the launcher batch script:
    ```powershell
    .\run_sentinelforge.bat
    ```
    *This script automatically adds the portable Node binaries to the path, activates the Python virtual environment, double-checks Node package installations, starts both frontend and backend dev servers concurrently, and opens the dashboard (`http://localhost:3000`) in your default web browser.*

---

## 💡 Pitch Deck & Shortlist Strengths for Recruiters

*   **Design Patterns & Clean Code:** Built using a Factory Pattern for VCS/CI platforms and Scanner classes, showcasing solid OOP principles.
*   **Algorithms & Data Structures:** Uses an Aho-Corasick Trie for $O(N)$ multi-pattern keyword matching and custom Directed Acyclic Graphs (DAG) for parallel task scheduling.
*   **Enterprise Fallbacks:** Implements custom TF-IDF search for local RAG so the system runs smoothly even if cloud services go offline.
*   **Multi-Agent Swarm Design:** Utilizes the AutoGen swarm protocol where agents cross-evaluate each other, reducing AI hallucinations.
