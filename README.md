# PyBugLens — AI-Powered Python Code Intelligence

> **Find bugs. Understand code. Build better Python.**

[![Python 3.14](https://img.shields.io/badge/Python-3.14.8-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 113 Passed](https://img.shields.io/badge/Tests-113%20Passed-brightgreen.svg)]()
[![Coverage: 91%](https://img.shields.io/badge/Coverage-91%25-brightgreen.svg)]()
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-black.svg)](https://astral.sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/Type%20Checked-Mypy-blue.svg)](https://mypy-lang.org/)

**PyBugLens** (powered by the AI Bug Detector Core engine) is an enterprise-grade, zero-execution Python static analysis and AI-assisted code review platform. The system inspects Python source code for security vulnerabilities, logic defects, and code smells using deterministic Abstract Syntax Tree (AST) scanning, and optionally augments findings with generative AI insights via OpenAI.

---

## Table of Contents

1. [Features & Capabilities](#features--capabilities)
2. [Security Invariants & Non-Execution Guarantee](#security-invariants--non-execution-guarantee)
3. [Architecture Overview](#architecture-overview)
4. [Supported Python Versions & System Requirements](#supported-python-versions--system-requirements)
5. [Ubuntu Installation & Setup Guide](#ubuntu-installation--setup-guide)
6. [Starting the Local FastAPI Web Server & Dashboard](#starting-the-local-fastapi-web-server--dashboard)
7. [Command-Line Interface (CLI) Usage](#command-line-interface-cli-usage)
8. [Running Automated Tests & Quality Gates](#running-automated-tests--quality-gates)
9. [OpenAI API Configuration (Optional)](#openai-api-configuration-optional)
10. [Local SQLite Storage & History Management](#local-sqlite-storage--history-management)
11. [Public Demo Mode (`DEMO_MODE=true`)](#public-demo-mode-demo_modetrue)
12. [Security & Privacy Audit Findings](#security--privacy-audit-findings)
13. [Project Directory Layout](#project-directory-layout)
14. [Troubleshooting Guide](#troubleshooting-guide)

---

## 1. Features & Capabilities

- **Zero-Execution Code Inspection**: User-submitted Python code is never evaluated, executed, imported, or run via subprocesses. Code is strictly compiled to an Abstract Syntax Tree via `ast.parse()`.
- **Accurate Syntax Verification**: Catches `SyntaxError` with 1-indexed line and column numbers, error messages, and verbatim line context.
- **Deterministic Static AST Rules**:
  - `CORR001` (Correctness): Mutable default arguments (`def f(x=[])`).
  - `CORR002` (Correctness): Literal division by zero (`x / 0`, `x // 0`, `x % 0`).
  - `CORR003` (Correctness): Ineffective standalone comparisons (`x == 10`).
  - `CORR004` (Correctness): Unreachable code following unconditional `return`, `raise`, `break`, or `continue`.
  - `SEC001` (Security): Dangerous dynamic execution (`eval()`, `exec()`).
  - `SEC002` (Security): Hardcoded secrets and API keys with automated masking/redaction.
  - `SEC003` (Security): Insecure temporary file generation (`tempfile.mktemp()`).
  - `STYLE001` (Style): Bare `except:` clauses suppressing interrupts.
  - `STYLE002` (Style): Unused local variables in function scopes.
  - `STYLE003` (Style): Redundant or duplicate `if`/`elif`/`else` branches.
- **Optional OpenAI Intelligence**: Augments static findings with structured recommendations (`gpt-4o-mini`). Fully optional — 100% operational offline without API keys.
- **FastAPI REST API**: High-performance asynchronous API endpoints with input size validation and sliding-window rate limiting.
- **Modern Web Dashboard**: Self-contained dark-mode dashboard with real-time counters, syntax alerts, finding badges, suggested remediation blocks, and review history.
- **Scriptable CLI**: `bug-detector` utility supporting formatted console output and raw JSON output with standardized exit codes.
- **SQLite Persistence**: Local transaction-safe storage with parameterization, indexing, and newest-first pagination.

---

## 2. Security Invariants & Non-Execution Guarantee

> **CRITICAL SECURITY INVARIANT:** Under no circumstances is user-submitted Python code executed, dynamically imported, or run as a subprocess.

1. **AST Analysis Only**: The inspection pipeline strictly converts source strings into an AST via `ast.parse(source_code)`. No `exec()`, `eval()`, or `compile(..., 'exec')` execution takes place.
2. **Canary Verification**: Automated canary tests submit code with destructive filesystem and OS side-effects (`os.environ`, filesystem deletion, `sys.exit`) to mathematically prove that side-effects never occur.
3. **Denial-of-Service Protection**: Input payloads are bounded before parsing: maximum 100 KB payload size and 2,000 source code lines.
4. **XSS Defense**: The web dashboard renders findings, explanations, and user source code strictly using `textContent` and `document.createElement()`.

---

## 3. Architecture Overview

```
[ User Input (Web Dashboard / CLI / API) ]
                    │
                    ▼
          [ CodeSanitizer ] ────(Oversized / Null Bytes)───► [ 413 / 400 Error ]
                    │ (Normalized code & SHA-256)
                    ▼
        [ AST Syntax Checker ] ───(SyntaxError)──────────► [ SyntaxValidationResult ]
                    │ (Valid AST)
                    ▼
        [ 10 AST Rule Visitors ] ────────────────────────► [ List of BugFinding ]
                    │
                    ├───► [ SQLite Review Repository ] (If enabled & not DEMO_MODE)
                    │
                    ├───► [ Optional OpenAI Reviewer ] (If requested & key available)
                    │
                    ▼
         [ AnalysisResult Schema ] ──► [ Dashboard UI / JSON Response / CLI Table ]
```

---

## 4. Supported Python Versions & System Requirements

- **Supported Python Runtimes**: Python 3.11, Python 3.12, Python 3.13, and Python 3.14.
- **Verified Environment**: **Python 3.14.8** on Linux (x86_64).
- **Operating Systems**: Ubuntu 22.04 / 24.04 LTS, Debian 12, macOS 13+, Windows 11 (via WSL2).
- **Disk & Memory**: Minimum 512 MB RAM, 100 MB free disk space.

---

## 5. Ubuntu Installation & Setup Guide

### Step 1: Install System Prerequisites
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git build-essential
```

### Step 2: Clone the Repository & Enter Directory
```bash
git clone <repository_url> ai-bug-detector-v2
cd ai-bug-detector-v2
```

### Step 3: Create & Activate Python Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 4: Install Dependencies in Editable Mode
```bash
# Core dependencies + Development & Testing tools + Optional OpenAI SDK
pip install -e ".[dev,ai]"
```

Verify package installation:
```bash
bug-detector --version
# Output: bug-detector, version 0.1.0
```

---

## 6. Starting the Local FastAPI Web Server & Dashboard

### Option A: Using the CLI Entry Point
```bash
source .venv/bin/activate
bug-detector server --host 127.0.0.1 --port 8000
```

### Option B: Using Uvicorn Directly
```bash
uvicorn bug_detector.api.app:app --host 127.0.0.1 --port 8000 --reload
```

### Accessing the Web Dashboard
Open your web browser and navigate to:
```
http://localhost:8000
```
Interactive API documentation is accessible at:
```
http://localhost:8000/docs
```

---

## 7. Command-Line Interface (CLI) Usage

The `bug-detector` CLI allows terminal-based static analysis and history queries.

### Analyze a Python File
```bash
# Basic colorized terminal analysis
bug-detector analyze path/to/script.py

# Output formatted structured JSON
bug-detector analyze path/to/script.py --json

# Analyze without saving to SQLite database
bug-detector analyze path/to/script.py --no-save

# Request optional AI review (requires OPENAI_API_KEY)
bug-detector analyze path/to/script.py --ai
```

### Standardized CLI Exit Codes
- `0`: Clean code (Valid syntax, zero bug findings).
- `1`: Issues detected (Static rule violations found).
- `2`: Syntax error, file not found, or oversized input.

### Inspect Review History
```bash
# List recent review records
bug-detector history --limit 10

# Inspect details of a past review
bug-detector view <review_uuid>

# Inspect past review in raw JSON format
bug-detector view <review_uuid> --json
```

---

## 8. Running Automated Tests & Quality Gates

The test suite validates correctness, security boundaries, rate limiting, and zero-execution invariants.

```bash
# 1. Run all 113 automated unit, integration, and security tests with coverage
./.venv/bin/python -m pytest -W error::ResourceWarning --cov=bug_detector tests/

# 2. Run Ruff linter and code style checker
./.venv/bin/ruff check .

# 3. Run Mypy static type verification
./.venv/bin/mypy src tests

# 4. Verify virtual environment dependency tree
./.venv/bin/pip check
```

---

## 9. OpenAI API Configuration (Optional)

The OpenAI integration is 100% optional. The system functions entirely offline without an API key.

To enable AI code reviews:
1. Create a `.env` file from the template:
   ```bash
   cp .env.example .env
   ```
2. Add your OpenAI API key to `.env`:
   ```ini
   OPENAI_API_KEY="sk-your-openai-api-key-here"
   OPENAI_MODEL="gpt-4o-mini"
   OPENAI_TIMEOUT_SECONDS=30.0
   ```
3. Restart the server. In the web dashboard, the "AI Review" toggle switch will become active.

---

## 10. Local SQLite Storage & History Management

Review records are persisted in a local SQLite database (`./data/bug_detector.db` by default):
- Connections utilize write-ahead logging (WAL) where supported.
- Connections automatically roll back on exceptions.
- All database queries strictly use parameterized statements (`?`) to eliminate SQL injection.
- Stored records revalidate against Pydantic models upon retrieval.

---

## 11. Public Demo Mode (`DEMO_MODE=true`)

When exposing the application as a public demonstration or sandbox:
1. Set `DEMO_MODE=true` in your `.env` or container environment.
2. **Security Enforcements in Demo Mode**:
   - Paid OpenAI requests are unconditionally blocked without network traffic.
   - Visitor-submitted code is **never** saved to disk or database even if `save=true` is requested.
   - All `/api/history` endpoints return `403 Forbidden` to protect user privacy.

---

## 12. Security & Privacy Audit Findings

| Audit Check | Status | Verification Detail |
|---|---|---|
| Hardcoded Secrets | **PASS** | No real API keys or sensitive credentials exist in Git or source code. |
| Zero Execution Guarantee | **PASS** | Automated canary tests confirm submitted code is never executed. |
| Input Size Bounds | **PASS** | Enforces 100 KB payload ceiling and 2,000 line maximum. |
| SQL Injection Protection | **PASS** | 100% of SQL statements use parameterized queries (`?`). |
| Error Masking | **PASS** | Database errors mask raw queries and source code via `StorageError`. |
| XSS Prevention | **PASS** | Frontend renders all dynamic content via DOM `textContent`. |
| CORS Configuration | **PASS** | Explicit origin list without wildcard credentials. |
| Demo Mode Protection | **PASS** | Blocks persistence, paid AI, and history access. |
| In-Memory Rate Limiting | **NOTE** | Tracks client IP in-process. In multi-worker deployments (`gunicorn -w 4`), limits apply per worker process. Behind reverse proxies, configure forwarded header middleware. |
| Multi-Tenant Isolation | **NOTE** | Local mode (`DEMO_MODE=false`) does not implement user login or row-level tenant authorization. Public deployments must use `DEMO_MODE=true` or be placed behind an authenticating proxy. |

---

## 13. Project Directory Layout

```
ai-bug-detector-v2/
├── .env.example                # Safe environment configuration template
├── .gitignore                  # Git exclusion rules (venv, db, secrets, caches)
├── pyproject.toml              # Build system and dependency definitions
├── requirements.txt            # Production runtime dependencies
├── requirements-dev.txt        # Development and testing dependencies
├── README.md                   # Complete system documentation
├── docs/
│   └── architecture.md         # Full architecture specification
├── src/bug_detector/           # Core application package
│   ├── ai/
│   │   ├── __init__.py
│   │   └── reviewer.py         # Defensive OpenAI integration
│   ├── analyzers/              # AST scanner and rules
│   │   ├── rules/              # Modular correctness, security, style rules
│   │   ├── ast_scanner.py      # AST visitor engine
│   │   ├── engine.py           # Pipeline coordinator
│   │   └── syntax.py           # Python syntax checker
│   ├── api/                    # FastAPI application
│   │   ├── app.py              # Application factory
│   │   ├── dependencies.py     # Dependency injection
│   │   ├── limiter.py          # Sliding-window rate limiter
│   │   └── routes/             # REST routes (/health, /analyze, /history)
│   ├── cli/                    # Click command-line interface
│   │   ├── __init__.py
│   │   └── main.py             # CLI commands
│   ├── core/                   # Pydantic schemas and configuration
│   │   ├── config.py           # Settings loader
│   │   └── models.py           # Data models
│   ├── static/                 # Frontend dashboard
│   │   ├── app.js              # Safe DOM rendering logic
│   │   ├── index.html          # Semantic responsive HTML
│   │   └── styles.css          # Modern dark theme styles
│   ├── storage/                # SQLite storage layer
│   │   ├── database.py         # Database connection manager
│   │   └── repository.py       # Parameterized review repository
│   └── utils/                  # Input validation
│       └── sanitizer.py        # Code normalizer and size bounds
└── tests/                      # Automated test suite (113 tests)
    ├── integration/            # API, canary security, and e2e tests
    └── unit/                   # Rule, engine, model, CLI, and AI tests
```

---

## 14. Troubleshooting Guide

### Issue: `Port 8000 already in use`
- **Cause**: Another process or previous server instance is listening on port 8000.
- **Fix**: Specify an alternate port via CLI:
  ```bash
  bug-detector server --port 8080
  ```

### Issue: `OpenAI authentication failed`
- **Cause**: Invalid or expired `OPENAI_API_KEY` in `.env`.
- **Fix**: Verify your API key at [platform.openai.com](https://platform.openai.com). The system continues to run full static AST analysis even if the API key is invalid.

### Issue: `History access is disabled in public demo mode (403 Forbidden)`
- **Cause**: Application is running with `DEMO_MODE=true`.
- **Fix**: In a private development environment, set `DEMO_MODE=false` in `.env` to enable local persistence and review history inspection.

### Issue: `Source code payload exceeds maximum allowed limit`
- **Cause**: Submitted code exceeds 100 KB or 2,000 lines.
- **Fix**: Submit code within size boundaries, or adjust `MAX_CODE_SIZE_BYTES` and `MAX_CODE_LINES` in `.env` for large local file processing.
