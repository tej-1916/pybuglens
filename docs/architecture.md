# AI-Powered Bug Detection System — Architecture Specification

## 1. Executive Summary

The **AI-Powered Bug Detection System** is an enterprise-grade, static analysis and AI-assisted code review platform designed for Python codebases. It combines deterministic AST-based static verification with optional generative AI intelligence (OpenAI API), served via a FastAPI REST backend, an interactive web dashboard, and a scriptable CLI.

---

## 2. Core Architectural Principles & Security Guardrails

### 2.1 Zero-Trust Code Execution Guarantee
> **CRITICAL SECURITY INVARIANT:** User-submitted Python code is NEVER executed, evaluated, imported, or invoked as a subprocess.
- No `eval()`, `exec()`, `compile(..., 'exec')` with execution, or `importlib` calls are ever performed on user code.
- All code inspection is performed purely via:
  1. Python Standard Library `ast.parse()` to build an Abstract Syntax Tree.
  2. AST Node Visitors (`ast.NodeVisitor`) to inspect syntax trees deterministically.
  3. Tokenizer and line/character analysis for formatting and metrics.
  4. OpenAI LLM prompts containing escaped code for semantic recommendations.

### 2.2 Offline-First Design
- The core static analysis engine is 100% self-contained and functions completely without internet connectivity or third-party API keys.
- OpenAI integration is strictly additive and optional. Missing or failing API keys never prevent static bug analysis from returning complete results.

### 2.3 Defense-in-Depth
- **Input Sanitization & Normalization**: Strips null bytes (`\x00`), normalizes line endings (`\r\n` to `\n`), enforces byte size ceilings (100 KB default) and line count limits (2000 lines default) to prevent Denial of Service (DoS).
- **Public Demo Mode**: Configurable `DEMO_MODE=true` disables paid AI usage, disables persistent storage of visitor code, and enforces strict rate limiting.
- **Zero Secret Leakage**: No secrets in source code, logs, database records, or frontend responses.

---

## 3. Directory and Package Layout

```
ai-bug-detector-v2/
├── pyproject.toml              # Modern build system & tool configuration (PEP 621)
├── requirements.txt            # Pinned runtime dependencies
├── requirements-dev.txt        # Development, linting, and testing dependencies
├── .env.example                # Environment variable configuration template
├── .gitignore                  # Git ignore rules (secrets, venvs, caches, databases)
├── docs/
│   └── architecture.md         # Full system architecture documentation
├── src/
│   └── bug_detector/           # Primary Python package
│       ├── __init__.py         # Package entrypoint & version metadata
│       ├── core/               # Foundational configuration and schemas
│       │   ├── __init__.py
│       │   ├── config.py       # Pydantic Settings & environment loader
│       │   └── models.py       # Core data models (Finding, Result, Enums)
│       ├── analyzers/          # Static analysis engines
│       │   ├── __init__.py
│       │   └── base.py         # Abstract Base Analyzer interface
│       ├── db/                 # Phase 3: SQLite persistence layer
│       │   └── __init__.py
│       ├── ai/                 # Phase 4: OpenAI optional review provider
│       │   └── __init__.py
│       ├── api/                # Phase 4: FastAPI routers and server
│       │   └── __init__.py
│       ├── cli/                # Phase 4: Command-line interface
│       │   └── __init__.py
│       ├── static/             # Phase 4: Web dashboard (HTML, CSS, JS)
│       └── utils/              # Helper utilities
│           ├── __init__.py
│           └── sanitizer.py    # Code sanitization, size validation, SHA-256
└── tests/
    ├── __init__.py
    ├── conftest.py             # Shared pytest fixtures
    ├── unit/                   # Unit test suite
    │   ├── __init__.py
    │   ├── test_config.py      # Configuration tests
    │   ├── test_models.py      # Schema and validation tests
    │   └── test_sanitizer.py   # Input sanitizer tests
    └── integration/            # Phase 4/5 integration tests
```

---

## 4. Five-Phase Implementation Roadmap

### Phase 1: Project Initialization & Foundation (COMPLETED)
- Verification of Python 3.14.8 environment and dependencies.
- Standardized `pyproject.toml`, `requirements.txt`, and `requirements-dev.txt`.
- Robust package layout under `src/bug_detector/`.
- Pydantic models, environment configuration, code sanitization, and base analyzer abstractions.
- Automated testing structure with unit tests verifying configuration, models, and sanitization.

### Phase 2: Core Static Analysis Engine (COMPLETED)
- **Syntax Validator**: Accurate error detection with line numbers, column offsets, and line excerpts via `SyntaxChecker` (`SYNTAX001`).
- **AST Bug Rules Catalog**:
  - `CORR001`: Mutable default arguments in function definitions (`def f(x=[])`).
  - `CORR002`: Statically provable division by literal zero (`x / 0`, `x // 0`, `x % 0`).
  - `CORR003`: Ineffective standalone comparison statements (`x == y`).
  - `CORR004`: Unreachable code statements following unconditional returns, raises, breaks, or continues.
  - `SEC001`: Dangerous dynamic execution calls (`eval()`, `exec()`, `builtins.eval()`).
  - `SEC002`: Hardcoded secrets and credential patterns (API keys, tokens, passwords) with automated redaction.
  - `SEC003`: Insecure temporary file generation via `tempfile.mktemp()`.
  - `STYLE001`: Bare `except:` clauses catching all exceptions.
  - `STYLE002`: Unused local variables in function scopes.
  - `STYLE003`: Duplicate or redundant conditional branches.
- **Pipeline Coordinator**: `AnalysisEngine` orchestrating sanitization, syntax checking, rule execution, and structured metric summarization.
- **Zero-Execution Guarantee**: Verified through security canary tests confirming untrusted code is never executed.

### Phase 3: SQLite Persistence & History (COMPLETED)
- **Database Manager (`DatabaseManager`)**: Automated directory creation, schema initialization, version tracking (`schema_version`), and transactional connection handling with automatic rollback on errors.
- **Database Schema**:
  - `reviews` table storing `review_id` (UUID PK), `timestamp` (ISO 8601 UTC), `filename`, `source_code`, `code_hash`, line & char counts, `is_valid_syntax`, `syntax_error_details` (JSON), `findings_json` (JSON), severity counts, `ai_review_json` (JSON), and `execution_duration_ms`.
  - Indexes on `timestamp DESC`, `code_hash`, and `filename`.
- **Repository Layer (`ReviewRepository`)**:
  - `save_review()`: Parameterized insert preserving full analysis results.
  - `get_review_by_id()`: Retrieve and reconstruct typed `AnalysisResult` by UUID.
  - `list_recent_reviews()`: Newest-first pagination via `limit` and `offset`.
  - `search_reviews()`: Filter by SHA-256 code hash and UTC date ranges.
  - `delete_review()`: Delete individual record.
  - `clear_history()`: Explicitly purge all reviews.
  - `count_reviews()`: Total record count.
- **Engine Integration & Privacy Controls**:
  - `AnalysisEngine` supports optional `save=True/False` execution.
  - Supports zero-persistence public demo mode where visitor code is never saved to disk.

### Phase 4: AI Integration, Web Dashboard, and CLI (COMPLETED)
- **AI Review Component (`AIReviewer`)**:
  - Independent, defensive OpenAI chat completion integration (`src/bug_detector/ai/reviewer.py`).
  - Graceful degradation when `OPENAI_API_KEY` is omitted or unconfigured.
  - Strict block and isolation when `DEMO_MODE=true` (never makes paid external API calls).
  - Handles `AuthenticationError`, `RateLimitError`, `APITimeoutError`, and `APIConnectionError` without crashing or throwing unhandled exceptions.
  - Strict security policy: never logs or exposes API keys or user source code.
- **FastAPI Backend Application (`src/bug_detector/api/`)**:
  - Endpoints:
    - `GET /api/health`: Returns service health, version, demo mode status, and boolean AI availability (zero secret exposure).
    - `POST /api/analyze`: Zero-execution AST analysis pipeline with size/line validation and per-IP rate limiting.
    - `GET /api/history`: Paginated history summaries (blocked with 403 in `DEMO_MODE`).
    - `GET /api/history/{id}`: Detailed historical review record (blocked with 403 in `DEMO_MODE`).
    - `DELETE /api/history/{id}`: Delete specific historical review (blocked with 403 in `DEMO_MODE`).
    - `POST /api/history/clear`: Purge all historical reviews (blocked with 403 in `DEMO_MODE`).
  - Thread-safe sliding-window `RateLimiter` protecting endpoints against automated abuse.
  - Strict CORS policy with configurable allowed origins and non-wildcard credentials.
- **Web Dashboard (`src/bug_detector/static/`)**:
  - Modern, responsive single-page application served directly from FastAPI at root `/`.
  - Self-contained HTML/CSS/JS without external CDN dependencies.
  - Code editor with live character/line counters and preloaded bug snippet library.
  - Status banner, real-time metrics cards, categorized findings with severity badges and suggested fixes.
  - Optional AI Quality Advisor panel displaying structured review insights.
  - Review history drawer with inspection and clearing controls (auto-disabled in demo mode).
  - Strict DOM rendering using `textContent` and `document.createElement` eliminating Cross-Site Scripting (XSS).
- **Command-Line Interface (`bug-detector`)**:
  - Click-powered CLI entrypoint installed under `bug-detector`.
  - Commands:
    - `bug-detector analyze <path> [--json] [--ai] [--no-save]`: Analyzes local Python files, formatted color output or JSON. Exit codes: 0 = clean, 1 = bugs detected, 2 = syntax error or invalid input.
    - `bug-detector history [--limit N]`: Lists past reviews.
    - `bug-detector view <review_id> [--json]`: Displays full review details.
    - `bug-detector server [--host H] [--port P] [--reload]`: Starts FastAPI uvicorn web server.

### Phase 5: Verification, Hardening & Deployment
- Production deployment packaging and verification.
- Netlify static frontend configuration + cloud backend configuration (Render/Fly.io/Docker).
- Production documentation and operational runbooks.

---

## 5. Data Flow Diagram

```
[ User Input (Web / CLI / API) ]
              │
              ▼
   [ CodeSanitizer ]  ──(Size > Limit or Null bytes)──► [ ValueError (400 Bad Request) ]
              │ (Normalized code & SHA-256)
              ▼
    [ AST Syntax Parser ]  ──(Syntax Error)──────────► [ SyntaxValidationResult (Flagged) ]
              │ (Valid AST)
              ▼
    [ AST Visitor Rules ]  ──────────────────────────► [ List of BugFinding ]
              │
              ├───► [ SQLite History Store ] (Async / Synchronous Save)
              │
              ├───► [ Optional OpenAI Reviewer ] (If requested & key available)
              │
              ▼
   [ Final AnalysisResult ] ───► [ JSON Response / CLI Output / Dashboard ]
```

---

## 6. Verification and Quality Gates

Every implementation phase must pass:
1. `pytest -v` automated tests.
2. `ruff check .` style and syntax linting.
3. `mypy src` static type analysis.
4. `pip check` environment integrity validation.
