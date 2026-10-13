# Cloud Deployment Strategy & Readiness Guide

## 1. Overview & Architecture Plan

This document outlines the recommended, security-conscious deployment strategy for the **AI-Powered Bug Detection System**.

### Target Architecture
- **Frontend Dashboard**: Netlify (Static Hosting & CDN).
- **Backend REST API**: Python Web Service (Render, Fly.io, or Containerized Cloud Service).
- **Connection Model**: Netlify reverse-proxy rewrites (`/api/*` -> Backend) or direct CORS-authenticated requests.

```
[ User Browser ]
       │
       ├───► [ Netlify CDN (Static Frontend: HTML/CSS/JS) ]
       │
       └───► [ Netlify /api/* Proxy Rewrite ]
                     │
                     ▼
             [ Backend Web Service (Render / Fly.io / Docker) ]
                     │
                     ├─── [ AST Static Analysis Engine (Zero-Execution) ]
                     ├─── [ In-Memory Sliding-Window Rate Limiter ]
                     └─── [ DEMO_MODE Enforcer (No Persistence / No Paid AI) ]
```

---

## 2. Python Runtime Compatibility Across Providers

| Platform | Native Python Support | Docker / Container Support | Recommendation |
|---|---|---|---|
| **Render Web Services** | Python 3.11 / 3.12 (via `PYTHON_VERSION=3.12.7`) | Full Python 3.14 via `Dockerfile` | Use Render Docker service for Python 3.14.8 parity |
| **Fly.io** | N/A (Docker-native) | Full Python 3.14 via `Dockerfile` | Fully supported |
| **Railway** | Python 3.11 / 3.12 (Nixpacks) | Full Python 3.14 via `Dockerfile` | Fully supported |
| **Netlify** | Static HTML/CSS/JS only | N/A | Host static frontend from `src/bug_detector/static` |

---

## 3. Frontend Deployment (Netlify)

### Configuration
The repository includes a root [`netlify.toml`](../netlify.toml):
- **Publish Directory**: `src/bug_detector/static`
- **Asset Rewrites**: Maps `/static/*` to root assets for backward compatibility.
- **API Proxy**: Redirects `/api/*` to the remote backend service without requiring frontend code modifications or cross-origin issues.

### Deployment Steps (When Approved)
1. Link GitHub repository to Netlify.
2. Set Build Command: *(Leave blank - static files do not require compilation)*.
3. Set Publish Directory: `src/bug_detector/static`.
4. Set Environment Variables:
   - `BACKEND_URL`: `https://your-backend-app.onrender.com`
5. Deploy Site.

---

## 4. Backend Deployment (Render / Docker)

### Mandatory Public Guardrail: `DEMO_MODE=true`
> **CRITICAL SECURITY REQUIREMENT:** When hosting a public backend without multi-tenant authentication, you **MUST** set `DEMO_MODE=true`.

In `DEMO_MODE=true`:
1. Paid OpenAI calls are blocked to prevent credit drainage.
2. Visitor-submitted source code is **never** written to disk or the SQLite database.
3. Private `/api/history` endpoints return `403 Forbidden` to ensure no visitor can view another visitor's submitted code.

### Backend Environment Variables
```ini
ENVIRONMENT=production
DEBUG=false
DEMO_MODE=true
CORS_ORIGINS=["https://your-frontend-site.netlify.app"]
MAX_CODE_SIZE_BYTES=102400
MAX_CODE_LINES=2000
RATE_LIMIT_PER_MINUTE=60
HOST=0.0.0.0
PORT=8000
```

---

## 5. Ephemeral Storage & Free-Tier Limitations

### Render Free Tier
- **Spin-Down Behavior**: Free instances spin down after 15 minutes of inactivity. The first incoming request encounters a ~50-second cold start.
- **Ephemeral Disk**: Local SQLite databases (`bug_detector.db`) are wiped whenever the service restarts or redeploys.
- **No User History Risk in Demo Mode**: Because `DEMO_MODE=true` prevents saving visitor code, ephemeral storage does not impact analysis functionality.

### Netlify Free Tier
- 100 GB monthly bandwidth.
- Automated HTTPS certificates.

---

## 6. Pre-Deployment Verification Checklist

- [x] Static files render properly without local backend (`index.html`, `styles.css`, `app.js`).
- [x] Zero hardcoded backend URLs in frontend source.
- [x] Netlify redirect proxy defined in `netlify.toml`.
- [x] Dockerfile verifies unprivileged execution (`appuser:1000`).
- [x] Non-execution canary tests passing (100% zero-execution invariant).
- [x] Rate limiting active.
- [ ] Explicit User Approval before remote publishing (REQUIRED).
