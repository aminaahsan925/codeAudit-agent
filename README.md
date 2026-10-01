# CodeAudit Agent

Evidence-driven security and code-quality analysis for GitHub repositories.
Built for the NEBIUS x NVIDIA Global AI Hackathon (Best Apps & Agents track).

**Phase 1 — backend foundation.** A FastAPI backend that clones a public
GitHub repository, discovers analyzable files, parses Python with the AST,
runs deterministic static analysis, validates every finding against the real
source (the evidence hard gate), scores risk with a transparent formula, and
returns structured JSON. No AI calls in Phase 1 — the Nemotron integration
lands in Phase 2 behind a provider interface.

> The risk formula is a documented heuristic, not a scientifically validated
> measure. No accuracy or benchmark claims are made.

## Quickstart

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

# Run the server
uvicorn app.main:app --reload

# In another terminal:
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"repository_url": "https://github.com/octocat/Hello-World"}'
```

## Running tests

```bash
cd backend
pytest tests/ -q
```

Tests are hermetic: no test touches the network (the clone step is stubbed;
metadata fetching degrades gracefully).

## Environment variables

Copy `backend/.env.example` to `backend/.env` and fill in what you need.
Only the AI variables matter in Phase 2; everything else has safe defaults.

| Variable | Purpose | Default |
|---|---|---|
| `NEBIUS_API_KEY` | Nebius Token Factory key (Phase 2) | — |
| `NEMOTRON_MODEL` | Nemotron model identifier (Phase 2; verify against current Nebius docs) | — |
| `NEBIUS_BASE_URL` | Token Factory base URL | `https://api.tokenfactory.nebius.com/v1` |
| `GITHUB_TOKEN` | Raises GitHub API rate limits for metadata | — |
| `CODEAUDIT_MAX_FILE_SIZE` | Skip files larger than this (bytes) | `1000000` |
| `CODEAUDIT_MAX_FILES` | Max files analyzed per repo | `2000` |
| `CODEAUDIT_MAX_TOTAL_BYTES` | Max total analyzed payload (bytes) | `50000000` |
| `CODEAUDIT_CLONE_TIMEOUT` | `git clone` timeout (seconds) | `120` |
| `CODEAUDIT_MAX_FUNCTION_LINES` | `long_function` detector threshold | `50` |
| `CODEAUDIT_LOG_LEVEL` | Logging level | `INFO` |

## API

### `GET /health`
Liveness probe. Returns `{"status": "ok", "version": "0.1.0"}`.

### `POST /analyze`
Analyzes a public GitHub repository.

Request:
```json
{ "repository_url": "https://github.com/owner/repo" }
```

Response (structured):
```json
{
  "repository": { "owner": "owner", "name": "repo", "url": "..." },
  "summary": {
    "files_discovered": 30, "files_analyzed": 24, "files_skipped": 6,
    "files_failed_parse": 0, "findings_total": 5,
    "findings_by_severity": { "high": 2 }, "findings_by_category": { "security": 2 }
  },
  "findings": [
    {
      "id": "sql_string_construction:backend/users.py:47",
      "category": "security", "severity": "high",
      "title": "Potential SQL injection",
      "file": "backend/users.py", "line": 47,
      "evidence": "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)",
      "suggested_fix": "Use parameterized queries ...",
      "confidence": "medium", "source": "deterministic",
      "detector": "sql_string_construction", "validation": "passed"
    }
  ],
  "risk": {
    "score": 8, "level": "low",
    "breakdown": { "formula": "...", "severity_weights": {...}, "confidence_factors": {...}, "reachability_factors": {...} }
  }
}
```

Errors are structured: `{"error": {"code": "INVALID_REPOSITORY_URL", "message": "..."}}`
with codes `INVALID_REPOSITORY_URL` (422), `REPOSITORY_NOT_FOUND` (404),
`CLONE_TIMEOUT` (504), `CLONE_FAILED` (502), `REPOSITORY_TOO_LARGE` (413,
repo exceeds the file-count or payload budget), `INTERNAL_ERROR` (500).

## Analysis pipeline

```
POST /analyze
      ↓
Validate request (typed Pydantic model, strict GitHub URL check)
      ↓
GitHubService.fetch_repo — shallow clone (--depth 1) into a temp dir,
      timeout-guarded, always cleaned up; repository code is NEVER executed
      ↓
RepositoryScanner.scan_files — ignore rules (.git, node_modules, venv, …),
      binary/empty/oversize skip, symlink refusal, size/count/payload limits
      ↓
CodeParser.parse — Python AST → functions/classes/imports;
      one broken file cannot abort the analysis
      ↓
StaticAnalyzer.analyze_static — 10 deterministic detectors (Python only),
      every finding carries the exact source line as evidence
      ↓
FindingValidator.validate_findings — HARD GATE: file must exist, line must
      exist, evidence must match the cited line; failures are dropped
      ↓
RiskEngine.score_risk — deterministic, transparent formula with a full
      breakdown in the response (heuristic, not validated)
      ↓
Structured AnalysisResult JSON
```

The `AnalysisOrchestrator` exposes each stage as a tool-style method
(`fetch_repo`, `scan_files`, `parse`, `analyze_static`, `validate_findings`,
`score_risk`) — the honest single-agent boundary Phase 3's Nemotron reasoning
will drive.

## Project structure

```
codeaudit-agent/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI app: routes + error mapping only
│   │   └── config.py        # env-based settings, no secrets committed
│   ├── models/
│   │   └── schemas.py       # Pydantic contracts (enums keep values consistent)
│   ├── services/
│   │   ├── orchestrator.py       # pipeline + agent-with-tools boundary
│   │   ├── github_service.py     # URL validation, shallow clone, metadata
│   │   ├── repository_scanner.py # safe file discovery, language detection
│   │   ├── code_parser.py        # Python AST parsing, per-file error capture
│   │   ├── static_analyzer.py    # 10 deterministic detectors
│   │   ├── finding_validator.py  # evidence hard gate
│   │   ├── risk_engine.py        # transparent risk formula
│   │   ├── ai_provider.py        # provider-agnostic AI interface + test stub
│   │   ├── nemotron_service.py   # Nemotron provider (interface only in Phase 1)
│   │   └── report_generator.py   # markdown/dict rendering (interface only)
│   ├── utils/
│   │   ├── constants.py     # ignore rules, limits, risk weights
│   │   └── file_utils.py    # binary detection, safe reading
│   ├── tests/
│   │   ├── fixtures/        # planted SQLi / secret / XSS / eval / invalid / mixed repos
│   │   └── test_*.py        # 56 hermetic tests
│   ├── requirements.txt / requirements-dev.txt
│   └── .env.example
├── README.md
└── LICENSE                  # Apache-2.0
```

## Design principles

- **Evidence first:** a finding without verifiable file + line + matching
  source snippet does not ship.
- **Deterministic before AI:** anything reliably detectable by structure or
  pattern never waits for a model.
- **No fake agents:** one real orchestrator with tools; specialist roles only
  if they earn their place later.
- **Safe by default:** untrusted repos are cloned shallow, never executed,
  and analyzed under strict size/time limits.
- **Honest scoring:** the risk formula is shown in every response.

## Limitations (Phase 1)

- Deep analysis is Python-only; other languages are detected but not parsed.
- 10 deterministic detectors — no AI reasoning yet (Phase 2).
- No fix generation, no re-scan/verification loop, no PDF reports (later phases).
- No frontend, Docker, CI/CD, auth, or database — intentionally out of scope.
