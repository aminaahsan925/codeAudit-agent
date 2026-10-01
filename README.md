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
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements-dev.txt

# Run the server (from the backend/ directory)
cd backend
uvicorn app.main:app --reload

# In another terminal:
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"repository_url": "https://github.com/octocat/Hello-World"}'
```

## Running tests

```bash
# from the backend/ directory, with the venv active
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
| `CODEAUDIT_AI_ENABLED` | Master switch for the AI layer | `true` |
| `CODEAUDIT_AI_TEMPERATURE` | Model temperature (low = repeatable) | `0.2` |
| `CODEAUDIT_AI_MAX_TOKENS` | Output cap per investigation | `2000` |
| `CODEAUDIT_AI_TIMEOUT_SECONDS` | Model request timeout | `60` |
| `CODEAUDIT_AI_MAX_RETRIES` | Bounded retries (transient failures) | `2` |
| `CODEAUDIT_AI_MAX_CONTEXT_CHARS` | Hard prompt context cap | `24000` |
| `CODEAUDIT_AI_MAX_CONTEXT_FILES` | Max files in context | `12` |
| `CODEAUDIT_AI_MAX_FILE_CHARS` | Per-file excerpt cap | `6000` |
| `CODEAUDIT_AI_MAX_FINDINGS` | Max deterministic findings sent | `25` |
| `CODEAUDIT_AI_CONTEXT_LINES` | Source lines around each finding | `15` |
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
    "files_discovered": 30, "files_scanned": 24,
    "files_deep_analyzed": 20, "files_unsupported": 4,
    "files_skipped": 6, "files_failed_parse": 0,
    "findings_total": 5, "findings_dropped": 0,
    "findings_by_severity": { "high": 2 }, "findings_by_category": { "security": 2 },
    "skip_reasons": { "ignored_dir": 4, "binary": 2 }
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
    "score": 1, "level": "low",
    "breakdown": {
      "formula": "per_finding_score = severity_weight * confidence_factor * reachability_factor; repository_score = min(10, round(sum(per_finding_score) / 100)), an integer on a 0-10 scale. ...",
      "severity_weights": {"critical": 100, "high": 60, "medium": 30, "low": 10, "info": 1},
      "confidence_factors": {"high": 1.0, "medium": 0.7, "low": 0.4},
      "reachability_factors": {"exposed": 1.25, "internal": 1.0},
      "findings_counted": 5, "total_weighted_points": 84.0
    }
  },
  "ai": {
    "status": "enabled", "provider": "nemotron", "model": "nvidia/nemotron-3-ultra",
    "prompt_version": "codeaudit-security-v1", "model_calls": 1,
    "deterministic_findings": 5, "findings_enriched": 5,
    "ai_findings_accepted": 1, "ai_findings_dropped": 0, "duplicates_merged": 2
  }
}
```

`ai.status` is `disabled` when no credentials are configured, `failed` /
`unavailable` when the provider errors — deterministic findings are always
returned regardless.

### File accounting

Every discovered file lands in exactly one terminal bucket:

| Field | Meaning |
|---|---|
| `files_discovered` | Every file entry the walk encountered (directories excluded) |
| `files_scanned` | Passed exclusion filters; read and content-sniffed |
| `files_deep_analyzed` | Python files successfully parsed **and** run through the detectors |
| `files_unsupported` | Scanned but not deep-analyzable (non-Python / unknown language) |
| `files_skipped` | Excluded by ignore rules, size/count/payload limits, or unreadable — see `skip_reasons` |
| `files_failed_parse` | Python files whose AST parse failed |

Reconciliation invariant (enforced by the API schema itself):

```
files_discovered == files_deep_analyzed + files_unsupported + files_skipped + files_failed_parse
files_scanned    == files_deep_analyzed + files_unsupported + files_failed_parse
```

### Risk scoring

The repository score is an integer on a **0–10** scale:

```
per_finding_score = severity_weight * confidence_factor * reachability_factor
repository_score  = min(10, round(sum(per_finding_score) / 100))
```

Bands: 8+ critical, 5+ high, 3+ medium, otherwise low. `reachability_factor`
is 1.25 when the finding's file path suggests web-exposed code
(views/routes/handlers/controllers/api), else 1.0 — path-substring matching
only, never a claim about data flow. The full breakdown (weights, factors,
formula, findings counted, total weighted points) ships in every response so
the score is auditable. Heuristic, not scientifically validated — no accuracy
or benchmark claims are made.

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
      every finding carries the exact source line as evidence:
      hardcoded_secret, sql_string_construction, unsafe_html_render,
      dangerous_eval, dangerous_exec, subprocess_shell_true, os_system,
      weak_crypto, long_function, bare_except
      ↓
FindingValidator.validate_findings — HARD GATE: file must exist, line must
      exist, evidence must match the cited line; failures are dropped
      ↓
AI investigation (Phase 2, optional) — Nemotron reasons over the
      deterministic evidence: assesses each finding (confirmed / uncertain /
      unlikely), proposes additional issues; every AI output is normalized,
      schema-validated, deduplicated against deterministic anchors, and run
      through the SAME evidence hard gate. AI failure degrades gracefully:
      deterministic findings are always returned
      ↓
RiskEngine.score_risk — deterministic, transparent formula with a full
      breakdown in the response: 0-10 integer score, bands 8+/5+/3+,
      severity x confidence x reachability (heuristic, not validated).
      The model never sets the score; it only contributes structured findings
      ↓
Structured AnalysisResult JSON (includes an `ai` metadata block)
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
│   │   ├── ai_errors.py          # typed AI error contract (AI_* codes)
│   │   ├── ai_context_builder.py # bounded, deterministic evidence selection
│   │   ├── ai_result_processor.py# assessment application + dedup (pure)
│   │   ├── nemotron_service.py   # real Nemotron via Token Factory (Phase 2)
│   │   ├── prompts/              # versioned prompts (codeaudit-security-v1)
│   │   └── report_generator.py   # markdown/dict rendering
│   ├── scripts/
│   │   ├── check_token_factory.py# /v1/models diagnostic (manual)
│   │   └── smoke_nemotron.py     # tiny live smoke test (manual, not in CI)
│   ├── utils/
│   │   ├── constants.py     # ignore rules, limits, risk weights
│   │   └── file_utils.py    # binary detection, safe reading
│   ├── tests/
│   │   ├── fixtures/        # planted SQLi / secret / XSS / eval / invalid / mixed repos
│   │   ├── fakes.py         # FakeAIProvider + fake OpenAI client (tests only)
│   │   └── test_*.py        # 144 hermetic tests (no network)
│   ├── requirements.txt / requirements-dev.txt
│   └── .env.example
├── README.md
└── LICENSE                  # Apache-2.0
```

## Phase 2 — Nemotron AI reasoning (Nebius Token Factory)

Phase 2 adds one real AI reasoning layer on top of the deterministic
pipeline. It does **not** replace static analysis: deterministic findings
remain the evidence anchor, and the risk score stays fully deterministic.

### Provider architecture

```
AnalysisOrchestrator
        ↓  AIProvider.investigate(findings, context) -> AIInvestigationResult
   ┌────┴─────┐
   ▼          ▼
FakeAIProvider   NemotronService  (real OpenAI-compatible client → /v1)
(tests only)     (production)
```

The orchestrator depends on the `AIProvider` protocol, never on SDK
details. `NemotronService` is auto-selected when `NEBIUS_API_KEY` and
`NEMOTRON_MODEL` are set; otherwise analysis runs deterministic-only
(`ai.status: "disabled"`). Tests inject `FakeAIProvider` — a fake is never
silently active in production.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `NEBIUS_API_KEY` | — | Token Factory key (never logged, never committed) |
| `NEMOTRON_MODEL` | — | Model id, resolved against the live `/v1/models` catalog |
| `NEBIUS_BASE_URL` | `https://api.tokenfactory.nebius.com/v1` | Token Factory endpoint |
| `CODEAUDIT_AI_ENABLED` | `true` | Master switch for the AI layer |
| `CODEAUDIT_AI_TEMPERATURE` | `0.2` | Low temperature for repeatable analysis |
| `CODEAUDIT_AI_MAX_TOKENS` | `2000` | Output cap per investigation |
| `CODEAUDIT_AI_TIMEOUT_SECONDS` | `60` | Hard request timeout |
| `CODEAUDIT_AI_MAX_RETRIES` | `2` | Bounded SDK retries (transient failures only) |
| `CODEAUDIT_AI_MAX_CONTEXT_CHARS` | `24000` | Hard cap on prompt context |
| `CODEAUDIT_AI_MAX_CONTEXT_FILES` | `12` | Max files in context |
| `CODEAUDIT_AI_MAX_FILE_CHARS` | `6000` | Per-file excerpt cap |
| `CODEAUDIT_AI_MAX_FINDINGS` | `25` | Max deterministic findings sent |
| `CODEAUDIT_AI_CONTEXT_LINES` | `15` | Source lines around each finding |

Do **not** copy a model identifier from an old guide — resolve it at runtime:

```bash
cd backend
NEBIUS_API_KEY=... python scripts/check_token_factory.py
```

The script reports reachability, authentication, and whether the configured
model id is actually in the catalog (auth success ≠ model available).

### AI analysis flow

```
Deterministic findings + scan
        ↓
ai_context_builder — deterministic relevance selection, hard budgets:
  1. finding files ± N lines (finding's own line never truncated away)
  2. entry-point-like files (main.py, app.py, routes/, handlers/, …)
  3. files imported by finding-bearing files (parsed import symbols)
        ↓  (never the whole repository)
Nemotron — one bounded chat/completions call, response_format json_object
  system prompt: evidence rules + prompt-injection defense
  user message: findings + <repository_evidence>…</repository_evidence>
  repository content is UNTRUSTED DATA — never instructions
        ↓
Structured output → normalization → Pydantic validation → fail-closed reject
        ↓
ai_result_processor — apply assessments (confirmed/uncertain/unlikely;
  uncertain demotes confidence one step, unlikely demotes to low;
  id/file/line/evidence/severity/detector NEVER rewritten) +
  deduplicate AI candidates vs deterministic anchors (same file + category
  + ±2 lines → merged, never double-shown)
        ↓
FindingValidator — the SAME hard gate runs over every AI-discovered
  candidate: unknown file, out-of-range line, or mismatched evidence ⇒ dropped
        ↓
RiskEngine — deterministic scoring over all validated findings
        ↓
AnalysisResult.ai — {status, provider, model, findings_enriched,
  ai_findings_accepted, ai_findings_dropped, duplicates_merged, …}
```

### Failure behavior

AI failure never destroys deterministic analysis. Typed errors
(`AI_PROVIDER_NOT_CONFIGURED`, `AI_MODEL_UNAVAILABLE`, `AI_REQUEST_TIMEOUT`,
`AI_RATE_LIMITED`, `AI_UPSTREAM_ERROR`, `AI_INVALID_RESPONSE`,
`AI_OUTPUT_INVALID`) map to a degraded `ai` block (`status: failed` /
`unavailable`, sanitized message) while deterministic findings, risk, and a
200 response are preserved. Invalid model output is rejected outright —
never guessed into a finding.

### Test strategy

144 hermetic tests, no network: fake OpenAI client exercises timeouts,
rate limits, auth failures, 5xx, malformed/fenced/invalid JSON, path
traversal; context-builder tests pin budgets and determinism; prompt tests
prove injection text stays inside `<repository_evidence>` delimiters;
processor tests pin enrichment/dedup rules; an end-to-end test runs
fixture → fake AI → validation → dedup → risk. The live path is covered by
manual scripts only:

```bash
cd backend
NEBIUS_API_KEY=... NEMOTRON_MODEL=... python scripts/smoke_nemotron.py
```

No accuracy/precision benchmarks are claimed — none have been measured.

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

## Limitations

- Deep analysis is Python-only; other languages are detected but not parsed.
- 10 deterministic detectors; Nemotron adds reasoning but no new detector families yet.
- AI enrichment is one investigation call per analysis (no per-finding agent fan-out).
- No fix generation, no re-scan/verification loop, no PDF reports (later phases).
- No frontend, Docker, CI/CD, auth, or database — intentionally out of scope.
