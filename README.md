# CodeAudit Agent

Evidence-driven security and code-quality analysis for GitHub repositories.
Built for the NEBIUS x NVIDIA Global AI Hackathon (Best Apps & Agents track).

**Phase A — multi-language analysis.** A FastAPI backend that clones a public
GitHub repository, discovers analyzable files, deep-parses Python
**and** JavaScript/TypeScript with language-specific analyzers, runs
deterministic static analysis, validates every finding against the real
source (the evidence hard gate), scores risk with a transparent formula, and
returns structured JSON. Nemotron reasoning plugs in behind the provider
interface with a hard per-mode AI budget.

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
| `CODEAUDIT_FIX_MAX_CONTEXT_CHARS` | Hard fix-prompt context cap (Phase 3) | `12000` |
| `CODEAUDIT_FIX_MAX_FILE_CHARS` | Per-file window cap for fix context (Phase 3) | `4000` |
| `CODEAUDIT_FIX_CONTEXT_LINES` | Source lines around the evidence line (Phase 3) | `20` |
| `CODEAUDIT_FIX_TEMPERATURE` | Model temperature for fix proposals (Phase 3) | `0.2` |
| `CODEAUDIT_FIX_MAX_TOKENS` | Output cap per fix proposal (Phase 3) | `1500` |
| `CODEAUDIT_FIX_MAX_CHANGES` | Max changes accepted per proposal (Phase 3) | `5` |
| `CODEAUDIT_MAX_REMEDIATIONS_PER_REQUEST` | Hard cap on batch remediation (Phase 3) | `3` |
| `CODEAUDIT_AGENT_MODE` | Multi-agent operating mode: `free` (0 AI calls), `economy` (1+1), `full` (4+2) | `free` |
| `CODEAUDIT_MAX_AI_CALLS_PER_ANALYSIS` | Explicit override of the per-analysis AI call cap | mode default |
| `CODEAUDIT_MAX_AI_CALLS_PER_REMEDIATION` | Explicit override of the per-remediation AI call cap | mode default |
| `GITHUB_TOKEN` | Raises GitHub API rate limits for metadata | — |
| `CODEAUDIT_MAX_FILE_SIZE` | Skip files larger than this (bytes) | `1000000` |
| `CODEAUDIT_MAX_FILES` | Max files analyzed per repo | `2000` |
| `CODEAUDIT_MAX_TOTAL_BYTES` | Max total analyzed payload (bytes) | `50000000` |
| `CODEAUDIT_CLONE_TIMEOUT` | `git clone` timeout (seconds) | `120` |
| `CODEAUDIT_MAX_FUNCTION_LINES` | `long_function` detector threshold | `50` |
| `CODEAUDIT_ADVISORY_DB` | Path to the local advisory DB for dependency matching (Phase 4) | `backend/data/advisories.json` |
| `CODEAUDIT_ADVISORY_MAX_AGE_DAYS` | Max DB age before it counts as stale (Phase 4) | `30` |
| `CODEAUDIT_DATABASE_URL` | SQLAlchemy DB URL (Phase 7); SQLite file is created `0600` | `sqlite:///./codeaudit.db` |
| `CODEAUDIT_REQUIRE_AUTH` | Require API-key auth on all endpoints (Phase 7) | `false` |
| `CODEAUDIT_DEV_BOOTSTRAP_KEY` | Print a dev API key on first run (Phase 7; loud warning) | `false` |
| `CODEAUDIT_WEBHOOK_URL` | Signed JSON webhook on completed runs (Phase 8; empty = disabled) | — |
| `CODEAUDIT_WEBHOOK_SECRET` | HMAC secret for webhook signatures (Phase 8) | — |
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

### `POST /remediate`
Proposes and deterministically verifies a fix for one finding
(FIND → FIX → VERIFY). The repository is cloned fresh, the finding is
located in the analysis result, Nemotron proposes a minimal structured patch,
the patch engine validates every change, the patch is applied inside an
isolated temporary workspace, and the deterministic pipeline (AI disabled)
re-analyzes the workspace to verify the outcome. The original repository is
never modified.

Request:
```json
{ "repository_url": "https://github.com/owner/repo", "finding_id": "sql_string_construction:backend/users.py:47" }
```

Response (structured):
```json
{
  "status": "verified",
  "finding_id": "sql_string_construction:backend/users.py:47",
  "proposal": {
    "finding_id": "sql_string_construction:backend/users.py:47",
    "decision": "fix",
    "reasoning": "Parameterize the query ...",
    "changes": [
      {
        "file": "backend/users.py", "start_line": 47, "end_line": 47,
        "old_text": "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)",
        "new_text": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "rationale": "parameterize the query"
      }
    ],
    "provider": "nemotron", "model": "nvidia/nemotron-3-ultra",
    "prompt_version": "codeaudit-remediation-v1"
  },
  "verification": {
    "status": "verified", "verified": true,
    "finding_present_before": true, "finding_present_after": false,
    "original_evidence_present_before": true, "original_evidence_present_after": false,
    "new_findings_introduced": [],
    "reason": "The original finding and its evidence no longer appear ..."
  },
  "changes_applied": [ { "file": "backend/users.py", "start_line": 47, "end_line": 47, "lines_changed": 1 } ],
  "changes_rejected": [],
  "risk_before": { "score": 1, "level": "low", "...": "..." },
  "risk_after": { "score": 0, "level": "low", "...": "..." }
}
```

`status` is one of `verified`, `partially_verified`, `not_verified`,
`patch_rejected`, `new_issue_introduced`, `cannot_verify`, `unavailable`
(AI not configured), or `failed` (AI error — the analysis itself is never
destroyed). Unknown `finding_id` returns 404.

### `POST /remediate/batch`
Remediates several findings, each independently against the original
repository (fixes are never chained). Limited to
`CODEAUDIT_MAX_REMEDIATIONS_PER_REQUEST` (default 3) — more returns 400.

Request:
```json
{ "repository_url": "https://github.com/owner/repo", "finding_ids": ["sql_string_construction:backend/users.py:47"] }
```

Response: a JSON array of remediation results, one per finding.

### `POST /scan/website`
Authorized live security scan of a website — a **separate capability**
from repository analysis (it makes outbound HTTP requests).

Authorization (both required, else 403 before any network I/O):
```json
{
  "target_url": "https://example.com/",
  "authorization_token": "the-token-configured-for-example.com",
  "i_authorize_this_scan": true,
  "include_subdomains": false,
  "active_probes": true
}
```
- `CODEAUDIT_SCAN_TOKENS="example.com:token,..."` configures per-host
  tokens server-side (compared with `hmac.compare_digest`, never
  logged). Empty = every scan refused.
- **Legal warning:** only scan systems you own or are explicitly
  permitted to test. Unauthorized scanning may be illegal.

Safety (see `docs/SECURITY_MODEL.md` for the full model):
- **SSRF guard** on every request and redirect hop: private, loopback,
  link-local (incl. `169.254.169.254`), multicast, reserved ranges
  refused; localhost only with `CODEAUDIT_SCAN_ALLOW_LOCALHOST=true`.
- **Scope enforcement:** crawl stays on the authorized host + path
  prefix (opt-in subdomains); out-of-scope URLs are skipped, never
  fetched.
- **Bounded active probes:** GET-only reflected-XSS canary and SQL-error
  probes, rate-limited; findings capped at MEDIUM with a
  manual-verification note. No data is ever extracted.

Response: `urls_scanned`, `findings` (each with `source: "live-scan"`,
`rule_id` like `LIVE-007`, CWE), `checks_run`, `requests_made`, and a
`disclaimer` — a limited scan never claims the site is secure.

### File accounting

Every discovered file lands in exactly one terminal bucket:

| Field | Meaning |
|---|---|
| `files_discovered` | Every file entry the walk encountered (directories excluded) |
| `files_scanned` | Passed exclusion filters; read and content-sniffed |
| `files_deep_analyzed` | Files in deeply analyzed languages (Python, JavaScript/TypeScript) successfully parsed **and** run through the detectors, **plus** files covered by a structural supply-chain analyzer (manifests, Dockerfiles, workflows, compose files) |
| `files_unsupported` | Scanned but not deep-analyzable and not supply-chain-covered (recognized language without a registered analyzer, or unknown language) |
| `files_skipped` | Excluded by ignore rules, size/count/payload limits, or unreadable — see `skip_reasons` |
| `files_failed_parse` | Files whose parser reported a structural parse failure |

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
Language analyzers (services/languages/) — one plugin per deeply analyzed
      language, routed by the registry; each parses to symbols and runs its
      own deterministic detectors, every finding carrying the exact source
      line as evidence:
      · Python (AST): hardcoded_secret, sql_string_construction,
        unsafe_html_render, dangerous_eval, dangerous_exec,
        subprocess_shell_true, os_system, weak_crypto, long_function,
        bare_except
      · JavaScript/TypeScript (tree-sitter): js_dangerous_eval,
        js_function_constructor, js_command_injection, js_xss_dom_sink,
        js_react_dangerous_html, js_hardcoded_secret,
        js_sql_string_construction, js_weak_crypto, js_implied_eval
      ↓
FindingValidator.validate_findings — HARD GATE: file must exist, line must
      exist, evidence must match the cited line; failures are dropped
      ↓
SupervisorAgent — multi-agent coordination (Phase 3 upgrade): builds the
      execution plan, runs security/performance/quality specialists IN
      PARALLEL over the validated findings, then (economy/full) a budgeted
      Nemotron evidence review over specialist outputs + bounded shared
      excerpts; deterministic fusion merges everything (anchors win,
      provenance stamped). The AI step is the evidence agent's bounded call:
      Nemotron reasons over the deterministic evidence, assessing each
      finding (confirmed / uncertain / unlikely) and proposing additional
      issues; every AI output is normalized, schema-validated, deduplicated
      against deterministic anchors, and run through the SAME evidence hard
      gate. AI failure degrades gracefully: deterministic findings are
      always returned. In free mode the evidence step is skipped entirely —
      zero Nebius calls by construction
      ↓
RiskEngine.score_risk — deterministic, transparent formula with a full
      breakdown in the response: 0-10 integer score, bands 8+/5+/3+,
      severity x confidence x reachability (heuristic, not validated).
      The model never sets the score; it only contributes structured findings
      ↓
Structured AnalysisResult JSON (includes an `ai` metadata block)
```

The `SupervisorAgent` coordinates each stage as a specialist agent
(`agents/supervisor_agent.py`) — security, performance, and quality triage in
parallel, a budgeted Nemotron evidence review per the configured agent mode,
and deterministic fusion. The `AnalysisOrchestrator` remains the tool layer
the supervisor drives (`fetch_repo`, `scan_files`, `parse`, `analyze_static`,
`validate_findings`, `score_risk`).

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
│   │   ├── languages/            # per-language analyzer plugins + registry
│   │   │   ├── python_analyzer.py      # adapter: code_parser + static_analyzer
│   │   │   ├── javascript_analyzer.py  # tree-sitter JS/TS, 9 detectors
│   │   │   └── registry.py             # single source of truth for deep analysis
│   │   ├── code_parser.py        # Python AST parsing, per-file error capture
│   │   ├── static_analyzer.py    # 10 deterministic Python detectors
│   │   ├── finding_validator.py  # evidence hard gate
│   │   ├── risk_engine.py        # transparent risk formula
│   │   ├── ai_provider.py        # provider-agnostic AI interface + test stub
│   │   ├── ai_errors.py          # typed AI error contract (AI_* codes)
│   │   ├── ai_context_builder.py # bounded, deterministic evidence selection
│   │   ├── ai_result_processor.py# assessment application + dedup (pure)
│   │   ├── nemotron_service.py   # real Nemotron via Token Factory (Phase 2)
│   │   ├── prompts/              # versioned prompts (codeaudit-security-v1)
│   │   │   └── report_generator.py   # markdown/dict rendering
│   │   ├── supplychain/        # Phase 4: dependency/secret/config scanning
│   │   │   ├── manifests.py          # 7 manifest format parsers (never exec)
│   │   │   ├── advisories.py         # AdvisorySource + LocalAdvisoryDB
│   │   │   ├── dependencies.py       # DEP-001…004
│   │   │   ├── secrets.py            # SECRET-001…006 (redacted, sensitive)
│   │   │   ├── redaction.py          # sk-live-****c123 redaction helpers
│   │   │   ├── config.py             # Dockerfile / GHA / compose (CFG-*)
│   │   │   ├── sbom.py               # CycloneDX-inspired SBOM builder
│   │   │   └── dispatch.py           # file-kind routing + accounting
│   │   ├── data/
│   │   │   └── advisories.example.json  # advisory DB schema (copy to advisories.json)
│   │   ├── scripts/
│   │   │   ├── check_token_factory.py# /v1/models diagnostic (manual)
│   │   │   ├── refresh_advisories.py # populate advisory DB from OSV.dev (manual)
│   │   │   └── smoke_nemotron.py     # tiny live smoke test (manual, not in CI)
│   ├── utils/
│   │   ├── constants.py     # ignore rules, limits, risk weights
│   │   └── file_utils.py    # binary detection, safe reading
│   ├── tests/
│   │   ├── fixtures/        # planted SQLi / secret / XSS / eval / invalid / mixed repos
│   │   ├── fakes.py         # FakeAIProvider + fake OpenAI client (tests only)
│   │   └── test_*.py        # 386 hermetic tests (no network)
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
   ┌────┴──────────────────┐
   ▼                       ▼
FakeAIProvider   NemotronService (Nebius)   GroqService (Groq)
(tests only)     (default, hackathon target) (opt-in via CODEAUDIT_AI_PROVIDER=groq)
```

The orchestrator depends on the `AIProvider` protocol, never on SDK
details. `services/provider_factory.py:build_ai_provider()` selects the
provider: `NemotronService` when `NEBIUS_API_KEY` and `NEMOTRON_MODEL` are
set (default), `GroqService` when `CODEAUDIT_AI_PROVIDER=groq` with
`GROQ_API_KEY`/`GROQ_MODEL` set (free no-card tier, useful for live
AI-layer testing); otherwise analysis runs deterministic-only
(`ai.status: "disabled"`). `GroqService` subclasses `NemotronService`,
reusing the bounded-context, structured-output, and error machinery —
only identity and defaults differ, so reports attribute results to the
provider that actually ran. Tests inject `FakeAIProvider` — a fake is never
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
| `CODEAUDIT_AI_RESPONSE_FORMAT` | `json_object` | Set to `none` if your Nemotron deployment rejects `response_format` (answer is read from `reasoning_content` when `content` is empty) |

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

144 hermetic tests cover the Phase 2 AI layer (no network): fake OpenAI client exercises timeouts,
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

```bash
cd backend
NEBIUS_API_KEY=<redacted>
```

No accuracy/precision benchmarks are claimed — none have been measured.

## Phase 3 — Verified remediation (FIND → FIX → VERIFY)

Phase 3 adds the remediation layer **after** findings are produced. It does
not replace the Phase 1/2 pipeline. The model proposes a fix; the system
controls the patch; the system verifies the result. A claimed fix without
verification is not a verified fix.

### The loop

```
POST /remediate {repository_url, finding_id}
        ↓
locate the finding in the BEFORE analysis (unknown id → 404)
        ↓
FixContext — bounded evidence window around the cited line (the evidence
line is expanded outward from, so it can never be truncated), enclosing
function/class, budgets recorded
        ↓
Nemotron propose_fix — versioned prompt (codeaudit-remediation-v1),
JSON-only contract, repository bytes treated as UNTRUSTED DATA inside
<repository_evidence> delimiters (injection attempts neutralized)
        ↓
normalize → Pydantic validate → fail-closed reject; finding_id / provider /
model / prompt_version are STAMPED BY THE SYSTEM, never trusted from the model
        ↓
PatchEngine.validate_changes — deterministic gate per change:
  safe relative path (no traversal, no absolute), v1 scope (the finding's
  own file only), file exists, valid line range, old_text matches EXACTLY
  at the claimed lines (whitespace-tolerant), ranges do not overlap
        ↓
temporary_workspace — the repo is copied to an isolated temp dir
(.git excluded, symlinks preserved as links); the ORIGINAL IS NEVER MODIFIED
        ↓
apply_validated_changes — bottom-up, re-verifies old_text against disk,
refuses symlinks and root escapes; valid changes apply, invalid ones are
recorded as RejectedChange (partial application, never half-applied)
        ↓
deterministic AFTER analysis (AI disabled) on the workspace
        ↓
verification_engine.verify_fix — BEFORE vs AFTER on repository content only:
  VERIFIED (finding + evidence gone, nothing new in changed files),
  NOT_VERIFIED (identity match persists, line shift ≤ 2),
  PARTIALLY_VERIFIED (same detector fires on the same file within 10 lines),
  NEW_ISSUE_INTRODUCED (original gone + new verified finding in changed files),
  CANNOT_VERIFY (patched file missing, or evidence present but detector silent)
        ↓
RemediationResult — {status, proposal, verification, changes_applied,
changes_rejected, risk_before, risk_after}; workspace always cleaned up
```

### Failure behavior

Every failure mode degrades to a status, never an exception, and the
original repository is byte-identical afterwards: AI not configured →
`unavailable`; AI error / malformed JSON / schema failure → `failed` with a
sanitized error code (no tracebacks, no raw model text); nothing valid to
apply → `patch_rejected`; the model declines (`cannot_fix`) → `not_verified`
with the proposal attached. The BEFORE analysis is never destroyed.

### Test strategy

221 hermetic tests, no network: patch-engine tests cover every rejection
(traversal, absolute, unrelated file, wrong old_text, overlapping ranges,
symlinks, root escapes); context/prompt tests pin budgets and delimiter
injection defense; verification-engine tests pin all five outcomes;
end-to-end tests run the §20 scenarios (good fix → verified, `%`-formatting
fix → not_verified, `eval` fix → new_issue_introduced) with a fake provider,
plus risk recalculation and line-shift cases; a parametrized failure-mode
test asserts the original repo is byte-identical across 8 degradation paths;
API tests cover `/remediate` and `/remediate/batch` (404/400 mapping, cap
enforcement). No live Nemotron remediation calls — none have been measured.

## Multi-agent backend (Phase 3 upgrade)

The analysis and remediation paths are now coordinated by a **Supervisor
agent** driving specialist agents — a hybrid design, not a model-everywhere
design. The honest labeling matters: the specialists that do the real
detection work are **deterministic**; Nemotron is used only where judgment
adds value, inside hard cost caps.

### Agent roster

| Agent | Kind | Role |
|---|---|---|
| `supervisor` | deterministic | Builds the execution plan, enforces AI budgets, consolidates results |
| `security` | hybrid | Triages validated security findings; budgeted AI review in full mode |
| `performance` | hybrid | Conservative AST rules (nested loops, concat-in-loop, expensive-call-in-loop); budgeted AI review in full mode |
| `quality` | hybrid | Wraps analyzer quality detectors + conservative AST extras (branch complexity, parameter count); budgeted AI review in full mode |
| `evidence` | AI | One bounded Nemotron review over specialist findings + shared excerpts (economy/full) |
| `fusion` | deterministic | Merges specialist + evidence outputs; deterministic anchors win; stamps `provenance` |
| `fix` | AI | Proposes a structured fix on explicit request only; never writes files |
| `verification` | deterministic | Coordinates deterministic verification; never overrides the verdict |
| `patch_guard` | deterministic | Validates every proposed change (path/line/old_text/overlap gates) |

The supervisor runs the three specialists **in parallel** (they are
independent — each triages only its own category). The evidence agent sees
the specialists' outputs plus a bounded shared context (source excerpts, not
whole files). Fusion deduplicates on file/line/detector and stamps
`provenance: {detected_by, reviewed_by, fixed_by, verified_by}` on every
finding.

### Modes and cost control (`CODEAUDIT_AGENT_MODE`)

| Mode | Analysis AI calls | Remediation AI calls | Behavior |
|---|---|---|---|
| `free` (default) | 0 | 0 | Deterministic specialists only. The supervisor forces the stub provider — **zero Nebius calls by construction**, even if a provider is injected |
| `economy` | 1 | 1 | One Nemotron evidence-review call; remediation calls Nemotron only on explicit user request |
| `full` | 4 | 2 | Selective multi-agent reasoning: one budgeted review per specialist with findings, then evidence review |

Overrides: `CODEAUDIT_MAX_AI_CALLS_PER_ANALYSIS` /
`CODEAUDIT_MAX_AI_CALLS_PER_REMEDIATION` (explicit caps; never unlimited).
Budgets are enforced by a thread-safe `AIBudgetManager` owned by the
supervisor — the **sole** enforcement point; analysis and remediation
budgets are separate. A request-scoped `AICallCache` deduplicates identical
AI calls within a run. Budget exhaustion surfaces as the controlled status
`AI_BUDGET_EXHAUSTED` — never an exception, never a silent extra call.

### Guarantees (unchanged, now per-agent)

- **Deterministic anchors win:** the evidence agent and fusion can attach
  reasoning and metadata, but never rewrite a finding's id, file, line,
  evidence, severity, or category.
- **Evidence hard gate** applies to every finding, human- or AI-sourced.
- **Fix only on request:** analysis never remediates; `/remediate` runs the
  FIND → FIX → VERIFY cycle with `agent_trail` recording every participant.
- **Original repository never modified** — patches apply in an isolated
  temp workspace that is always cleaned up.
- **No fake benchmarks:** the demo fixture
  (`backend/tests/fixtures/multiagent_demo/`) is a controlled 6-finding
  repo used by hermetic tests, not a performance claim.

Every `AnalysisResult` now carries `agents` (per-agent status, timings,
model calls, prompt versions) and `ai_budget` (mode, limit, used,
remaining); every `RemediationResult` carries `agent_trail`.

## Phase 4 — Supply-chain scanning (dependencies, secrets, config)

A third deterministic stage (`backend/services/supplychain/`) runs after
the language analyzers on every scanned file. Findings flow through the
same validation → risk → fusion → AI pipeline, with two hard guarantees:

- **Secrets never reach AI.** Every secret finding carries redacted
  evidence (`sk-live-****c123`, never the raw value) and `sensitive=true`;
  the AI context builder excludes sensitive findings *and their files*
  from all context stages, and fix windows are redacted too.
- **No fabricated vulnerabilities.** Dependency findings match only
  against a local advisory database you control; a package with no
  advisory entry is never reported as vulnerable.

**Dependencies** — parses `requirements.txt`, `setup.py` (AST, never
executed), `pyproject.toml`, `Pipfile`/`Pipfile.lock`, `package.json`,
`package-lock.json`. DEP-001 fires only on a concrete-version advisory
match; DEP-002 flags fully unpinned declarations; DEP-003 (INFO) reports
a stale/missing advisory DB; DEP-004 reports manifest parse errors.

**Advisory database** — `backend/data/advisories.json` (JSON, schema in
`backend/data/advisories.example.json`). Populate it from OSV.dev:

```powershell
cd backend
..\.venv\Scripts\python.exe scripts\refresh_advisories.py
```

(`refresh_advisories.py` is manual and network-dependent — never part of
tests or analysis.) Without a populated DB every dependency finding
carries `database_status: unavailable` and no vulnerability is reported.
Set `CODEAUDIT_ADVISORY_DB` to use a different path,
`CODEAUDIT_ADVISORY_MAX_AGE_DAYS` (default 30) for staleness.

**Secrets** — PEM keys, AWS (`AKIA…`), GitHub tokens, Google API keys,
Stripe keys, and high-entropy strings assigned to secret-like names.
The Python/JS hardcoded-secret rules now redact evidence, mark findings
sensitive, and defer token-shaped values to these detectors (no
double-reporting).

**Config** — Dockerfile (no `USER`, `:latest` tag, secrets in `ENV`/`ARG`,
`ADD` vs `COPY`, curl-pipe-shell), GitHub Actions (`permissions:
write-all`, `pull_request_target` + checkout, unpinned action refs), and
compose files (`privileged`, secrets in `environment:`). Line-based
checks, documented per rule as a first net rather than a proof.

**SBOM** — every `AnalysisResult` carries `sbom`: a CycloneDX-inspired
inventory (name, version, type, scope) with the advisory DB status
recorded and an explicit note that it is not full spec compliance and
the transitive closure is not resolved.

## Phase 6 — Authorized live website scanning

`POST /scan/website` (`backend/services/livescan/`) tests a deployed
site: bounded crawl, passive checks, and minimal GET-only active
probes. Findings share the Finding contract with `source: "live-scan"`,
`rule_id` (`LIVE-001`…`LIVE-021`), and CWE mappings.

**Guards are built before the scanner** (full model in
`docs/SECURITY_MODEL.md`):
- **Authorization:** per-host token (`CODEAUDIT_SCAN_TOKENS`) compared
  with `hmac.compare_digest` **plus** `"i_authorize_this_scan": true`
  per request — else 403 before any network I/O. No default-allow.
- **SSRF guard:** resolve-then-check on every request and redirect hop;
  refuses private/loopback/link-local/multicast/reserved ranges and
  non-HTTP(S) schemes; defeats decimal/octal/hex IP spellings;
  localhost only via explicit opt-in. Residual DNS-TOCTOU risk is
  documented, not hidden.
- **Scope:** exact host + port + path prefix (opt-in subdomains);
  out-of-scope links and redirect targets are never fetched.
- **Active probes:** reflected-XSS canary and SQL-error probes only —
  GET-only, rate-limited, non-destructive, findings capped at MEDIUM
  with "requires manual verification"; no data extraction, ever.
- **Credentials** (tokens, cookies, auth headers) are never logged,
  stored, or echoed.

**Checks:** transport (LIVE-007), security headers (LIVE-001…005),
cookie flags (LIVE-006, values never recorded), server banners
(LIVE-008), exposed `/.git/HEAD` + `/.env` (LIVE-009, HIGH),
TLS certificate inspection (LIVE-010), reflected-XSS probe (LIVE-020),
SQL-error probe (LIVE-021).

**Honesty:** every result carries a disclaimer — N URLs, M passive
checks, K active probes; absence of findings is not proof of security.
Probe findings are observations, not confirmed exploits. Static
findings never claim deployed exploitability.

**Legal warning:** only scan systems you own or have explicit written
permission to test. Unauthorized security testing may be illegal.

## Phase 7 — Persistence, API keys & jobs

`backend/services/persistence/` (SQLAlchemy 2.0.44) adds durable state:
users, API keys, projects, repo analyses, website scans, immutable
finding snapshots, scan jobs, and usage counters.

- **Auth:** API keys only (`Authorization: Bearer …`). Keys are issued
  once and stored as salted hashes; scopes `read` ⊂ `scan` ⊂ `admin`
  are enforced per endpoint. `CODEAUDIT_REQUIRE_AUTH` (default `false`
  for the local demo) switches the API to 401-without-key. Any network
  deployment must enable it.
- **Tenant isolation:** every query is scoped project→user in the
  repository layer; cross-user access returns 404. Tested at both
  repository and API layers.
- **Jobs:** `?async=true` on `/analyze` and `/scan/website` returns
  202 + job id; `GET /jobs/{id}` polls, `DELETE /jobs/{id}` cancels.
  The worker thread is dev-only and marked as such; production needs a
  separate worker process.
- **History:** `GET /projects/{id}/scans` lists both scan kinds;
  `GET /analyses/{id}` and `GET /website-scans/{id}` return finding
  snapshots. Live-scan credentials for async jobs stay in memory only.
- **Database:** SQLite by default (`CODEAUDIT_DATABASE_URL`,
  file created `0600`); the schema is Postgres-compatible and
  versioned (`upgrade_database()`), Postgres is the production target.
- **Metering:** per-key counters for analyses, scans, and AI calls —
  the data billing will need later. No billing yet.

## Phase 8 — Lifecycle, retest, reports & webhooks

- **Finding lifecycle:** `POST/GET /projects/{id}/findings/status`
  marks findings `acknowledged` / `fixed` (no row = new), keyed by a
  stable fingerprint (rule + file + evidence; line shifts don't break
  it). Tenant-scoped.
- **Retest:** `POST /projects/{id}/retest` re-runs the latest
  analysis/scan and diffs findings into new / persisting / resolved,
  with risk delta. Previously-fixed findings that persist are flagged
  `regressed`; fixed + gone are `verified`. Website retests need fresh
  authorization every time.
- **Reports:** `GET /analyses/{id}/report` and
  `GET /website-scans/{id}/report` export Markdown or self-contained
  HTML (`?format=html`), escaped and disclaimer-carrying.
- **Webhooks:** `CODEAUDIT_WEBHOOK_URL` receives an HMAC-signed JSON
  POST on every completed run (`X-CodeAudit-Signature`). Best-effort,
  never fails the request.

## Phase 9 — Demo frontend & customer workflow

A static, no-build-step web UI in `frontend/` (three files: `index.html`,
`styles.css`, `app.js` — no npm, no bundler). It is the customer-facing
path through the whole product:

- **Analyze repo** — repo URL → `POST /analyze`, optional background-job
  mode (`?async=true`) with live polling of `GET /jobs/{id}`; renders
  the risk score, expandable finding cards with evidence blocks, and AI
  status.
- **Scan website** — target URL + per-host token + mandatory
  "I authorize this scan" checkbox (the API 403s without both);
  optional session cookie for authenticated scans.
- **Findings** — per-project lifecycle: pick a project, see the latest
  run's findings with their `acknowledged` / `fixed` status, and set
  statuses (fingerprint-aware buttons hit
  `POST /projects/{id}/findings/status`).
- **Retest** — `POST /projects/{id}/retest`: new / persisting / resolved
  buckets with `verified` / `regressed` annotations.

Both the analyze and scan forms can attach the run to a project
(`project_id`), which is what makes the lifecycle/history/retest
workflow work end to end. Two small backend endpoints were added for
the UI: `GET /analyses/{id}/findings` and
`GET /website-scans/{id}/findings`, each returning
`{fingerprint, finding}` pairs.

Security notes: every dynamic string is HTML-escaped before rendering
(findings carry code evidence); the scan token is never persisted to
`localStorage`; the UI repeats the honesty rules (evidence-grounded
observations, not confirmed exploits; absence of findings is not proof
of security).

Serve it with any static host (see `frontend/README.md` for deploy
options), or preview locally:

```bash
cd frontend && python -m http.server 8080
# open http://localhost:8080, set Backend to your API URL
```

For a real deployment (Docker, Render/Railway/Fly, env vars, first API
key): see `docs/DEPLOYMENT.md`. For the pre-launch checklist:
`docs/PRODUCTION.md`.

## Design principles

- **Evidence first:** a finding without verifiable file + line + matching
  source snippet does not ship.
- **Deterministic before AI:** anything reliably detectable by structure or
  pattern never waits for a model.
- **No fake agents:** every named agent does real work — deterministic
  specialists triage real findings, the supervisor enforces real budgets,
  and AI agents only act inside those budgets. Agent kinds are labeled
  honestly (`deterministic` / `hybrid` / `ai`) in the registry.
- **Safe by default:** untrusted repos are cloned shallow, never executed,
  and analyzed under strict size/time limits.
- **Honest scoring:** the risk formula is shown in every response.

## Language support

CodeAudit analyzes **Python** and **JavaScript/TypeScript** repositories
deeply, and provides extensible multi-language security scanning: each
language gets its own parser and detector set behind a plugin registry
(`services/languages/`), so new languages add one analyzer class instead of
bolting regexes onto a shared scanner.

Java, C/C++, Go, Rust, Ruby, and PHP are recognized by extension but are
**not** yet deeply analyzed — they land in the `unsupported` bucket until
their analyzers exist.

Roadmap: more language analyzers next. Dependency, secret, and config
scanning shipped in Phase 4; authorized live website scanning shipped
in Phase 6 (`POST /scan/website`); persistence, API-key auth, and jobs
shipped in Phase 7.

## Limitations

- Deep analysis covers Python and JavaScript/TypeScript; other recognized
  languages are detected but not parsed.
- 10 deterministic Python detectors, 9 JS/TS detectors, 20 supply-chain
  rules; Nemotron adds reasoning but no new detector families yet.
- Dependency vulnerability matching requires a populated advisory DB
  (`backend/data/advisories.json`); without it, no CVE is ever reported.
- Config checks (Dockerfile, GHA, compose) are line-based: a first net,
  not a proof of absence — see each rule's known limitations.
- AI enrichment is hard-capped per mode (free 0, economy 1, full 4 per
  analysis); no per-finding agent fan-out.
- No PDF reports, no frontend, Docker, CI/CD, auth, or database — intentionally
  out of scope.
- Remediation is backend-only: `POST /remediate` proposes and verifies fixes,
  but no code is ever written back to the analyzed repository.
