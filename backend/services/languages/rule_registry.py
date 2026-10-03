"""Rule registry: stable metadata for every deterministic detector.

Each detector gets a stable rule ID (``PY-SEC-001`` …), CWE mapping(s),
applicable languages, severity rationale, confidence rules, known
limitations, and a remediation reference. This is documentation-as-data:
detectors stamp ``rule_id``/``cwe_ids`` onto findings from here, so the
finding model, the benchmark corpus, and future reports all share one
source of truth.

CWE mappings use canonical CWE identifiers. OWASP mappings refer to the
OWASP Top 10 2021. Quality rules (``-QLT-``) have no CWE mapping — they
are maintainability rules, not weaknesses, and the registry says so
rather than forcing a fit.

No detector behavior lives here; this module only describes rules.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleMetadata:
    """Stable, auditable metadata for one deterministic detection rule."""

    rule_id: str  # e.g. "PY-SEC-001" — stable across releases
    detector: str  # detector name as it appears on findings
    languages: tuple[str, ...]  # analyzer languages this rule applies to
    cwe_ids: tuple[str, ...]  # canonical CWE IDs, e.g. ("CWE-89",); () if none
    owasp_mapping: str  # e.g. "A03:2021 Injection"; "" when not applicable
    severity_rationale: str  # why this severity, in one or two sentences
    confidence_rules: str  # how the detector assigns confidence
    known_limitations: str  # what the rule misses or may misflag
    remediation_reference: str  # short actionable pointer, not a full guide


_RULES: tuple[RuleMetadata, ...] = (
    # ------------------------------------------------------------------
    # Python security rules
    # ------------------------------------------------------------------
    RuleMetadata(
        rule_id="PY-SEC-001",
        detector="hardcoded_secret",
        languages=("python",),
        cwe_ids=("CWE-798",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale=(
            "HIGH: a committed credential is immediately usable by anyone "
            "with repository read access; rotation is the only remedy."
        ),
        confidence_rules=(
            "HIGH when a secret-like variable name is assigned a non-placeholder "
            "string literal. Placeholder values, short strings, and env-var "
            "lookups are excluded to keep false positives down."
        ),
        known_limitations=(
            "Only direct assignments are checked; secrets built dynamically, "
            "loaded from files, or embedded in non-assignment contexts are "
            "missed. Unusual-but-real secret names outside the hint list are missed. "
            "Evidence is REDACTED (never the full value). Values matching a "
            "known token shape (AWS key, GitHub token, ...) are not reported "
            "here; the SECRET-002..005 detectors own them (no double-reporting)."
        ),
        remediation_reference=(
            "CWE-798; move the secret to an environment variable or secrets "
            "manager and rotate the exposed value."
        ),
    ),
    RuleMetadata(
        rule_id="PY-SEC-002",
        detector="sql_string_construction",
        languages=("python",),
        cwe_ids=("CWE-89",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: SQL built from string operations and passed to execute() is "
            "the classic SQL injection shape; impact is data theft or destruction."
        ),
        confidence_rules=(
            "MEDIUM by default (dynamic construction alone does not prove the "
            "data is untrusted). Raised to HIGH only when source-to-sink "
            "tracing identifies a concrete untrusted origin (taint_trace set)."
        ),
        known_limitations=(
            "No interprocedural analysis: SQL built in one function and executed "
            "in another is missed. ORM query builders are out of scope."
        ),
        remediation_reference=(
            "CWE-89; use parameterized queries / prepared statements "
            "(OWASP SQL Injection Prevention Cheat Sheet)."
        ),
    ),
    RuleMetadata(
        rule_id="PY-SEC-003",
        detector="unsafe_html_render",
        languages=("python",),
        cwe_ids=("CWE-79",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: mark_safe() on dynamic content and dynamic "
            "render_template_string() both bypass template autoescaping, "
            "enabling stored or reflected XSS."
        ),
        confidence_rules=(
            "MEDIUM: the sink is dangerous, but only attacker-controlled "
            "content makes it exploitable; dynamic-ness of the argument is "
            "what the detector checks."
        ),
        known_limitations=(
            "Only mark_safe() and render_template_string() are covered; other "
            "frameworks' unsafe renderers (e.g. raw Jinja2 from_string) are not."
        ),
        remediation_reference=(
            "CWE-79; rely on template autoescaping, never mark dynamic "
            "content safe (OWASP XSS Prevention Cheat Sheet)."
        ),
    ),
    RuleMetadata(
        rule_id="PY-SEC-004",
        detector="dangerous_eval",
        languages=("python",),
        cwe_ids=("CWE-95",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH with a dynamic argument: eval() on attacker-controlled text "
            "is arbitrary code execution. MEDIUM with a constant argument: "
            "still fragile and worth removing."
        ),
        confidence_rules=(
            "HIGH when the argument is not a constant; MEDIUM when it is a "
            "constant (the call is still flagged as a code smell)."
        ),
        known_limitations=(
            "Does not distinguish eval() aliases or wrappers; a constant "
            "argument is still flagged (deliberately, as a smell)."
        ),
        remediation_reference=(
            "CWE-95; use ast.literal_eval() for data or a real parser for "
            "expressions."
        ),
    ),
    RuleMetadata(
        rule_id="PY-SEC-005",
        detector="dangerous_exec",
        languages=("python",),
        cwe_ids=("CWE-95",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH with a dynamic argument: exec() on attacker-controlled text "
            "is arbitrary code execution with statement-level power."
        ),
        confidence_rules=(
            "HIGH when the argument is not a constant; MEDIUM when constant."
        ),
        known_limitations="Same as PY-SEC-004.",
        remediation_reference=(
            "CWE-95; restructure to avoid dynamic execution (dispatch dicts, "
            "plugins)."
        ),
    ),
    RuleMetadata(
        rule_id="PY-SEC-006",
        detector="subprocess_shell_true",
        languages=("python",),
        cwe_ids=("CWE-78",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: shell=True routes the command through a shell, so any "
            "untrusted argument becomes shell command injection."
        ),
        confidence_rules=(
            "HIGH: the shell=True keyword is explicit in the call; the "
            "dangerous configuration is certain even if exploitability is not."
        ),
        known_limitations=(
            "Only literal shell=True is detected; shell truthiness via a "
            "variable (shell=flag) is missed."
        ),
        remediation_reference=(
            "CWE-78; pass argv as a list and drop shell=True (OWASP Command "
            "Injection defenses)."
        ),
    ),
    RuleMetadata(
        rule_id="PY-SEC-007",
        detector="os_system",
        languages=("python",),
        cwe_ids=("CWE-78",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: os.system()/os.popen() always invoke a subshell; any "
            "interpolated untrusted input is command injection."
        ),
        confidence_rules="HIGH: the subshell invocation is unconditional.",
        known_limitations=(
            "Matches any .system()/.popen() attribute call, not just the os "
            "module's — e.g. a hypothetical obj.system() would false-positive. "
            "Documented; kept conservative rather than requiring import tracking."
        ),
        remediation_reference="CWE-78; use subprocess with an argument list.",
    ),
    RuleMetadata(
        rule_id="PY-SEC-008",
        detector="weak_crypto",
        languages=("python",),
        cwe_ids=("CWE-327",),
        owasp_mapping="A02:2021 Cryptographic Failures",
        severity_rationale=(
            "MEDIUM: MD5/SHA-1 are collision-broken; using them for integrity "
            "or password hashing is unsafe, but not every use is security-critical."
        ),
        confidence_rules="HIGH: the algorithm name is explicit in the call.",
        known_limitations=(
            "Cannot tell security-critical use (password hashing) from benign "
            "use (non-security checksums, hash tables); all uses are flagged."
        ),
        remediation_reference=(
            "CWE-327; use SHA-256 or better; bcrypt/argon2/scrypt for passwords."
        ),
    ),
    # ------------------------------------------------------------------
    # Python quality rules (no CWE mapping — maintainability, not weakness)
    # ------------------------------------------------------------------
    RuleMetadata(
        rule_id="PY-QLT-001",
        detector="long_function",
        languages=("python",),
        cwe_ids=(),
        owasp_mapping="",
        severity_rationale=(
            "LOW: a maintainability signal only. Long functions are harder to "
            "review and test, which indirectly hurts security review quality."
        ),
        confidence_rules="HIGH: function length is measured exactly from AST spans.",
        known_limitations=(
            "Threshold-based (default 50 lines); the cutoff is a heuristic, "
            "not a defect boundary."
        ),
        remediation_reference="Split into smaller, single-purpose functions.",
    ),
    RuleMetadata(
        rule_id="PY-QLT-002",
        detector="bare_except",
        languages=("python",),
        cwe_ids=(),
        owasp_mapping="",
        severity_rationale=(
            "LOW: bare except swallows KeyboardInterrupt/SystemExit and hides "
            "failures, including security-relevant ones."
        ),
        confidence_rules="HIGH: a bare except: clause is unambiguous in the AST.",
        known_limitations="None significant; the AST pattern is exact.",
        remediation_reference="Catch specific exception types.",
    ),
    # ------------------------------------------------------------------
    # JavaScript/TypeScript security rules
    # ------------------------------------------------------------------
    RuleMetadata(
        rule_id="JS-SEC-001",
        detector="js_dangerous_eval",
        languages=("javascript", "typescript"),
        cwe_ids=("CWE-95",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: eval() executes its string argument as JavaScript; "
            "attacker-controlled input means arbitrary code execution in the "
            "page or process."
        ),
        confidence_rules="HIGH: a bare eval() call is unambiguous.",
        known_limitations=(
            "Only bare eval() calls are matched; window.eval() or aliased "
            "eval are missed."
        ),
        remediation_reference="CWE-95; use JSON.parse or a safe expression evaluator.",
    ),
    RuleMetadata(
        rule_id="JS-SEC-002",
        detector="js_function_constructor",
        languages=("javascript", "typescript"),
        cwe_ids=("CWE-95",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: new Function(...) compiles strings into a function at "
            "runtime — eval by another name."
        ),
        confidence_rules="HIGH: the constructor call is unambiguous.",
        known_limitations="None significant for the direct pattern.",
        remediation_reference="CWE-95; define the function statically.",
    ),
    RuleMetadata(
        rule_id="JS-SEC-003",
        detector="js_command_injection",
        languages=("javascript", "typescript"),
        cwe_ids=("CWE-78",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: child_process.exec/execSync run through a shell (spawn does "
            "with shell:true); a non-literal command with untrusted parts is "
            "command injection."
        ),
        confidence_rules=(
            "HIGH: fires only on shell:true or a non-literal command argument; "
            "literal commands and execFile-style array calls stay silent."
        ),
        known_limitations=(
            "Member calls must plausibly target child_process (db.exec() stays "
            "silent); destructured bare exec() is accepted and may over-flag "
            "in rare non-child_process uses."
        ),
        remediation_reference=(
            "CWE-78; avoid shell:true; use execFile/spawn with an argument array."
        ),
    ),
    RuleMetadata(
        rule_id="JS-SEC-004",
        detector="js_xss_dom_sink",
        languages=("javascript", "typescript"),
        cwe_ids=("CWE-79",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: assigning non-literal content to innerHTML/outerHTML or "
            "calling document.write parses attacker-influenced strings as "
            "HTML — DOM XSS."
        ),
        confidence_rules=(
            "HIGH: fires only on non-literal assigned content or "
            "document.write/writeln calls."
        ),
        known_limitations=(
            "Sanitizer use (e.g. DOMPurify) before assignment is not "
            "recognized; sanitized flows may false-positive."
        ),
        remediation_reference=(
            "CWE-79; use textContent or sanitize with DOMPurify (OWASP XSS "
            "Prevention Cheat Sheet)."
        ),
    ),
    RuleMetadata(
        rule_id="JS-SEC-005",
        detector="js_react_dangerous_html",
        languages=("javascript", "typescript"),
        cwe_ids=("CWE-79",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: dangerouslySetInnerHTML bypasses React's escaping; an "
            "attacker-controlled __html value is XSS."
        ),
        confidence_rules="HIGH: the attribute/prop name is explicit.",
        known_limitations=(
            "The __html value is not traced; sanitized values still flag."
        ),
        remediation_reference="CWE-79; render as children/text or sanitize first.",
    ),
    RuleMetadata(
        rule_id="JS-SEC-006",
        detector="js_hardcoded_secret",
        languages=("javascript", "typescript"),
        cwe_ids=("CWE-798",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale=(
            "HIGH: same as PY-SEC-001 — a committed credential is immediately "
            "usable by repository readers."
        ),
        confidence_rules=(
            "HIGH when a secret-like const/let/var name is assigned a "
            "non-placeholder string literal."
        ),
        known_limitations=(
            "Same as PY-SEC-001, for variable declarations. Evidence is "
            "REDACTED; known token shapes defer to SECRET-002..005."
        ),
        remediation_reference=(
            "CWE-798; load from environment variables or a secrets manager; "
            "rotate the exposed value."
        ),
    ),
    RuleMetadata(
        rule_id="JS-SEC-007",
        detector="js_sql_string_construction",
        languages=("javascript", "typescript"),
        cwe_ids=("CWE-89",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "HIGH: dynamic SQL (template literal with substitutions or "
            "concatenation) passed to query()/execute() is the SQL injection "
            "shape."
        ),
        confidence_rules=(
            "MEDIUM by default; raised to HIGH only when source-to-sink "
            "tracing identifies a concrete untrusted origin."
        ),
        known_limitations=(
            "Only query()/execute() call shapes are covered; ORM builders are "
            "out of scope."
        ),
        remediation_reference=(
            "CWE-89; use parameterized queries / prepared statements."
        ),
    ),
    RuleMetadata(
        rule_id="JS-SEC-008",
        detector="js_weak_crypto",
        languages=("javascript", "typescript"),
        cwe_ids=("CWE-327",),
        owasp_mapping="A02:2021 Cryptographic Failures",
        severity_rationale="MEDIUM: same reasoning as PY-SEC-008.",
        confidence_rules="HIGH: the algorithm string is explicit.",
        known_limitations="Same as PY-SEC-008.",
        remediation_reference=(
            "CWE-327; use SHA-256+; bcrypt/scrypt/argon2 for passwords."
        ),
    ),
    RuleMetadata(
        rule_id="JS-SEC-009",
        detector="js_implied_eval",
        languages=("javascript", "typescript"),
        cwe_ids=("CWE-95",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "MEDIUM: a string argument to setTimeout/setInterval is evaluated "
            "as code (implied eval); lower than direct eval() because the "
            "pattern is rarer and often legacy."
        ),
        confidence_rules="HIGH: a string first argument is unambiguous.",
        known_limitations="None significant for the direct pattern.",
        remediation_reference="CWE-95; pass a function instead of a string.",
    ),
    # ------------------------------------------------------------------
    # Dependency rules (supply-chain analyzers)
    # ------------------------------------------------------------------
    RuleMetadata(
        rule_id="DEP-001",
        detector="dep_vulnerable_package",
        languages=("supplychain",),
        cwe_ids=("CWE-1104",),
        owasp_mapping="A06:2021 Vulnerable and Outdated Components",
        severity_rationale=(
            "Taken from the matched advisory (default HIGH): a dependency "
            "with a known, remotely-reachable flaw is the most common initial "
            "access vector."
        ),
        confidence_rules=(
            "HIGH: the installed version (lockfile or == pin) falls inside "
            "the advisory's affected range. Range-only specifiers are never "
            "matched — advisory matching requires a concrete version."
        ),
        known_limitations=(
            "Only concrete versions are matched; range specifiers (>=, ^) are "
            "skipped rather than guessed. CWE-1104 is the closest fit — there "
            "is no exact CWE for 'known-vulnerable component'. Matches are "
            "only as fresh as the advisory database (see database_status on "
            "the finding)."
        ),
        remediation_reference=(
            "Upgrade to the advisory's fixed version (named on the finding), "
            "verify with the lockfile, and redeploy."
        ),
    ),
    RuleMetadata(
        rule_id="DEP-002",
        detector="dep_unpinned",
        languages=("supplychain",),
        cwe_ids=(),
        owasp_mapping="",
        severity_rationale=(
            "LOW: an unconstrained specifier is a hygiene signal, not a "
            "vulnerability — but it makes the installed version unknowable "
            "and future installs non-reproducible."
        ),
        confidence_rules=(
            "HIGH: fires only on fully unconstrained specifiers ('*', empty, "
            "'latest'). Bounded ranges (>=) are deliberately not flagged to "
            "avoid noise."
        ),
        known_limitations=(
            "Only the absence of any constraint is flagged; loose-but-bounded "
            "ranges are out of scope. No CWE mapping: this is packaging "
            "hygiene, not a weakness."
        ),
        remediation_reference=(
            "Pin the dependency and commit a lockfile "
            "(Pipfile.lock, package-lock.json)."
        ),
    ),
    RuleMetadata(
        rule_id="DEP-003",
        detector="dep_advisory_db_status",
        languages=("supplychain",),
        cwe_ids=(),
        owasp_mapping="",
        severity_rationale=(
            "INFO: not a vulnerability — a disclosure that advisory matching "
            "was limited or disabled, so results cannot be mistaken for a "
            "clean bill of health."
        ),
        confidence_rules="HIGH: the database status is computed, not inferred.",
        known_limitations="None; informational by design.",
        remediation_reference=(
            "Refresh the advisory database with "
            "backend/scripts/refresh_advisories.py and re-run."
        ),
    ),
    RuleMetadata(
        rule_id="DEP-004",
        detector="dep_manifest_parse_error",
        languages=("supplychain",),
        cwe_ids=(),
        owasp_mapping="",
        severity_rationale=(
            "LOW: a manifest that cannot be parsed means its dependencies "
            "were not analyzed — a coverage gap, not a vulnerability."
        ),
        confidence_rules="HIGH: the parse failure is observed, not inferred.",
        known_limitations="None; the file simply needs fixing.",
        remediation_reference="Fix the manifest syntax to restore coverage.",
    ),
    # ------------------------------------------------------------------
    # Secret rules (supply-chain secret analyzer; all findings sensitive)
    # ------------------------------------------------------------------
    RuleMetadata(
        rule_id="SECRET-001",
        detector="secret_pem_key",
        languages=("supplychain",),
        cwe_ids=("CWE-312",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale=(
            "HIGH: a committed private key is fully compromised the moment it "
            "is pushed; anyone with read access can impersonate the owner."
        ),
        confidence_rules="HIGH: the PEM armor header is unambiguous.",
        known_limitations=(
            "Only the BEGIN line is matched; keys split across unusual armor "
            "or stored in binary formats are missed. Evidence shows the "
            "header line only — key material never appears in findings."
        ),
        remediation_reference=(
            "CWE-312; delete from history, generate a new key pair, use a "
            "secrets manager or mounted secret files."
        ),
    ),
    RuleMetadata(
        rule_id="SECRET-002",
        detector="secret_aws_key",
        languages=("supplychain",),
        cwe_ids=("CWE-798",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale=(
            "HIGH: an AWS access key ID in source is immediately usable "
            "against the account until revoked."
        ),
        confidence_rules=(
            "HIGH: the AKIA prefix + 16-char shape is AWS-specific. "
            "Documented examples (containing 'EXAMPLE') are excluded."
        ),
        known_limitations=(
            "Only AKIA-prefixed long-term keys are matched; session tokens "
            "(ASIA) and other credential shapes are not. Evidence redacted."
        ),
        remediation_reference=(
            "CWE-798; revoke in the AWS console, issue a new key, load from "
            "environment/secrets manager."
        ),
    ),
    RuleMetadata(
        rule_id="SECRET-003",
        detector="secret_github_token",
        languages=("supplychain",),
        cwe_ids=("CWE-798",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale=(
            "HIGH: a GitHub token in source grants API access as the token "
            "owner until revoked."
        ),
        confidence_rules="HIGH: the ghp_/gho_/ghu_/ghs_/ghr_ prefix is GitHub-specific.",
        known_limitations="Evidence redacted; fine-grained token scopes are not inspected.",
        remediation_reference=(
            "CWE-798; revoke in GitHub settings, replace with an Actions "
            "secret or environment variable."
        ),
    ),
    RuleMetadata(
        rule_id="SECRET-004",
        detector="secret_google_api_key",
        languages=("supplychain",),
        cwe_ids=("CWE-798",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale="HIGH: same reasoning as SECRET-003.",
        confidence_rules="HIGH: the AIza 39-char shape is Google-specific.",
        known_limitations="Evidence redacted.",
        remediation_reference=(
            "CWE-798; regenerate in Google Cloud Console with API/IP "
            "restrictions."
        ),
    ),
    RuleMetadata(
        rule_id="SECRET-005",
        detector="secret_stripe_key",
        languages=("supplychain",),
        cwe_ids=("CWE-798",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale="HIGH: same reasoning as SECRET-003.",
        confidence_rules="HIGH: the sk-live-/sk-test- prefix is Stripe-specific.",
        known_limitations="Evidence redacted.",
        remediation_reference="CWE-798; roll the key in the Stripe dashboard.",
    ),
    RuleMetadata(
        rule_id="SECRET-006",
        detector="secret_high_entropy",
        languages=("supplychain",),
        cwe_ids=("CWE-798",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale=(
            "HIGH: a high-entropy string assigned to a secret-like name in a "
            "non-code file (.env, YAML, configs) is very likely a real "
            "credential."
        ),
        confidence_rules=(
            "MEDIUM: requires a secret-like name, length >= 12, Shannon "
            "entropy >= 4.5, and exclusion of placeholders/examples. "
            "Heuristic by nature."
        ),
        known_limitations=(
            "Entropy is a heuristic: random-looking non-secrets can fire, and "
            "low-entropy real secrets (weak passwords) are missed. Does not "
            "run on .py/.js/.ts files — PY-SEC-001/JS-SEC-006 own those. "
            "Evidence redacted."
        ),
        remediation_reference=(
            "CWE-798; move to environment/secrets manager and rotate."
        ),
    ),
    # ------------------------------------------------------------------
    # Configuration rules (Dockerfile / GitHub Actions / compose)
    # ------------------------------------------------------------------
    RuleMetadata(
        rule_id="CFG-001",
        detector="cfg_docker_no_user",
        languages=("supplychain",),
        cwe_ids=("CWE-250",),
        owasp_mapping="A01:2021 Broken Access Control",
        severity_rationale=(
            "HIGH: containers run as root by default; an exploited process "
            "or escape then has maximum privilege."
        ),
        confidence_rules=(
            "HIGH: the absence of any USER instruction is observed directly."
        ),
        known_limitations=(
            "Line-based: a USER in an earlier multi-stage build stage is "
            "counted even if the final stage lacks one (fail-open toward "
            "silence is avoided; documented here instead)."
        ),
        remediation_reference=(
            "CWE-250; add 'USER <nonroot>' after system package installation."
        ),
    ),
    RuleMetadata(
        rule_id="CFG-002",
        detector="cfg_docker_latest_tag",
        languages=("supplychain",),
        cwe_ids=(),
        owasp_mapping="",
        severity_rationale=(
            "LOW: a mutable tag makes builds non-reproducible and can silently "
            "introduce vulnerable base layers — hygiene, not a direct flaw."
        ),
        confidence_rules="HIGH: the tag (or its absence) is read from the FROM line.",
        known_limitations="No CWE mapping: determinism hygiene, not a weakness.",
        remediation_reference="Pin an immutable tag or image digest.",
    ),
    RuleMetadata(
        rule_id="CFG-003",
        detector="cfg_docker_secret_env",
        languages=("supplychain",),
        cwe_ids=("CWE-798",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale=(
            "HIGH: secrets baked into image layers are visible to anyone who "
            "can pull the image and persist in layer history."
        ),
        confidence_rules=(
            "MEDIUM: secret-like ENV/ARG name with a non-placeholder value; "
            "the name heuristic can misfire."
        ),
        known_limitations="Evidence redacted. BuildKit secret mounts are the fix.",
        remediation_reference=(
            "CWE-798; pass secrets at runtime via mounted secret files, never "
            "in ENV/ARG."
        ),
    ),
    RuleMetadata(
        rule_id="CFG-004",
        detector="cfg_docker_add",
        languages=("supplychain",),
        cwe_ids=(),
        owasp_mapping="",
        severity_rationale=(
            "LOW: ADD's auto-extract/fetch behavior makes builds less "
            "predictable than COPY — hygiene."
        ),
        confidence_rules="HIGH: the ADD instruction is explicit.",
        known_limitations="No CWE mapping.",
        remediation_reference="Prefer COPY.",
    ),
    RuleMetadata(
        rule_id="CFG-005",
        detector="cfg_docker_curl_pipe",
        languages=("supplychain",),
        cwe_ids=("CWE-494",),
        owasp_mapping="A08:2021 Software and Data Integrity Failures",
        severity_rationale=(
            "MEDIUM: piping a download straight into a shell executes "
            "unreviewed, unpinned remote code at build time."
        ),
        confidence_rules="HIGH: the curl|wget ... | sh shape is explicit.",
        known_limitations="Line-based; multi-line RUN with backslash continuations is still matched per line — the pipe must be on one line.",
        remediation_reference=(
            "CWE-494; vendor the script with a checksum or install a pinned package."
        ),
    ),
    RuleMetadata(
        rule_id="CFG-010",
        detector="cfg_gha_write_all",
        languages=("supplychain",),
        cwe_ids=("CWE-250",),
        owasp_mapping="A01:2021 Broken Access Control",
        severity_rationale=(
            "HIGH: write-all grants every job maximum token scope; a "
            "compromised step can push code or exfiltrate secrets."
        ),
        confidence_rules="HIGH: the literal 'permissions: write-all' is explicit.",
        known_limitations="None significant.",
        remediation_reference=(
            "CWE-250; scope permissions per job to the minimum needed."
        ),
    ),
    RuleMetadata(
        rule_id="CFG-011",
        detector="cfg_gha_pull_request_target",
        languages=("supplychain",),
        cwe_ids=("CWE-250",),
        owasp_mapping="A01:2021 Broken Access Control",
        severity_rationale=(
            "HIGH: pull_request_target runs with base-repo write permissions; "
            "checking out PR code in that context is a known "
            "privilege-escalation vector."
        ),
        confidence_rules=(
            "MEDIUM: the dangerous combination is observed, but whether the "
            "checkout actually builds attacker code needs human review."
        ),
        known_limitations="Line-based; does not evaluate expressions or job conditions.",
        remediation_reference=(
            "CWE-250; avoid checking out untrusted PR code under "
            "pull_request_target."
        ),
    ),
    RuleMetadata(
        rule_id="CFG-012",
        detector="cfg_gha_unpinned_action",
        languages=("supplychain",),
        cwe_ids=("CWE-1104",),
        owasp_mapping="A08:2021 Software and Data Integrity Failures",
        severity_rationale=(
            "MEDIUM: a mutable action ref (branch/tag) lets the action owner "
            "— or a tag hijack — change what runs in your pipeline without "
            "a reviewable diff."
        ),
        confidence_rules=(
            "HIGH: any non-40-hex-char ref is flagged. Deliberately strict: "
            "tag-pinning (actions/checkout@v4) is common practice and will "
            "flag — see limitations."
        ),
        known_limitations=(
            "Opinionated: the ecosystem norm is tag-pinning; this rule "
            "enforces the stricter SHA-pinning standard (CIS/Scorecard). "
            "Expect findings on conventional workflows; treat as hardening "
            "guidance. CWE-1104 is the closest fit."
        ),
        remediation_reference="Pin third-party actions to a full commit SHA.",
    ),
    RuleMetadata(
        rule_id="CFG-020",
        detector="cfg_compose_privileged",
        languages=("supplychain",),
        cwe_ids=("CWE-250",),
        owasp_mapping="A01:2021 Broken Access Control",
        severity_rationale=(
            "MEDIUM: privileged: true disables container isolation, making "
            "host escape far easier if the service is exploited."
        ),
        confidence_rules="HIGH: the literal key is explicit.",
        known_limitations="Line-based YAML approximation; deeply nested or anchored structures may be missed.",
        remediation_reference=(
            "CWE-250; drop privileged and grant only needed capabilities."
        ),
    ),
    RuleMetadata(
        rule_id="CFG-021",
        detector="cfg_compose_secret_env",
        languages=("supplychain",),
        cwe_ids=("CWE-798",),
        owasp_mapping="A07:2021 Identification and Authentication Failures",
        severity_rationale=(
            "HIGH: cleartext credentials in the compose file are visible to "
            "repository readers and in container inspect output."
        ),
        confidence_rules=(
            "MEDIUM: secret-like name heuristic inside environment blocks; "
            "line-based block tracking is approximate."
        ),
        known_limitations="Evidence redacted. Line-based; see module docstring.",
        remediation_reference=(
            "CWE-798; use Docker secrets or an uncommitted env_file."
        ),
    ),
    # ------------------------------------------------------------------
    # Live website scan rules (Phase 6). "website" is the analyzer
    # language label, mirroring "supplychain". Findings carry
    # source="live-scan"; they are observations from HTTP responses,
    # not repository evidence.
    # ------------------------------------------------------------------
    RuleMetadata(
        rule_id="LIVE-001",
        detector="live_missing_csp",
        languages=("website",),
        cwe_ids=("CWE-693",),
        owasp_mapping="A05:2021 Security Misconfiguration",
        severity_rationale=(
            "MEDIUM: missing CSP removes the primary browser-level "
            "mitigation for XSS and injection; exploitation still needs "
            "an injection point."
        ),
        confidence_rules="HIGH: the response headers are observed directly.",
        known_limitations=(
            "A CSP delivered via <meta> tag is not detected (header-only "
            "check); some apps set CSP on HTML pages only."
        ),
        remediation_reference=(
            "CWE-693; deploy a Content-Security-Policy, starting report-only."
        ),
    ),
    RuleMetadata(
        rule_id="LIVE-002",
        detector="live_missing_hsts",
        languages=("website",),
        cwe_ids=("CWE-319",),
        owasp_mapping="A02:2021 Cryptographic Failures",
        severity_rationale=(
            "MEDIUM: without HSTS, browsers may accept downgraded HTTP "
            "connections to the host, enabling sslstrip-style attacks."
        ),
        confidence_rules="HIGH: observed directly on HTTPS responses.",
        known_limitations="Only checked on HTTPS responses; HTTP targets get LIVE-007 instead.",
        remediation_reference=(
            "CWE-319; send Strict-Transport-Security with long max-age + includeSubDomains."
        ),
    ),
    RuleMetadata(
        rule_id="LIVE-003",
        detector="live_missing_frame_options",
        languages=("website",),
        cwe_ids=("CWE-1021",),
        owasp_mapping="A05:2021 Security Misconfiguration",
        severity_rationale=(
            "LOW: missing framing controls enable clickjacking; impact "
            "depends on the page's actions."
        ),
        confidence_rules="HIGH: observed directly.",
        known_limitations="frame-ancestors in CSP is not evaluated; header-only check.",
        remediation_reference="CWE-1021; set X-Frame-Options: DENY or a frame-ancestors directive.",
    ),
    RuleMetadata(
        rule_id="LIVE-004",
        detector="live_missing_content_type_options",
        languages=("website",),
        cwe_ids=("CWE-693",),
        owasp_mapping="A05:2021 Security Misconfiguration",
        severity_rationale="LOW: missing nosniff permits MIME-sniffing attacks.",
        confidence_rules="HIGH: observed directly.",
        known_limitations="None significant.",
        remediation_reference="CWE-693; send X-Content-Type-Options: nosniff.",
    ),
    RuleMetadata(
        rule_id="LIVE-005",
        detector="live_referrer_policy",
        languages=("website",),
        cwe_ids=("CWE-200",),
        owasp_mapping="A01:2021 Broken Access Control",
        severity_rationale=(
            "LOW: a missing or 'unsafe-url' policy can leak full URLs "
            "(possibly with tokens) to third parties."
        ),
        confidence_rules="HIGH: observed directly.",
        known_limitations="None significant.",
        remediation_reference="CWE-200; set a restrictive Referrer-Policy.",
    ),
    RuleMetadata(
        rule_id="LIVE-006",
        detector="live_cookie_flags",
        languages=("website",),
        cwe_ids=("CWE-614", "CWE-1004"),
        owasp_mapping="A01:2021 Broken Access Control",
        severity_rationale=(
            "MEDIUM without Secure on HTTPS (session theft over HTTP); LOW "
            "without HttpOnly (widens XSS impact) or with SameSite=None "
            "lacking Secure (weakened CSRF protection)."
        ),
        confidence_rules="HIGH: Set-Cookie attributes are observed directly.",
        known_limitations=(
            "Cookie values are never recorded. __Host-/__Secure- prefix "
            "conventions are not evaluated."
        ),
        remediation_reference="CWE-614, CWE-1004; set Secure, HttpOnly, and an explicit SameSite.",
    ),
    RuleMetadata(
        rule_id="LIVE-007",
        detector="live_http_not_https",
        languages=("website",),
        cwe_ids=("CWE-319",),
        owasp_mapping="A02:2021 Cryptographic Failures",
        severity_rationale=(
            "HIGH: cleartext HTTP exposes all traffic — credentials, "
            "cookies, personal data — to interception and modification."
        ),
        confidence_rules="HIGH: the URL scheme is observed directly.",
        known_limitations="None significant.",
        remediation_reference="CWE-319; serve over HTTPS and redirect HTTP to HTTPS.",
    ),
    RuleMetadata(
        rule_id="LIVE-008",
        detector="live_server_disclosure",
        languages=("website",),
        cwe_ids=("CWE-200",),
        owasp_mapping="A01:2021 Broken Access Control",
        severity_rationale=(
            "LOW: version banners help attackers target known "
            "vulnerabilities; informational, not directly exploitable."
        ),
        confidence_rules="HIGH: banner headers are observed directly.",
        known_limitations="Only version-shaped banners are flagged; plain product names are not.",
        remediation_reference="CWE-200; suppress or generalize version banners.",
    ),
    RuleMetadata(
        rule_id="LIVE-009",
        detector="live_exposed_file",
        languages=("website",),
        cwe_ids=("CWE-200",),
        owasp_mapping="A01:2021 Broken Access Control",
        severity_rationale=(
            "HIGH: publicly retrievable .git/HEAD leaks repository "
            "structure; .env commonly contains secrets."
        ),
        confidence_rules=(
            "HIGH: HTTP 200 with plausible content (.git/HEAD starts with "
            "'ref:'; .env looks like assignments, not HTML). Only the "
            "first bytes are read; contents are never stored."
        ),
        known_limitations=(
            "Only /.git/HEAD and /.env at the scope root are probed; other "
            "exposed paths are not enumerated."
        ),
        remediation_reference="CWE-200; block these paths at the web server/CDN and rotate exposed secrets.",
    ),
    RuleMetadata(
        rule_id="LIVE-010",
        detector="live_tls_verification_failed",
        languages=("website",),
        cwe_ids=("CWE-297",),
        owasp_mapping="A02:2021 Cryptographic Failures",
        severity_rationale=(
            "MEDIUM: an expired, not-yet-valid, mismatched, or missing "
            "certificate breaks chain-of-trust validation."
        ),
        confidence_rules="HIGH: the presented certificate is inspected directly.",
        known_limitations=(
            "Revocation (OCSP/CRL) is not checked; cipher-suite strength is "
            "not evaluated."
        ),
        remediation_reference="CWE-297; serve a valid, hostname-matching certificate and automate renewal.",
    ),
    RuleMetadata(
        rule_id="LIVE-020",
        detector="live_reflected_xss_probe",
        languages=("website",),
        cwe_ids=("CWE-79",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "MEDIUM (capped): unencoded reflection of a probe token is "
            "consistent with reflected XSS but does not prove "
            "exploitability; manual verification is required."
        ),
        confidence_rules=(
            "MEDIUM maximum: a unique canary reflected unencoded in HTML. "
            "HTML-escaped reflections are correctly NOT flagged."
        ),
        known_limitations=(
            "GET-only, single probe parameter; no JS-context analysis; "
            "cannot distinguish stored XSS; ambiguous reflections are "
            "reported as possible."
        ),
        remediation_reference="CWE-79; HTML-encode untrusted output; prefer auto-escaping + CSP.",
    ),
    RuleMetadata(
        rule_id="LIVE-021",
        detector="live_sqli_error_probe",
        languages=("website",),
        cwe_ids=("CWE-89",),
        owasp_mapping="A03:2021 Injection",
        severity_rationale=(
            "MEDIUM (capped): database error text after input perturbation "
            "suggests unparameterized SQL but does not prove injection; "
            "manual verification is required."
        ),
        confidence_rules=(
            "MEDIUM maximum: known DB error signatures in the response. No "
            "data is ever extracted."
        ),
        known_limitations=(
            "Error-based only; blind/time-based SQLi is not tested. "
            "Error messages may be generic or localized."
        ),
        remediation_reference="CWE-89; use parameterized queries / prepared statements.",
    ),
)

_BY_DETECTOR: dict[str, RuleMetadata] = {r.detector: r for r in _RULES}

_BY_RULE_ID: dict[str, RuleMetadata] = {r.rule_id: r for r in _RULES}


def get_rule(detector: str) -> RuleMetadata | None:
    """Metadata for a detector name, or None for unregistered producers
    (e.g. AI-discovered findings, which must not invent a rule mapping)."""
    return _BY_DETECTOR.get(detector)


def get_rule_by_id(rule_id: str) -> RuleMetadata | None:
    """Metadata for a stable rule ID, or None if unknown."""
    return _BY_RULE_ID.get(rule_id)


def all_rules() -> tuple[RuleMetadata, ...]:
    """Every registered rule, in stable rule-ID order."""
    return _RULES


__all__ = ["RuleMetadata", "get_rule", "get_rule_by_id", "all_rules"]
