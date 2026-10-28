"""
core/scoring.py
---------------
Advanced scoring, priority calculations, secret confidence, and typosquatting detection.

Implements the official four scoring equations:
1. Risk Priority:
   priority = 100 * impact * exploitability * exposure * reachability * confidence
2. Duplicate/Corroboration Scoring:
   effective = min(100, max(rule_scores) + 10 * (independent_rules - 1))
3. Secret Confidence:
   secret_score = 0.35 * entropy_norm + 0.25 * length_score + 0.20 * charset_score + 0.20 * issuer_prefix - placeholder_penalty
4. Typosquatting:
   suspicious if Damerau-Levenshtein(name, popular_package) <= max(1, len(name)//6) and download_count is disproportionately low
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import Any

from core.entropy import shannon_entropy


# -----------------------------------------------------------------------------
# 1. Risk Priority Equation
# -----------------------------------------------------------------------------

def calculate_risk_priority(
    *,
    impact: float,
    exploitability: float,
    exposure: float,
    reachability: float,
    confidence: float,
) -> float:
    """Calculates risk priority according to:

    priority = 100 * impact * exploitability * exposure * reachability * confidence
    Clamped to [0.0, 100.0].
    """
    impact = max(0.0, min(1.0, float(impact)))
    exploitability = max(0.0, min(1.0, float(exploitability)))
    exposure = max(0.0, min(1.0, float(exposure)))
    reachability = max(0.0, min(1.0, float(reachability)))
    confidence = max(0.0, min(1.0, float(confidence)))

    raw = 100.0 * impact * exploitability * exposure * reachability * confidence
    return round(max(0.0, min(100.0, raw)), 2)


_SEVERITY_IMPACT: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.05,
}

_CWE_IMPACT_OVERRIDES: dict[str, float] = {
    "CWE-78": 1.0,   # OS Command Injection
    "CWE-89": 1.0,   # SQL Injection
    "CWE-798": 1.0,  # Hardcoded Credentials
    "CWE-95": 0.95,  # Eval Injection
    "CWE-94": 0.95,  # Code Injection
    "CWE-918": 0.85, # SSRF
    "CWE-22": 0.85,  # Path Traversal
    "CWE-79": 0.75,  # Cross-Site Scripting
    "CWE-352": 0.70, # CSRF
    "CWE-601": 0.50, # Open Redirect
}

_CONFIDENCE_MULTIPLIER: dict[str, float] = {
    "high": 1.0,
    "medium": 0.75,
    "low": 0.5,
}


def score_finding_priority(
    finding: Any,
    *,
    reachability: float = 1.0,
    exposure: float | None = None,
    exploitability: float | None = None,
) -> float:
    """Scores a Finding instance dynamically using the risk priority equation."""
    # 1. Impact
    cwe = getattr(finding, "cwe", None) or ""
    impact = _CWE_IMPACT_OVERRIDES.get(
        cwe, _SEVERITY_IMPACT.get(getattr(finding, "severity", "medium").lower(), 0.5)
    )

    # 2. Exploitability
    if exploitability is None:
        category = getattr(finding, "category", "").lower()
        tags = set(getattr(finding, "tags", ()))
        if "kev" in tags or "exploited" in tags:
            exploitability = 1.0
        elif category in {"secret", "sast"} or any(t in tags for t in ("rce", "sqli", "command-injection")):
            exploitability = 0.85
        elif category in {"web", "supply-chain"}:
            exploitability = 0.70
        else:
            exploitability = 0.50

    # 3. Exposure
    if exposure is None:
        file_path = str(getattr(finding, "file", "")).lower()
        if any(file_path.endswith(ext) for ext in (".test.js", ".spec.js", ".test.ts", "_test.go", "_test.py")):
            exposure = 0.35
        elif "tests/" in file_path or "test/" in file_path or "fixtures/" in file_path:
            exposure = 0.35
        elif "docs/" in file_path or file_path.endswith(".md"):
            exposure = 0.25
        elif any(part in file_path for part in ("dockerfile", ".github/", "api", "routes", "views", "controllers")):
            exposure = 1.0
        else:
            exposure = 0.85

    # 4. Reachability (from caller or graph distance)
    reachability = max(0.1, min(1.0, reachability))

    # 5. Confidence
    confidence_level = str(getattr(finding, "confidence", "medium")).lower()
    confidence = _CONFIDENCE_MULTIPLIER.get(confidence_level, 0.75)

    return calculate_risk_priority(
        impact=impact,
        exploitability=exploitability,
        exposure=exposure,
        reachability=reachability,
        confidence=confidence,
    )


# -----------------------------------------------------------------------------
# 2. Duplicate / Corroboration Scoring
# -----------------------------------------------------------------------------

def corroboration_score(
    rule_scores: Sequence[float],
    independent_rules: int | None = None,
) -> float:
    """Calculates effective score under corroboration:

    effective = min(100, max(rule_scores) + 10 * (independent_rules - 1))
    Do not sum overlapping findings; reward corroboration slightly.
    """
    if not rule_scores:
        return 0.0
    if independent_rules is None:
        independent_rules = len(rule_scores)

    independent_rules = max(1, int(independent_rules))
    base_max = max(rule_scores)
    bonus = 10.0 * (independent_rules - 1)
    return round(min(100.0, base_max + bonus), 2)


# -----------------------------------------------------------------------------
# 3. Secret Confidence Equation
# -----------------------------------------------------------------------------

_KNOWN_ISSUER_PREFIXES = (
    "sk-",
    "sk-proj-",
    "sk-ant-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "AKIA",
    "ABIA",
    "ACCA",
    "ASIA",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "hf_",
    "pcsk_",
    "gsk_",
    "AIza",
)


def calculate_secret_score(
    secret: str,
    *,
    issuer_prefix_matched: bool | None = None,
    placeholder_penalty: float | None = None,
) -> float:
    """Calculates secret confidence according to:

    secret_score = (
        0.35 * entropy_norm +
        0.25 * length_score +
        0.20 * charset_score +
        0.20 * issuer_prefix -
        placeholder_penalty
    )
    Normalized to [0.0, 1.0].
    """
    clean = secret.strip().strip("\"'`")
    if not clean:
        return 0.0

    # 1. Entropy normalized against a realistic high-entropy threshold of ~4.5 bits
    raw_entropy = shannon_entropy(clean)
    entropy_norm = min(1.0, max(0.0, raw_entropy / 4.5))

    # 2. Length score (32+ chars reaches 1.0)
    length_score = min(1.0, max(0.0, len(clean) / 32.0))

    # 3. Character set diversity (upper, lower, digit, symbol)
    classes = 0
    if any(c.isupper() for c in clean):
        classes += 1
    if any(c.islower() for c in clean):
        classes += 1
    if any(c.isdigit() for c in clean):
        classes += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in clean):
        classes += 1
    charset_score = classes / 4.0

    # 4. Issuer prefix check
    if issuer_prefix_matched is None:
        issuer_prefix_matched = any(clean.startswith(prefix) for prefix in _KNOWN_ISSUER_PREFIXES)
    issuer_score = 1.0 if issuer_prefix_matched else 0.0

    # 5. Placeholder penalty
    if placeholder_penalty is None:
        from core.scanner import looks_like_placeholder
        placeholder_penalty = 0.6 if looks_like_placeholder(clean) else 0.0

    score = (
        0.35 * entropy_norm
        + 0.25 * length_score
        + 0.20 * charset_score
        + 0.20 * issuer_score
        - placeholder_penalty
    )
    return round(max(0.0, min(1.0, score)), 4)


# -----------------------------------------------------------------------------
# 4. Typosquatting (Damerau-Levenshtein)
# -----------------------------------------------------------------------------

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Damerau-Levenshtein distance (insertions, deletions, substitutions,

    and adjacent transpositions).
    """
    len1, len2 = len(s1), len(s2)
    # H[i, j] table with 2 extra boundary rows/cols
    # Using dictionary for safe, compact table lookup
    da: dict[str, int] = {}
    d: list[list[int]] = [[0] * (len2 + 2) for _ in range(len1 + 2)]

    max_dist = len1 + len2
    d[0][0] = max_dist

    for i in range(len1 + 1):
        d[i + 1][0] = max_dist
        d[i + 1][1] = i
    for j in range(len2 + 1):
        d[0][j + 1] = max_dist
        d[1][j + 1] = j

    for i in range(1, len1 + 1):
        db = 0
        for j in range(1, len2 + 1):
            k = da.get(s2[j - 1], 0)
            l = db
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            if cost == 0:
                db = j

            d[i + 1][j + 1] = min(
                d[i][j + 1] + 1,       # deletion
                d[i + 1][j] + 1,       # insertion
                d[i][j] + cost,        # substitution
                d[k][l] + (i - k - 1) + 1 + (j - l - 1),  # transposition
            )
        da[s1[i - 1]] = i

    return d[len1 + 1][len2 + 1]


POPULAR_PACKAGES: dict[str, set[str]] = {
    "pypi": {
        "requests", "urllib3", "numpy", "pandas", "flask", "django", "pytest",
        "cryptography", "torch", "boto3", "setuptools", "wheel", "pip", "scipy",
        "matplotlib", "pydantic", "fastapi", "black", "mypy", "ruff", "flake8",
        "httpx", "aiohttp", "click", "jinja2", "pyyaml", "scikit-learn", "tensorflow",
    },
    "npm": {
        "express", "react", "react-dom", "lodash", "axios", "chalk", "commander",
        "vue", "webpack", "typescript", "moment", "next", "tslib", "debug",
        "fs-extra", "glob", "inquirer", "rxjs", "semver", "uuid", "yargs",
        "body-parser", "cors", "dotenv", "mongoose", "nodemon",
    },
}


def check_typosquatting(
    package_name: str,
    *,
    ecosystem: str = "pypi",
    popular_set: Iterable[str] | None = None,
    download_count_is_low: bool = True,
) -> tuple[bool, str | None, int]:
    """Evaluates whether package_name is suspicious:

    suspicious if Damerau-Levenshtein(name, popular_package) <= max(1, len(name)//6)
                 and download_count is disproportionately low

    Returns (is_suspicious, target_package, distance).
    """
    clean_name = package_name.lower().strip()
    candidates = popular_set or POPULAR_PACKAGES.get(ecosystem.lower(), POPULAR_PACKAGES["pypi"])

    threshold = max(1, len(clean_name) // 6)

    for target in candidates:
        target_lower = target.lower()
        if clean_name == target_lower:
            continue  # Exact match is legitimate

        dist = damerau_levenshtein_distance(clean_name, target_lower)
        if dist <= threshold and download_count_is_low:
            return True, target, dist

    return False, None, 0


# -----------------------------------------------------------------------------
# 5. Probabilistic Commit Risk Index
# -----------------------------------------------------------------------------

def calculate_commit_risk_index(findings: Sequence[Any]) -> float:
    """Calculates the probabilistic Compound Commit Risk Index (0.0 to 100.0):

    CommitRisk = 100 * (1 - prod_{f in findings} (1 - priority(f) / 100))
    Treats each finding priority as an independent vulnerability likelihood.
    """
    if not findings:
        return 0.0

    survival_prob = 1.0
    for finding in findings:
        priority = getattr(finding, "risk_priority", None)
        if priority is None:
            priority = score_finding_priority(finding)
        p = max(0.0, min(1.0, float(priority) / 100.0))
        survival_prob *= (1.0 - p)

    risk = 100.0 * (1.0 - survival_prob)
    return round(max(0.0, min(100.0, risk)), 1)


# -----------------------------------------------------------------------------
# 6. Graph Diffusion Blast Radius
# -----------------------------------------------------------------------------

def calculate_file_blast_radius(
    file_path: str,
    dependency_graph: Any = None,
    *,
    alpha: float = 1.5,
    max_depth: int = 10,
) -> float:
    """Calculates graph diffusion blast radius for a file across the dependency graph:

    BlastRadius(f) = 1.0 + sum_{d in downstream(f)} (1.0 / (depth(f, d) ** alpha))
    """
    if dependency_graph is None:
        return 1.0

    reverse_map = getattr(dependency_graph, "reverse", None)
    if not reverse_map or not isinstance(reverse_map, dict):
        return 1.0

    score = 1.0
    seen: dict[str, int] = {}
    queue = [(file_path, 0)]
    idx = 0
    while idx < len(queue):
        current, depth = queue[idx]
        idx += 1
        if depth >= max_depth:
            continue
        for parent in reverse_map.get(current, ()):
            if parent == file_path:
                continue
            next_depth = depth + 1
            if parent not in seen or next_depth < seen[parent]:
                seen[parent] = next_depth
                queue.append((parent, next_depth))

    for target, depth in seen.items():
        if depth > 0:
            score += 1.0 / (float(depth) ** alpha)

    return round(score, 2)


# -----------------------------------------------------------------------------
# 7. Statistical Entropy Z-Score
# -----------------------------------------------------------------------------

def calculate_entropy_zscore(
    token: str,
    file_content: str | Sequence[str],
    window_size: int = 16,
) -> float:
    """Calculates statistical Z-score of token entropy compared to the baseline file distribution:

    Z = (H(token) - mu_H(file)) / sigma_H(file)
    """
    clean_token = token.strip().strip("\"'`")
    if not clean_token:
        return 0.0

    token_entropy = shannon_entropy(clean_token)

    if isinstance(file_content, str):
        lines = file_content.splitlines()
    else:
        lines = list(file_content)

    sample_entropies: list[float] = []
    for line in lines:
        stripped = line.strip()
        if len(stripped) < 4:
            continue
        if len(stripped) <= window_size:
            sample_entropies.append(shannon_entropy(stripped))
        else:
            step = max(1, window_size // 2)
            for i in range(0, len(stripped) - window_size + 1, step):
                sample_entropies.append(shannon_entropy(stripped[i:i + window_size]))

    if len(sample_entropies) < 2:
        return 0.0

    mean_h = sum(sample_entropies) / len(sample_entropies)
    variance = sum((x - mean_h) ** 2 for x in sample_entropies) / (len(sample_entropies) - 1)
    std_h = math.sqrt(variance)

    if std_h == 0.0:
        return 0.0

    z_score = (token_entropy - mean_h) / std_h
    return round(z_score, 2)


# -----------------------------------------------------------------------------
# 8. Security Debt & Remediation Time
# -----------------------------------------------------------------------------

_CATEGORY_DEBT_MINUTES: dict[str, float] = {
    "secret": 20.0,
    "sast": 25.0,
    "web": 25.0,
    "dependency": 15.0,
    "supply-chain": 15.0,
    "iac": 10.0,
    "container": 10.0,
    "quality": 5.0,
}


def calculate_security_debt(findings: Sequence[Any]) -> dict[str, float]:
    """Calculates estimated developer remediation time and savings:

    DebtMinutes = sum_{f in findings} BaseMinutes(category) * (1.0 - AutoFixAvailable * 0.85)
    """
    total_gross = 0.0
    total_net = 0.0
    saved = 0.0

    for finding in findings:
        cat = str(getattr(finding, "category", "")).lower()
        base = _CATEGORY_DEBT_MINUTES.get(cat, 15.0)
        has_fix = bool(getattr(finding, "fix", None))
        total_gross += base
        if has_fix:
            fix_debt = base * 0.15
            total_net += fix_debt
            saved += (base - fix_debt)
        else:
            total_net += base

    return {
        "gross_debt_minutes": round(total_gross, 1),
        "net_debt_minutes": round(total_net, 1),
        "saved_by_autofix_minutes": round(saved, 1),
        "gross_hours": round(total_gross / 60.0, 1),
        "net_hours": round(total_net / 60.0, 1),
    }

