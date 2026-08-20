<div align="center">

# 🔍 SherlockSec

**Agentic Security Auditing — from finding a vulnerability to fixing it, automatically.**

*Graduation Project · Faculty of Computers and Artificial Intelligence, Cairo University*
[![Team Name](https://img.shields.io/badge/Team%20Name-Pull%20Request%20Guardian%20PGR-Green)]()

[![Status](https://img.shields.io/badge/status-in%20development-yellow)]()
[![Supervisor](https://img.shields.io/badge/supervisor-Dr.%20Mohammad%20El--Ramly-blue)]()
[![License](https://img.shields.io/badge/license-TBD-lightgrey)]()

</div>

---

## What is SherlockSec?

Most security scanners stop at "here's a vulnerability class, good luck." SherlockSec doesn't.

It's a **multi-agent security auditing system** that runs continuous, automated assessments of web applications. Instead of a single scan-and-report pass, it chains cooperating agents that map the codebase, discover threats, **verify every finding against a sandboxed exploit** before trusting it, trace the exact vulnerable line, generate a working fix, and then **try to break its own patch** before marking anything resolved.

Built to sit next to a codebase the way a CI/CD pipeline does — triggered on a pull request or a schedule — so a small team without a pentest budget still gets an audit that behaves like one.

## Why

Professional pentesting is expensive and infrequent. Automated scanners (ZAP, Burp, Snyk) run continuously but stop at noisy, unverified alerts with no code-level fix. Newer AI tools narrow parts of this gap — Claude Security verifies findings, Copilot Autofix and Sonar's Remediation Agent auto-patch — but none combine **verified exploitation + web-app-specific coverage (including IDOR/broken access control) + self-verifying remediation** in one developer-facing loop. That's the gap this project targets.

## How it works

```
1. Knowledge & Index      → builds a call-graph / dependency-graph, maps entry points
2. Threat Discovery       → runs SAST + a self-critique pass to kill false positives early
3. Evidence Validator     → confirms findings with real exploit tools (or an LLM-built test for IDOR)
4. Root Cause Analyst     → traces data flow, clusters findings that share one root cause
5. Remediation & Validation → generates a fix, re-runs the exploit, attempts a bypass, grades the result (A–F)
```

Each stage hands off through a shared state — deterministic control flow between stages, with LLM reasoning reserved for the parts that actually need judgment (the exploit try/observe/adapt loop, the self-critique pass, the fix-then-bypass check).

## Current scope

This is a graduation project, scoped deliberately rather than claiming everything at once.

**Vulnerability classes (current phase):**
- Reflected XSS
- SQL Injection
- IDOR *(the one traditional signature-based scanners structurally can't catch)*

**Agents (current phase):** Knowledge & Index → Threat Discovery → Evidence Validator
*(Root Cause Analyst and Remediation & Validation follow once the first three are proven end-to-end.)*

## Tech stack

| Layer | Technology |
|---|---|
| Backend | FastAPI — Modular Monolith, Clean/Layered Architecture |
| Agent Orchestration | LangGraph |
| Code Analysis | GraphRAG (call-graph / dependency tracing) |
| Sandboxed Testing | Docker |
| AI Reasoning | Claude / GPT family |
| Vulnerability Grounding | NVD (CVE) API, OWASP Top 10 |
| Database | PostgreSQL |
| Reporting | Markdown → PDF |

## Project structure

```
app/
├── auth/            # authentication
├── users/           # user management
├── roles/           # role definitions
├── permissions/     # access control
├── ai/              # LLM clients + agent orchestration
├── database/         # models, migrations, session
├── api/             # route handlers
└── core/             # config, shared utilities

targets/              # vulnerable apps used for evaluation (DVWA, Juice Shop)
tests/                # unit tests + evaluation harness
```

## Evaluation

Performance is tracked across phases modeled on established AI-security benchmarks (PentestGPT, AutoPenBench, CyberSecEval):

- **Phase A** — Detection precision / recall / false-positive rate
- **Phase B** — Exploit simulation success rate
- **Phase C** — Remediation accuracy & code safety (no regressions, exploit actually closed)
- **Phase D** — Comparative baseline vs. human pentesters (survey-based)

Ground truth: isolated, fully-mapped Docker targets — OWASP Juice Shop and the DVWA difficulty matrix.

## Team

| Name |
|---|
| Mahmoud Elbasel | 
| Amr Khaled Ahmed | 
| Fares Abdulhamid | 
| Youssef Shaker | 
| Mohamed Ali Hassan | 

**Supervisor:** Dr. Mohammad El-Ramly

## Status

🚧 Active development — early build phase (Knowledge & Index, Threat Discovery, Evidence Validator).

---

<div align="center">
<sub>Faculty of Computers and Artificial Intelligence, Cairo University — Graduation Project 2026/2027</sub>
</div>
