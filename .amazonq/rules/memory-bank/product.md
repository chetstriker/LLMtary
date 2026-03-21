# PenExecute — Product Overview

## Purpose
PenExecute is a Flutter desktop application that automates penetration testing workflows using large language models. It accepts structured scan data (ports, services, banners, DNS, WAF, SSL), runs a phased LLM analysis pipeline to identify vulnerabilities, then autonomously validates each finding by executing real shell commands on the tester's machine.

## Value Proposition
- Replaces manual triage of scan output with a structured, phased LLM pipeline
- Validates findings with real command execution rather than static analysis
- Chains confirmed findings into multi-step attack paths automatically
- Runs entirely locally — no cloud execution environment

## Target Users
Security professionals conducting authorized penetration testing engagements, security researchers, and CTF competitors.

## Key Features

### Analysis Pipeline (2-Phase)
- **Phase 1** (fast, always runs): CVE/version matching, network service analysis, DNS/OSINT, SNMP. Builds a context block injected into Phase 2.
- **Phase 2** (enriched with Phase 1 context): Web app (4 passes), Active Directory (3 passes), SSL/TLS, privilege escalation, 15+ technology-specific deep-dives (WordPress, Jenkins, Exchange, VMware, etc.)
- Scope-aware: internal (RFC-1918) vs external targets get different prompt sets
- Post-analysis: deduplication, evidence validation, severity sort, BloodHound-style AD chain reasoning (fires when ≥2 HIGH/CRITICAL AD findings)

### Active Exploit Testing Loop
- Agentic loop: RECON → VERIFICATION → EXPLOITATION → CONFIRMATION phases
- Executes real commands, evaluates output, adapts approach
- Hard cap: 100 iterations (CVE-backed), 20 iterations (speculative)
- OPSEC-aware prompting, rate-limit detection, duplicate command prevention
- Metasploit pre-flight check; skips if unavailable

### Attack Chain Reasoning
- Confirmed artifacts (RCE, SQLi, auth bypass, LFI, SSRF) fed forward as context for subsequent tests
- Post-execution chain reasoning pass (fires when ≥2 confirmed findings) adds `AttackChain` findings

### Credential Bank
- Session-wide credential collection with deduplication by service/host/username fingerprint
- Verified credentials (seen in output) vs inferred credentials tracked separately
- Auto-injected as context for subsequent vulnerability tests

### Project Management
- Multiple named projects, each with multiple targets
- SQLite persistence for findings, command logs, credentials
- Encrypted `.penex` export/import (AES, password-protected)

### Report Generation
- HTML (professional, cover page, executive summary, CVSS metadata, credentials table)
- Markdown (portable)
- CSV (flat findings list)

### Safety Controls
- Dangerous command blocklist (`rm -rf`, `format`, `mkfs`, `dd`, `shutdown`, fork bomb, etc.)
- Command approval mode (pause before each execution)
- Configurable command whitelist
- Sensitive output sanitization

### Cross-Platform
- Linux, macOS, Windows
- Windows: WSL detection → bash via WSL; fallback to PowerShell/cmd
- OS detection informs LLM command choices throughout

## Supported AI Providers
Ollama (local), LM Studio (local), Claude (Anthropic), ChatGPT (OpenAI), Gemini (Google), OpenRouter, Custom (configurable URL + key)

## Default Configuration
- Temperature: 0.22
- Max tokens: 4096 (UI default; 32000 in settings)
- Timeout: 240s per command
