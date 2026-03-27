# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported |
|---------|-----------|
| latest  | ✓         |
| older   | ✗         |

## Reporting a Vulnerability

Do not report security vulnerabilities through public GitHub issues.

Open a [GitHub Security Advisory](https://github.com/promptshieldhq/promptshield-proxy/security/advisories/new) instead. Reports stay private until a fix is released.

Include:

- Type of issue
- File paths and line numbers relevant to the issue
- Steps to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact — what an attacker could achieve

Expect an initial response within **72 hours** and a fix or mitigation plan within **14 days** for confirmed issues.

## Scope

Things we consider in scope:

- API key leakage through proxy responses or logs
- Policy bypass (blocked content reaching the upstream LLM)
- SSRF via configurable upstream URLs
- Prompt injection bypassing the detection engine
- Authentication or rate-limit bypass

Things out of scope:

- Vulnerabilities in upstream LLM providers (report those to the provider)
- Issues requiring physical access to the server
- Social engineering

## Disclosure Policy

Once a fix is released, we will publish a security advisory describing the vulnerability, its impact, and the fix. Credit will be given to the reporter unless they prefer to remain anonymous.
