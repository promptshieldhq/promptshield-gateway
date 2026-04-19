# PromptShield Gateway

[![CI](https://github.com/promptshieldhq/promptshield-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/promptshieldhq/promptshield-gateway/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/promptshieldhq/promptshield-gateway)](https://goreportcard.com/report/github.com/promptshieldhq/promptshield-gateway)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/promptshieldhq/promptshield-gateway)](go.mod)
[![Release](https://img.shields.io/github/v/release/promptshieldhq/promptshield-gateway)](https://github.com/promptshieldhq/promptshield-gateway/releases)

A free, open-source LLM security gateway. Drop it between your app and any LLM provider to get rate limiting, audit logging, token tracking, and Prometheus metrics with no code changes to your app.

---

## How it works

Every request flows through the gateway. Policy decisions happen before the LLM is ever called.

| Action | What happens |
|--------|-------------|
| `block` | Request stopped, HTTP 403 returned — LLM never called |
| `mask` | PII replaced with `[ENTITY_TYPE]` before forwarding |
| `allow` | Prompt forwarded unchanged |

---

## Quickstart

```bash
git clone https://github.com/promptshieldhq/promptshield-gateway
cd promptshield-gateway

cp .env.example .env
# edit .env: set PROMPTSHIELD_PROVIDER and your API key

make run
# gateway listening on :8080
```

Test it:

```bash
curl http://localhost:8080/health
# {"status":"ok","service":"promptshield-gateway"}

curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-2.5-flash",
    "messages": [
      {
        "role": "user",
        "content": "What is the capital of Nepal?"
      }
    ]
  }'
```

---

## Modes

**Gateway mode** (default) : transparent gateway with rate limiting, token tracking, and audit logs. No PII scanning. Zero extra dependencies.
```
PROMPTSHIELD_ENGINE_URL=none
```

**Security mode** : full PII and injection scanning on every request via the detection engine.
```
PROMPTSHIELD_ENGINE_URL=http://localhost:4321
```

---

## Docker

```bash
git clone https://github.com/promptshieldhq/promptshield-gateway
cd promptshield-gateway
docker build -t promptshield-gateway .

docker run -p 8080:8080 \
  -e PROMPTSHIELD_PROVIDER=anthropic \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -v $(pwd)/config/policy.yaml:/app/config/policy.yaml:ro \
  promptshield-gateway
```

Swap the provider and key for whichever backend you use (`openai`, `gemini`, etc). The policy file mount is optional , omit it to run in gateway mode with no scanning.

---

## Build from source

```bash
make build   # outputs bin/promptshield

make run     # dev mode
```

Requirements: Go 1.22+

---

## Documentation

- Docs: [promptshield-docs.vercel.app](https://promptshield-docs.vercel.app/)
- Docs source: [promptshieldhq/promptshield-docs](https://github.com/promptshieldhq/promptshield-docs)

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=promptshieldhq/promptshield-gateway&type=Date)](https://star-history.com/#promptshieldhq/promptshield-gateway&Date)
