---
name: Bug report
about: Something is broken in the proxy
title: ''
labels: bug
assignees: ''

---

**What happened**

<!-- Include exact error messages, HTTP status codes, or unexpected behavior. -->

**What you expected to happen**

**Steps to reproduce**

<!-- Minimal reproduction — a curl command and config snippet is ideal. -->

```bash
# example
curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{ ... }'
```

**Environment**

- PromptShield version / commit:
- Go version (`go version`):
- OS:
- Mode: gateway / security (with detection engine)
- Provider: openai / anthropic / gemini / other

**Policy config** (`config/policy.yaml`)

<details>
<summary>policy.yaml</summary>

```yaml
# paste your policy here (redact anything sensitive)
```

</details>

**Proxy logs**

<details>
<summary>logs</summary>

```
# paste relevant log output here
```

</details>

**Anything else**

<!-- Detection engine version, relevant env vars (redact keys), etc. -->
