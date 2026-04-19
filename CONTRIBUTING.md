# Contributing to promptshield-gateway

MIT-licensed. PRs welcome.

## Getting started

1. Fork the repo and clone it locally.
2. Install Go (see `go.mod` for the required version).
3. Install [golangci-lint](https://golangci-lint.run/welcome/install/) for linting.
4. Copy `.env.example` to `.env` and fill in your keys.
5. Run the gateway: `make run`

## Making changes

- Keep changes focused, i.e one logical fix or feature per PR.
- Run `go vet ./...` and `go build ./...` before opening a PR.
- If you add a new provider or policy field, update `config/policy.yaml` and `.env.example`.
- No API keys or secrets in commits.

## Submitting a pull request

Use the PR template, fill in what the change does, how you tested it, and link any related issue.

## Reporting issues

Use the GitHub issue templates:

- **Bug report** : something is broken
- **Feature request** : something new or improved
- **Other** : questions, docs, anything else

## License

By contributing, you agree your code will be licensed under the [MIT License](./LICENSE).
