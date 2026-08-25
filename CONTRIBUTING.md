# Contributing to HorusShield

Thanks for considering contributing. A few ground rules, since this is a real, working security tool, not a toy project:

## Ground Rules

1. **Don't break working features.** HorusShield's standing rule across its whole history: don't rewrite or restyle working code without a concrete reason (a bug, a security issue, a measurable performance/maintainability win). If you're "just cleaning up," open an issue and discuss it first.
2. **V-8 Scanner stays an orchestrator, never an exploit engine.** It coordinates OWASP ZAP, Nikto, and Nmap — all actual testing logic lives in those tools. Do not add custom payload/exploit generation code, even for "better coverage." PRs that do this will be declined regardless of how well-written they are.
3. **No secrets in commits.** Every credential goes through an environment variable — see `.env.example`. If you accidentally commit one, rotate it immediately and say so in the PR, don't just force-push over it.
4. **Tests for new behavior.** If you add an API endpoint, a DB table, or a non-trivial function, add a test in `tests/`. See `docs/TESTING.md`.

## Getting Set Up

```bash
git clone <repo-url>
cd HorusShield_2.0
pip install -r backend/requirements.txt
pip install pytest black isort flake8
cp .env.example .env
pytest tests/ -v
```

## Before Opening a PR

```bash
black --check tests scripts backend/<files_you_touched>
isort --check-only tests scripts backend/<files_you_touched>
flake8 tests scripts backend/<files_you_touched>
pytest tests/ -v
python scripts/check_imports.py
```

CI runs all of this automatically, but catching it locally first saves everyone a review cycle.

## Commit Messages

Plain, descriptive, present tense: `Fix V-8 Scanner PDF crash on em-dash in target URL`, not `fixed stuff` or `WIP`.

## Reporting Bugs

Open an issue with: what you did, what you expected, what actually happened, and — for anything security-relevant — see [`SECURITY.md`](SECURITY.md) instead of a public issue.

## Reporting Security Issues

**Do not open a public issue for security vulnerabilities.** See [`SECURITY.md`](SECURITY.md) for responsible disclosure.

## Code of Conduct

This project follows [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
