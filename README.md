# Insecure WebApp (Node) — for SAST testing only

This repository is **intentionally vulnerable** to help you test SAST pipelines (SonarQube, etc.).
Do **NOT** deploy this anywhere public or connect it to real data.

## Notable insecure patterns included
- SQL injection (string concatenation into SQL)
- Command injection via `child_process.exec`
- XSS via unescaped EJS output
- Hardcoded credentials & secrets
- Disabled TLS verification
- Insecure cookies (no HttpOnly/Secure)
- `eval` on user input
- Duplicated code & high cognitive complexity
- 0% test coverage

## Quick start (local only — not required for SAST)
```bash
npm install
npm start
# open http://localhost:3000
```
