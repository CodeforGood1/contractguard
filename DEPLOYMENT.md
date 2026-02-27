# ContractGuard — Deployment Guide

> For usage instructions see [INSTRUCTIONS.md](INSTRUCTIONS.md).
> For capability reference see [CAPABILITIES.md](CAPABILITIES.md).

---

## Table of Contents

1. [Local Development](#1-local-development)
2. [Docker](#2-docker)
3. [GitHub Actions CI](#3-github-actions-ci)
4. [Cloud Deployment — Web UI](#4-cloud-deployment--web-ui)
5. [Environment Variables](#5-environment-variables)
6. [Production Checklist](#6-production-checklist)

---

## 1. Local Development

### Setup

```bash
git clone https://github.com/contractguard/contractguard.git
cd contractguard

python -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .venv\Scripts\Activate.ps1    # Windows

pip install -e ".[dev]"
```

### Run tests

```bash
pytest tests/ -v
# 162 tests, ~2 seconds
```

### Run the CLI

```bash
contractguard analyze --type all --path samples/ --score
```

### Run the web UI

```bash
contractguard serve
# Listening at http://127.0.0.1:8000
```

---

## 2. Docker

### Dockerfile

Create a `Dockerfile` in the project root:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY rules/ rules/

RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["contractguard", "serve", "--host", "0.0.0.0", "--port", "8000"]
```

> **Note:** The `serve` command needs `--host 0.0.0.0` to be accessible outside the container. Add that flag to `cli.py`'s `serve` command if deploying via Docker.

### Build and run

```bash
docker build -t contractguard:latest .
docker run -p 8000:8000 contractguard:latest
# Web UI at http://localhost:8000
```

### Scan a local directory via Docker

```bash
docker run --rm -v $(pwd)/myproject:/scan contractguard:latest \
  contractguard analyze --type all --path /scan --report-json /scan/report.json
```

---

## 3. GitHub Actions CI

The workflow is already included at `.github/workflows/contractguard-ci.yml`.

### What it does

- Triggers on every `push` and `pull_request`
- Installs ContractGuard in a Python 3.11 environment
- Runs the full test suite (`pytest`)
- Runs `--type all` against the repo
- Uploads HTML report as a build artifact (downloadable from the Actions tab)
- Exports SARIF 2.1.0 and uploads to GitHub Code Scanning
- **Returns exit code 2** on CRITICAL or BLOCK findings — failing the build

### Enable GitHub Code Scanning

1. Push the workflow file to your repo
2. Go to **Settings → Code security and analysis → Code scanning**
3. After the first run, findings appear under **Security → Code scanning alerts**

### Adding to an existing workflow

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install ContractGuard
        run: pip install contractguard

      - name: Run security scan
        run: |
          contractguard analyze --type all --path . \
            --ci \
            --report security-report.html \
            --report-sarif results.sarif

      - name: Upload HTML report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.html

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

---

## 4. Cloud Deployment — Web UI

Deploy the FastAPI web UI to any Python-compatible cloud host.

### Render (free tier)

1. Push the repo to GitHub
2. Create a new **Web Service** on [render.com](https://render.com)
3. Set:
   - **Build command:** `pip install -e .`
   - **Start command:** `uvicorn contractguard.web:create_app --factory --host 0.0.0.0 --port $PORT`
4. Deploy — Render assigns a public URL

### Railway

1. Connect your GitHub repo on [railway.app](https://railway.app)
2. Set the start command:
   ```
   uvicorn contractguard.web:create_app --factory --host 0.0.0.0 --port $PORT
   ```
3. Railway auto-detects Python and deploys

### Heroku

```bash
# Procfile
web: uvicorn contractguard.web:create_app --factory --host 0.0.0.0 --port $PORT
```

```bash
heroku create contractguard-app
git push heroku main
heroku open
```

### Fly.io

```bash
fly launch
# Set start command to uvicorn as above
fly deploy
```

### Self-hosted VPS (nginx + systemd)

1. Install Python 3.11 and clone the repo
2. Create a systemd service:

```ini
# /etc/systemd/system/contractguard.service
[Unit]
Description=ContractGuard Web UI
After=network.target

[Service]
WorkingDirectory=/opt/contractguard
ExecStart=/opt/contractguard/.venv/bin/uvicorn contractguard.web:create_app --factory --host 127.0.0.1 --port 8000
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

3. Configure nginx to proxy port 80 → 8000:

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
sudo systemctl enable contractguard
sudo systemctl start contractguard
```

---

## 5. Environment Variables

ContractGuard runs fully offline with no required environment variables. Optional configuration:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CONTRACTGUARD_RULES_DIR` | `./rules` | Path to custom rules directory |
| `CONTRACTGUARD_DB_PATH` | `.contractguard/history.db` | SQLite history database location |
| `PYTHONIOENCODING` | system default | Set to `utf-8` on Windows for emoji output |

### Example `.env` for deployment

```env
CONTRACTGUARD_RULES_DIR=/opt/contractguard/rules
CONTRACTGUARD_DB_PATH=/var/lib/contractguard/history.db
PYTHONIOENCODING=utf-8
```

---

## 6. Production Checklist

Before going live with the web UI:

- [ ] Run behind a reverse proxy (nginx/Caddy) — never expose uvicorn directly on port 80/443
- [ ] Enable HTTPS — use Let's Encrypt (Certbot) or your cloud provider's TLS termination
- [ ] Set file upload size limits in nginx (`client_max_body_size 10m`)
- [ ] Consider authentication if the instance is public-facing (the web UI has no auth by default)
- [ ] Set `PYTHONIOENCODING=utf-8` in the service environment on Linux hosts
- [ ] Store `history.db` on a persistent volume if deploying in containers
- [ ] Pin Docker base image to a specific digest, not `:latest`
- [ ] Run the container as a non-root user (add `USER nobody` to Dockerfile)
- [ ] Run `contractguard analyze --type all --path . --ci` in your deploy pipeline to gate releases
