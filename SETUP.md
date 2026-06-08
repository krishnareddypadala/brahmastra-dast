# BRAHMASTRA DAST - Setup & Deployment Guide

How to get a working BRAHMASTRA DAST instance up and running on a Linux box or WSL2 Ubuntu, end to end. Estimated time: **60 to 90 minutes** on a clean install.

This guide assumes you want the full on-prem experience: local BRAHMASTRA 0.3 model running in Ollama plus the DAST scanner serving its dashboard on port 8888. If you only want the scanner pointed at a cloud LLM (Gemini / Claude / OpenAI), skip steps 3 and 4 and configure the API key in the dashboard at scan time.

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Install system dependencies](#2-install-system-dependencies)
3. [Install Ollama](#3-install-ollama)
4. [Download and register the BRAHMASTRA 0.3 model](#4-download-and-register-the-brahmastra-03-model)
5. [Set up PostgreSQL](#5-set-up-postgresql)
6. [Clone and install the scanner](#6-clone-and-install-the-scanner)
7. [Start the DAST server](#7-start-the-dast-server)
8. [Verify the setup](#8-verify-the-setup)
9. [Run your first scan](#9-run-your-first-scan)
10. [Use commercial AI backends](#10-use-commercial-ai-backends)
11. [Troubleshooting](#11-troubleshooting)
12. [Production hardening](#12-production-hardening)
13. [Docker option](#13-docker-option)
14. [Uninstall](#14-uninstall)

---

## 1. Prerequisites

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU (for local AI) | NVIDIA card with 24 GB VRAM | RTX A5000 / 5090 / PRO 5000 Blackwell (32+ GB VRAM) |
| RAM | 16 GB | 32 GB |
| Disk | 40 GB free (model + scan history + temp) | 100 GB+ |
| Network | reachable from your browser; can reach scan targets | dedicated NIC |

**No GPU?** You can still run everything; just configure the dashboard to use a cloud LLM (Gemini Flash is free with generous limits). See [section 10](#10-use-commercial-ai-backends).

### OS

- Ubuntu 22.04 LTS or 24.04 LTS (bare metal or WSL2)
- Other Linux distros work but commands below use `apt`. For Fedora / Arch / etc., substitute your package manager.
- macOS works for the scanner + cloud LLM combo, but Ollama macOS GPU support is limited

### Software requirements (we install these in step 2)

- Python 3.10 or newer
- PostgreSQL 14+
- git
- NVIDIA driver if you have a GPU (already installed on most distros with NVIDIA hardware)

### Verify GPU is visible (skip if no GPU)

```bash
nvidia-smi
```

You should see your card listed with VRAM and driver version. If this fails on WSL2, install the latest NVIDIA Studio Driver on the Windows host (not inside WSL2). See [Microsoft's CUDA on WSL guide](https://learn.microsoft.com/en-us/windows/ai/directml/gpu-cuda-in-wsl).

---

## 2. Install system dependencies

```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv \
    postgresql postgresql-contrib \
    git curl build-essential
```

Confirm the versions:

```bash
python3 --version       # >= 3.10
psql --version          # >= 14
git --version
```

---

## 3. Install Ollama

Ollama is the LLM runtime that hosts the BRAHMASTRA model.

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

This installs Ollama as a systemd service and starts it. Verify:

```bash
systemctl is-active ollama       # should print "active"
curl -s http://localhost:11434/api/tags   # should return {"models":[]}
```

---

## 4. Download and register the BRAHMASTRA 0.3 model

### Option A: Pull the Q4_K_M GGUF from Hugging Face (recommended)

```bash
pip3 install --user huggingface_hub
~/.local/bin/huggingface-cli download Krishnapadala55/brahmastra-0.3-GGUF \
    brahmastra-v3.Q4_K_M.gguf \
    --local-dir ~/
```

Download is **~19 GB**. Allow 5 to 30 minutes depending on bandwidth.

### Option B: Use a GGUF you already have

If you previously exported your own GGUF (for example from a local fine-tune), just place the file at `~/brahmastra-v3.Q4_K_M.gguf`.

### Create the Ollama Modelfile

```bash
cat > ~/brahmastra-v3-Modelfile <<'EOF'
FROM /home/__USER__/brahmastra-v3.Q4_K_M.gguf
PARAMETER temperature 0.6
PARAMETER top_p 0.95
PARAMETER num_ctx 4096
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
TEMPLATE """<|im_start|>system
You are BRAHMASTRA, an elite AI-powered DAST security scanner. Use <think>...</think> to reason before each response.<|im_end|>
<|im_start|>user
{{ .Prompt }}<|im_end|>
<|im_start|>assistant
"""
SYSTEM """You are BRAHMASTRA, an elite AI-powered DAST security scanner. Use <think>...</think> to reason before each response. Be precise - only confirm vulnerabilities with clear evidence."""
EOF

# Substitute your actual username
sed -i "s|__USER__|$(whoami)|g" ~/brahmastra-v3-Modelfile
cat ~/brahmastra-v3-Modelfile | head -3
```

### Register the model in Ollama

```bash
ollama create brahmastra:0.3 -f ~/brahmastra-v3-Modelfile
```

This takes about 30 seconds. Verify:

```bash
ollama list | grep brahmastra
# expected: brahmastra:0.3   <hash>   19 GB   <minutes> ago
```

### Pre-warm the model in VRAM (optional but recommended)

```bash
curl -s http://localhost:11434/api/generate \
    -d '{"model":"brahmastra:0.3","prompt":"warm","keep_alive":-1,"stream":false}' \
    > /dev/null
```

The first call loads the 19 GB into VRAM and takes about 15 seconds. With `keep_alive:-1` the model stays loaded indefinitely, so future scans never pay this cold-start cost.

Verify VRAM is occupied:

```bash
nvidia-smi --query-gpu=memory.used --format=csv,noheader
# expected: ~20000 MiB
```

---

## 5. Set up PostgreSQL

The scanner uses Postgres to persist scans, findings, and AI reasoning chains.

### Start the service

```bash
sudo systemctl enable --now postgresql
pg_isready
# expected: /var/run/postgresql:5432 - accepting connections
```

### Create the user and database

```bash
sudo -u postgres createuser brahmastra
sudo -u postgres psql -c "ALTER USER brahmastra WITH PASSWORD 'brahmastra';"
sudo -u postgres createdb -O brahmastra brahmastra
```

(In production, replace the placeholder password with something strong and update the connection string later.)

### Verify

```bash
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra -c '\dt'
# expected: "Did not find any relations." (the schema is empty; migrations run on first scanner startup)
```

---

## 6. Clone and install the scanner

```bash
cd ~
git clone https://github.com/krishnareddypadala/brahmastra-dast.git
cd brahmastra-dast
```

### Create a Python virtual environment

```bash
python3 -m venv ~/brahmastra-env
source ~/brahmastra-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

The install takes 2 to 5 minutes (fastapi, asyncpg, httpx, uvicorn, plus 30+ deps).

### Apply database migrations

The scanner auto-applies migrations on startup, but you can run them manually to test:

```bash
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra \
    -f server/migrations/001_initial_schema.sql
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra \
    -f server/migrations/002_scan_chat.sql
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra \
    -f server/migrations/003_fp_analysis.sql
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra \
    -f server/migrations/004_multi_role_crawl.sql

PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra -c '\dt'
# expected: 27 tables including scans, findings, events, scan_chat, etc.
```

---

## 7. Start the DAST server

From the scanner directory with the venv activated:

```bash
cd ~/brahmastra-dast
source ~/brahmastra-env/bin/activate

python3 -m uvicorn server.api:app --host 0.0.0.0 --port 8888
```

You should see:

```
INFO:     Started server process [<pid>]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8888 (Press CTRL+C to quit)
```

### Run as a background service (recommended)

```bash
nohup python3 -m uvicorn server.api:app \
    --host 0.0.0.0 --port 8888 \
    > /tmp/brahmastra-dast.log 2>&1 < /dev/null &

disown -a
echo "Started PID $!"
```

### Or with systemd (production)

Create `/etc/systemd/system/brahmastra-dast.service`:

```ini
[Unit]
Description=BRAHMASTRA DAST Scanner
After=network.target postgresql.service ollama.service

[Service]
Type=simple
User=YOUR_USER
WorkingDirectory=/home/YOUR_USER/brahmastra-dast
Environment="PATH=/home/YOUR_USER/brahmastra-env/bin"
ExecStart=/home/YOUR_USER/brahmastra-env/bin/python3 -m uvicorn server.api:app --host 0.0.0.0 --port 8888
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now brahmastra-dast
sudo systemctl status brahmastra-dast
```

---

## 8. Verify the setup

### Quick health check

```bash
curl -s http://localhost:8888/api/health | python3 -m json.tool
```

Expected response:

```json
{
    "status": "ok",
    "backends": {
        "heuristic":     { "online": true,  "needs_key": false, ... },
        "brahmastra":    { "online": true,  "needs_key": false, "label": "BRAHMASTRA 0.3 (32B, cleaned + DAST synth)" },
        "brahmastra_02": { "online": false, "needs_key": false, ... },
        "gemini_flash":  { "online": false, "needs_key": true,  ... },
        ...
    }
}
```

Critical fields:

- `status` must be `"ok"`
- `backends.brahmastra.online` must be `true` (this confirms Ollama can reach the model)

### Open the dashboard

In a browser on the same machine:

```
http://localhost:8888
```

Or from another device on your LAN, using your Linux box's IP:

```
http://<your-server-ip>:8888
```

You should see the BRAHMASTRA dashboard with the AI Mode dropdown showing "BRAHMASTRA 0.3 (32B, cleaned + DAST synth)" available.

---

## 9. Run your first scan

### From the dashboard

1. Open `http://localhost:8888`
2. **Target URL:** `https://httpbin.org` (deliberately safe public test target) OR your own authorized lab
3. **AI Mode:** select `BRAHMASTRA 0.3 (32B, cleaned + DAST synth)` (the default)
4. **Profile:** `quick` (for first test) or `full` (for thorough)
5. Click **Launch Scan**

You should see findings stream in real time via SSE. Click any finding to see the AI's `<think>` reasoning chain.

### From the CLI

```bash
cd ~/brahmastra-dast
source ~/brahmastra-env/bin/activate

python3 -m cli.main scan \
    --target https://httpbin.org \
    --profile quick \
    --ai-mode brahmastra
```

### Disclaimer

**Only scan systems you own or have explicit written authorization to test.** BRAHMASTRA sends real attack payloads. Use on unauthorized targets is illegal in most jurisdictions.

---

## 10. Use commercial AI backends

If you do not have a 24 GB GPU, or you want to A/B compare verdicts, configure a cloud LLM. The scanner accepts API keys per-scan from the dashboard, so no secrets are stored on disk.

Supported backends:

| Mode | Backend | Where to get a key |
|------|---------|--------------------|
| `gemini_flash` | Gemini 2.5 Flash | https://aistudio.google.com/apikey (free tier) |
| `gemini_pro` | Gemini 2.5 Pro | https://aistudio.google.com/apikey |
| `claude_haiku` | Claude Haiku 4.5 | https://console.anthropic.com |
| `claude_sonnet` | Claude Sonnet 4 | https://console.anthropic.com |
| `openai` | GPT-4o-mini | https://platform.openai.com/api-keys |

In the dashboard:

1. Change AI Mode to your preferred backend
2. Paste the API key in the field that appears
3. Launch the scan

Cloud backends cost roughly **$0.10 to $0.50 per scan** depending on the model and finding count.

---

## 11. Troubleshooting

### `brahmastra:0.3 backend offline` in health check

Most common: Ollama is not running or the model is not registered.

```bash
systemctl is-active ollama
curl -s http://localhost:11434/api/tags | python3 -c "import sys,json; print([m['name'] for m in json.load(sys.stdin)['models']])"
```

If `brahmastra:0.3` is absent, re-run the `ollama create` step from section 4.

### `nvidia-smi: command not found` inside WSL2

The NVIDIA driver must be installed on the **Windows host**, not inside WSL2. After installing on Windows, restart WSL2:

```powershell
# In Windows PowerShell
wsl --shutdown
```

Then reopen Ubuntu and re-test.

### Ollama is "Killed" or runs very slowly

Almost always insufficient VRAM. Confirm:

```bash
nvidia-smi --query-gpu=memory.total,memory.used --format=csv,noheader
```

You need at least 22 GB total VRAM available. If the GPU is shared with the Windows desktop, expect 2 to 4 GB to be reserved. Solutions:

- Close any other GPU consumers (browser tabs, games, video editors)
- Set Windows display to "no preference" / iGPU when working from BRAHMASTRA
- Or fall back to a smaller variant (see [BRAHMASTRA 0.3-LoRA](https://huggingface.co/Krishnapadala55/brahmastra-0.3-lora))

### `pg_isready` succeeds but psql says "role brahmastra does not exist"

You skipped the `createuser` step. Redo section 5.

### Scans launch but findings show `fp_analysis.ai_reason: "AI bridge disabled or unreachable"`

The DAST server cannot reach Ollama. Check:

```bash
curl -s http://localhost:11434/api/tags
# If this works from your shell but the scanner sees it as unreachable,
# the scanner is probably bound to a different network namespace.
# In WSL2, ensure both Ollama and the scanner run inside the same WSL2 instance.
```

### Port 8888 is in use

```bash
ss -tlnp | grep 8888
# If something else is listening, either kill it or change the port:
python3 -m uvicorn server.api:app --host 0.0.0.0 --port 9999
```

### The model returns refusals on legitimate scans

BRAHMASTRA 0.3 is alignment-tuned to refuse unauthorized targeting. If you see refusals for a real authorized scan, the `<think>` chain will usually say so explicitly. Confirm:

1. The target URL clearly indicates authorized testing context (use a controlled test domain or an obvious "lab" subdomain)
2. The `system` prompt has not been altered

### `permission denied` writing to `/tmp/brahmastra-dast.log`

Switch to a path you own:

```bash
nohup python3 -m uvicorn server.api:app --host 0.0.0.0 --port 8888 \
    > ~/brahmastra-dast.log 2>&1 < /dev/null &
```

---

## 12. Production hardening

If you plan to run this on a shared / always-on server, do these before going live.

### Change default Postgres password

```bash
sudo -u postgres psql -c "ALTER USER brahmastra WITH PASSWORD '$(openssl rand -hex 24)';"
```

Set the connection string via env var:

```bash
export BRAHMASTRA_DB_URL='postgresql://brahmastra:NEW_PASSWORD@127.0.0.1:5432/brahmastra'
```

### Bind only to localhost (or behind a reverse proxy)

By default the scanner binds to `0.0.0.0:8888`, accessible to everyone on the LAN. For production, bind to `127.0.0.1` and put nginx / Caddy in front with TLS:

```bash
python3 -m uvicorn server.api:app --host 127.0.0.1 --port 8888
```

Example Caddy config (`/etc/caddy/Caddyfile`):

```
brahmastra.example.com {
    reverse_proxy 127.0.0.1:8888
    # Caddy auto-issues a Let's Encrypt cert
}
```

### Add basic auth (or SSO)

Until BRAHMASTRA ships native auth, gate access with a reverse-proxy auth layer (Caddy `basic_auth`, nginx `auth_basic`, or Authelia / Authentik for SSO).

### Resource limits

If you share the GPU with other workloads, set an Ollama memory limit:

```bash
sudo systemctl edit ollama
```

Add:

```
[Service]
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_NUM_PARALLEL=2"
```

### Log retention

The DAST server logs to wherever you redirected stdout. Wire it into `logrotate`:

```bash
sudo tee /etc/logrotate.d/brahmastra <<'EOF'
/var/log/brahmastra-dast.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
EOF
```

---

## 13. Docker option

A `Dockerfile` and `docker-compose.yml` ship with the repo for a containerised setup. **Important:** the Ollama container needs the `--gpus all` flag (and the nvidia-container-toolkit installed on the host).

```bash
# Install nvidia-container-toolkit
distribution=$(. /etc/os-release; echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/libnvidia-container/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt update && sudo apt install -y nvidia-container-toolkit
sudo systemctl restart docker

# Bring up the stack
cd ~/brahmastra-dast
docker compose up -d
```

This launches three containers:

1. `ollama` (hosts the BRAHMASTRA model, gets GPU access)
2. `postgres` (scan state)
3. `brahmastra-dast` (FastAPI + dashboard, port 8888)

On first start the Ollama container pulls and registers the model automatically.

---

## 14. Uninstall

To remove everything:

```bash
# Stop and remove services
sudo systemctl stop brahmastra-dast 2>/dev/null
sudo systemctl disable brahmastra-dast 2>/dev/null
sudo rm -f /etc/systemd/system/brahmastra-dast.service
sudo systemctl stop ollama
sudo systemctl stop postgresql

# Remove the model
ollama rm brahmastra:0.3

# Remove the database
sudo -u postgres dropdb brahmastra
sudo -u postgres dropuser brahmastra

# Remove the code and venv
rm -rf ~/brahmastra-dast ~/brahmastra-env
rm -f ~/brahmastra-v3.Q4_K_M.gguf ~/brahmastra-v3-Modelfile
```

Postgres and Ollama themselves stay installed (other apps may use them). To remove those too:

```bash
sudo apt purge -y postgresql postgresql-contrib
sudo rm -rf /var/lib/postgresql /etc/postgresql

curl -fsSL https://ollama.com/uninstall.sh | sh
```

---

## Where to go next

- **Run benchmarks**: pull [`Krishnapadala55/brahmastra-benchmark`](https://huggingface.co/datasets/Krishnapadala55/brahmastra-benchmark), replay the 6-suite eval against your own backend, compare F1 with the published numbers
- **Customize the rule engine**: drop new detectors into `brahmastra/narayanastra/rules.py`
- **Plug in a custom AI backend**: extend `brahmastra/ai_bridge.py` (see `_call_ollama`, `_call_gemini`, `_call_claude` for examples)
- **File issues, request features, or contribute fixes**: https://github.com/krishnareddypadala/brahmastra-dast/issues

---

## Quick reference

```bash
# Health check
curl -s http://localhost:8888/api/health | python3 -m json.tool

# Start everything (after install)
sudo systemctl start postgresql ollama
nohup python3 -m uvicorn server.api:app --host 0.0.0.0 --port 8888 > ~/brahmastra-dast.log 2>&1 &

# Stop the scanner
pkill -f "uvicorn server.api:app"

# Pre-warm the model in VRAM
curl -s http://localhost:11434/api/generate \
    -d '{"model":"brahmastra:0.3","prompt":"warm","keep_alive":-1,"stream":false}' > /dev/null

# Unload the model from VRAM
curl -s http://localhost:11434/api/generate \
    -d '{"model":"brahmastra:0.3","keep_alive":0}' > /dev/null

# Inspect Ollama models
ollama list

# Inspect Postgres state
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra -c '\dt'

# Reset the scan database (DANGEROUS: deletes all scan history)
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra -c 'TRUNCATE scans CASCADE;'
```

---

**Maintainer**: Krishna Padala
**Repository**: https://github.com/krishnareddypadala/brahmastra-dast
**Model**: https://huggingface.co/Krishnapadala55/brahmastra-0.3
**Last updated**: 2026-06-08
