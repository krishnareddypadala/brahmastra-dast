# BRAHMASTRA DAST - Setup & Deployment Guide

How to get a working BRAHMASTRA DAST instance up and running, end to end.
The scanner runs the same way whether you use a **local AI** (BRAHMASTRA 0.3 on Ollama) or a **public cloud AI** (Gemini, Claude, OpenAI). Pick the path that fits your environment.

---

## Choose your path

| | **Path A: Cloud AI** | **Path B: Local AI (BRAHMASTRA 0.3)** |
|---|---|---|
| **Setup time** | 10 to 15 minutes | 60 to 90 minutes |
| **GPU needed?** | No | Yes (24 GB VRAM minimum) |
| **Disk** | ~5 GB | ~40 GB (model + history) |
| **RAM** | 8 GB | 16+ GB |
| **Cost per scan** | $0.05 to $0.50 (per cloud usage) | $0 |
| **Privacy** | Scan data sent to chosen cloud provider | Fully on-prem, data never leaves your perimeter |
| **Audit story** | Cloud provider's terms apply | Open weights, every `<think>` chain reviewable |
| **AI quality** | GPT-4 / Claude / Gemini class | Specialized 32B, +23.9pp accuracy on DAST tasks vs 32B baseline |
| **API key required?** | Yes, per provider | No |
| **Offline support** | No | Yes |
| **Best for** | First-time tinkering, demos, low-volume teams, no-GPU laptops | Production, regulated environments, high-volume scanning |

**Both paths share the same scanner core**: the only difference is which AI backend gets called when an ambiguous finding needs judgment.

**Recommendation**: start with **Path A** (cloud) to get a working setup in 15 minutes and confirm the scanner works for you. If you like it and want privacy / cost / scale, **upgrade to Path B** (local) later. You can always switch from the dashboard per scan; both paths coexist.

---

## Table of contents

- [Common foundation (both paths)](#common-foundation-both-paths)
- [Path A: Cloud AI](#path-a-cloud-ai)
- [Path B: Local AI (BRAHMASTRA 0.3)](#path-b-local-ai-brahmastra-03)
- [Start the DAST server](#start-the-dast-server)
- [Verify the setup](#verify-the-setup)
- [Run your first scan](#run-your-first-scan)
- [Mixing paths: same scanner, different backends per scan](#mixing-paths-same-scanner-different-backends-per-scan)
- [Troubleshooting](#troubleshooting)
- [Production hardening](#production-hardening)
- [Docker option](#docker-option)
- [Uninstall](#uninstall)
- [Quick reference](#quick-reference)

---

## Common foundation (both paths)

These steps apply regardless of which AI backend you choose. Estimated time: 10 minutes on a clean Ubuntu install.

### 1. Prerequisites

- Ubuntu 22.04 or 24.04 (bare metal, VM, or WSL2). Other distros work; substitute your package manager.
- A user account with `sudo`
- Outbound HTTPS access (to clone the repo and pull dependencies; later also to reach scan targets and, in Path A, the cloud AI provider)

### 2. Install system dependencies

```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv \
    postgresql postgresql-contrib \
    git curl build-essential
```

Verify:

```bash
python3 --version       # >= 3.10
psql --version          # >= 14
git --version
```

### 3. Set up PostgreSQL

The scanner persists scans, findings, and AI reasoning chains in Postgres.

```bash
# Start the service
sudo systemctl enable --now postgresql
pg_isready          # expected: accepting connections

# Create the user and database
sudo -u postgres createuser brahmastra
sudo -u postgres psql -c "ALTER USER brahmastra WITH PASSWORD 'brahmastra';"
sudo -u postgres createdb -O brahmastra brahmastra

# Verify
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra -c '\dt'
# expected: "Did not find any relations." (schema is empty; migrations run on first scanner startup)
```

In production, replace `'brahmastra'` with a strong password and set `BRAHMASTRA_DB_URL` (see [Production hardening](#production-hardening)).

### 4. Clone and install the scanner

```bash
cd ~
git clone https://github.com/krishnareddypadala/brahmastra-dast.git
cd brahmastra-dast

python3 -m venv ~/brahmastra-env
source ~/brahmastra-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

The install takes 2 to 5 minutes (fastapi, asyncpg, httpx, uvicorn, plus 30+ deps).

### 5. Apply database migrations

The scanner auto-applies migrations on startup, but you can run them manually:

```bash
for f in server/migrations/*.sql; do
    PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra -f "$f"
done

PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra -c '\dt'
# expected: 27 tables including scans, findings, events, scan_chat
```

You are now ready for the AI backend step. **Pick Path A or Path B below** and follow that section.

---

## Path A: Cloud AI

**Use this path if** you do not have a 24 GB GPU, or you want the fastest possible time to first scan, or you are evaluating the tool.

The scanner accepts API keys per scan from the dashboard. **Keys are not stored on disk**: they live only in memory for the duration of a single scan.

Supported cloud backends:

| Mode | Backend | Where to get a key | Free tier? |
|------|---------|--------------------|:----------:|
| `gemini_flash` | Google Gemini 2.5 Flash | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) | Yes (generous) |
| `gemini_pro` | Google Gemini 2.5 Pro | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) | Yes (limited) |
| `claude_haiku` | Anthropic Claude Haiku 4.5 | [console.anthropic.com](https://console.anthropic.com) | No (paid) |
| `claude_sonnet` | Anthropic Claude Sonnet 4 | [console.anthropic.com](https://console.anthropic.com) | No (paid) |
| `openai` | OpenAI GPT-4o-mini | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) | No (paid) |

### A.1 Get an API key

For first-time setup, **Google Gemini Flash is recommended** because:

- Free tier with no credit card required for moderate use
- High request-per-minute limits
- Quality is competitive with Claude/GPT for DAST FP judgment in our benchmarks

Steps:

1. Open [aistudio.google.com/apikey](https://aistudio.google.com/apikey)
2. Sign in with a Google account
3. Click **Create API key**
4. Copy the key (starts with `AIzaSy...`)

You will paste this into the dashboard at scan time, not into any config file on disk.

### A.2 No further install required

The scanner already has the cloud-backend code wired in. The AIBridge will call the chosen cloud provider over HTTPS when you select a cloud AI mode on a scan.

**You can now skip to [Start the DAST server](#start-the-dast-server) and from there to your first scan.**

### A.3 Cost expectations

For a typical scan that produces 200 findings with ~50 routed to AI judgment:

| Backend | Tokens per scan | Approx. cost per scan |
|---------|----------------:|----------------------:|
| Gemini Flash 2.5 | ~50k input + 30k output | **$0.04** (or free under free-tier limits) |
| Gemini Pro 2.5 | ~50k input + 30k output | $0.25 |
| Claude Haiku 4.5 | ~50k input + 30k output | $0.17 |
| Claude Sonnet 4 | ~50k input + 30k output | $0.60 |
| GPT-4o-mini | ~50k input + 30k output | $0.05 |

(Costs are approximate as of mid-2026 published rates and will vary with finding volume and target complexity.)

### A.4 Privacy considerations

When using cloud AI:

- **Each finding's HTTP request and response trace is sent to the cloud provider** for judgment
- Sensitive customer data in scan responses (PII, credentials, tokens, internal hostnames) goes to the provider
- Each provider has different data handling: Anthropic and OpenAI explicitly do not train on API data; Google's terms vary by product and tier
- For regulated workloads (PCI-DSS, HIPAA, SOC 2), confirm the provider's data processing agreement covers your requirements before sending real scan data
- If unsure, switch to **Path B (local AI)** below

---

## Path B: Local AI (BRAHMASTRA 0.3)

**Use this path if** you have a 24 GB+ VRAM GPU and want privacy, $0 per-scan cost, or offline operation.

### B.1 Verify GPU is visible

```bash
nvidia-smi
```

You should see your card listed with VRAM and driver version. If this fails:

- **Bare metal Linux**: install the NVIDIA driver via `sudo apt install nvidia-driver-575` (or the latest available)
- **WSL2**: install the NVIDIA Studio Driver on the **Windows host**, then `wsl --shutdown` and reopen Ubuntu. See [Microsoft's CUDA on WSL guide](https://learn.microsoft.com/en-us/windows/ai/directml/gpu-cuda-in-wsl)

### B.2 Install Ollama

Ollama is the LLM runtime that hosts the BRAHMASTRA model.

```bash
curl -fsSL https://ollama.com/install.sh | sh

# Verify
systemctl is-active ollama       # expected: active
curl -s http://localhost:11434/api/tags   # expected: {"models":[]}
```

### B.3 Download the BRAHMASTRA 0.3 model from Hugging Face

```bash
pip3 install --user huggingface_hub
~/.local/bin/huggingface-cli download Krishnapadala55/brahmastra-0.3-GGUF \
    brahmastra-v3.Q4_K_M.gguf \
    --local-dir ~/
```

**~19 GB download**. Allow 5 to 30 minutes depending on bandwidth.

### B.4 Create the Ollama Modelfile

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
```

### B.5 Register the model in Ollama

```bash
ollama create brahmastra:0.3 -f ~/brahmastra-v3-Modelfile

# Verify
ollama list | grep brahmastra
# expected: brahmastra:0.3   <hash>   19 GB   <minutes> ago
```

This takes about 30 seconds.

### B.6 Pre-warm the model in VRAM (recommended)

```bash
curl -s http://localhost:11434/api/generate \
    -d '{"model":"brahmastra:0.3","prompt":"warm","keep_alive":-1,"stream":false}' \
    > /dev/null
```

The first call loads 19 GB into VRAM and takes ~15 seconds. With `keep_alive:-1` the model stays loaded indefinitely, so subsequent scans never pay the cold-start cost.

```bash
nvidia-smi --query-gpu=memory.used --format=csv,noheader
# expected: ~20000 MiB
```

### B.7 Cost expectations

After the one-time GPU investment (RTX A4000 / A5000 / PRO 5000 Blackwell / RTX 4090 / 5090):

- **$0 per scan**
- Power: roughly 250-400 W draw during active scans, idle when no scans running
- At a typical 1000 findings/week pipeline, the GPU pays back vs cloud AI in a few weeks of usage

You are now ready to start the scanner.

---

## Start the DAST server

This is the same for both paths.

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

### Run as a background service

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

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now brahmastra-dast
sudo systemctl status brahmastra-dast
```

The `After=ollama.service` line is harmless on Path A (cloud) systems where Ollama isn't installed; the dependency is treated as optional.

---

## Verify the setup

### Health check

```bash
curl -s http://localhost:8888/api/health | python3 -m json.tool
```

Expected response:

```json
{
    "status": "ok",
    "backends": {
        "heuristic":     { "online": true,  "needs_key": false, ... },
        "brahmastra":    { "online": true|false, "needs_key": false, "label": "BRAHMASTRA 0.3 ..." },
        "brahmastra_02": { "online": false, "needs_key": false, ... },
        "gemini_flash":  { "online": true, "needs_key": true,  ... },
        "gemini_pro":    { "online": true, "needs_key": true,  ... },
        "claude_haiku":  { "online": true, "needs_key": true,  ... },
        "openai":        { "online": true, "needs_key": true,  ... },
        ...
    }
}
```

Key fields:

- `status` must be `"ok"`
- **Path A (cloud)**: `gemini_flash` / `claude_haiku` / `openai` should show `online: true` and `needs_key: true`. `brahmastra` will show `online: false` (no local model registered).
- **Path B (local)**: `brahmastra` should show `online: true` and `needs_key: false`.
- It is normal and expected for the *other* path's backends to show offline; the dashboard only uses what you select.

### Open the dashboard

In a browser on the same machine:

```
http://localhost:8888
```

Or from another device on your LAN:

```
http://<your-server-ip>:8888
```

The AI Mode dropdown shows every backend the scanner knows about. Backends with grey "offline" indicators cannot be selected; backends marked "needs API key" will reveal a key field when chosen.

### Themes (appearance)

Click the gear icon (top-right of the header) to open the Appearance panel and pick one of four themes:

- **Midnight** - default deep dark slate with blue accent (best for low-light demos).
- **Aqua** - white background with light-blue accent (best for projector / classroom demos, screenshots in light reports).
- **Ocean** - deep navy / cyan dark variant.
- **Solarized** - warm cream low-eye-strain light variant.

Tick **Follow OS dark/light preference** to have the dashboard pick Aqua when your OS is in light mode and Midnight when it is in dark mode. The choice persists in `localStorage` (key `brahmastra_theme`) per browser.

---

## Run your first scan

### From the dashboard

1. Open `http://localhost:8888`
2. **Target URL**: `https://httpbin.org` (deliberately safe public test target) OR your own authorized lab
3. **AI Mode**: pick one
   - **Path A users**: select `Gemini 2.5 Flash (Google)` and paste your `AIzaSy...` API key in the field that appears
   - **Path B users**: select `BRAHMASTRA 0.3 (32B, cleaned + DAST synth)` (no key needed)
4. **Profile**: `quick` (for first test) or `full` (for thorough coverage)
5. Click **Launch Scan**

Findings stream in real time via SSE. Click any finding to see the AI's `<think>` reasoning chain.

### From the CLI

```bash
cd ~/brahmastra-dast
source ~/brahmastra-env/bin/activate

# Path A example
python3 -m cli.main scan \
    --target https://httpbin.org \
    --profile quick \
    --ai-mode gemini_flash \
    --api-key "AIzaSy..."

# Path B example
python3 -m cli.main scan \
    --target https://httpbin.org \
    --profile quick \
    --ai-mode brahmastra
```

### Disclaimer

**Only scan systems you own or have explicit written authorization to test.** BRAHMASTRA sends real attack payloads. Use on unauthorized targets is illegal in most jurisdictions.

---

## Mixing paths: same scanner, different backends per scan

The AI Mode dropdown is **per-scan**. You can:

- Use **Gemini Flash** for casual / experimental scans (free, fast)
- Use **BRAHMASTRA 0.3** for production / regulated scans (private, offline)
- Use **Claude Sonnet 4** for the hardest false-positive cases (highest quality)
- Use **brahmastra:0.2** (if registered) as a baseline for A/B comparison

The dashboard lets you switch on every scan. Both paths can coexist on the same server.

To run **Path A + Path B side by side** on the same server: complete the common foundation (steps 1 to 5) once, then do BOTH the cloud-key acquisition (Path A.1) and the Ollama / model setup (Path B.1 to B.6). The scanner will offer all backends in the dropdown.

---

## Troubleshooting

### Health check shows `"status":"ok"` but `brahmastra:0.3 backend offline`

This is **expected on Path A** (no local model). If you wanted Path B, then:

- Most common: Ollama is not running or the model is not registered
- Re-run section B.2 / B.5 above
- Test directly: `curl -s http://localhost:11434/api/tags | grep brahmastra`

### Gemini / Claude / OpenAI backend shows offline

- The scanner only does a basic reachability check at startup; if the network is offline at that moment, the backend appears offline
- Restart the scanner after restoring network connectivity
- Or just select the backend in the dashboard; the actual API call happens at scan time

### Scan launches but findings show `ai_reason: "AI bridge disabled or unreachable"`

Path A: the API key is wrong, expired, or out of quota.

```bash
# Test the key directly (Gemini example)
curl -s "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=YOUR_KEY" \
    -H 'Content-Type: application/json' \
    -d '{"contents":[{"parts":[{"text":"hi"}]}]}'
# Expect 200 with a "candidates" array. Any 4xx response is the key/billing issue.
```

Path B: the DAST server cannot reach Ollama. Check `systemctl status ollama` and `curl -s http://localhost:11434/api/tags`.

### `nvidia-smi: command not found` inside WSL2

The NVIDIA driver must be installed on the **Windows host**, not inside WSL2. After installing on Windows:

```powershell
wsl --shutdown
```

Reopen Ubuntu and re-test.

### Ollama is "Killed" or runs very slowly

Almost always insufficient VRAM. Confirm:

```bash
nvidia-smi --query-gpu=memory.total,memory.used --format=csv,noheader
```

You need at least 22 GB free for BRAHMASTRA 0.3. If your card is smaller:

- Close other GPU consumers
- Or **fall back to Path A** (cloud AI) - no GPU needed

### `pg_isready` succeeds but psql says "role brahmastra does not exist"

You skipped the `createuser` step. Redo step 3 in Common Foundation.

### Port 8888 is in use

```bash
ss -tlnp | grep 8888
# Kill the offender, or change the scanner port:
python3 -m uvicorn server.api:app --host 0.0.0.0 --port 9999
```

### The model returns refusals on legitimate scans

BRAHMASTRA 0.3 is alignment-tuned to refuse unauthorized targeting. If you see refusals for a real authorized scan, the `<think>` chain will usually say so. Confirm:

1. The target URL clearly indicates authorized testing context
2. The `system` prompt has not been altered
3. If using cloud AI, the provider's safety classifier may also be intervening (Gemini in particular has its own filter)

---

## Production hardening

### Change default Postgres password

```bash
NEW_PW=$(openssl rand -hex 24)
sudo -u postgres psql -c "ALTER USER brahmastra WITH PASSWORD '$NEW_PW';"
echo "Set this env var when starting the scanner:"
echo "  export BRAHMASTRA_DB_URL='postgresql://brahmastra:$NEW_PW@127.0.0.1:5432/brahmastra'"
```

### Bind only to localhost (or behind a reverse proxy)

By default the scanner binds to `0.0.0.0:8888`. For production, bind to `127.0.0.1` and put nginx / Caddy in front with TLS:

```bash
python3 -m uvicorn server.api:app --host 127.0.0.1 --port 8888
```

Example Caddy config:

```
brahmastra.example.com {
    reverse_proxy 127.0.0.1:8888
}
```

(Caddy auto-issues a Let's Encrypt cert.)

### Add basic auth (or SSO)

Until BRAHMASTRA ships native auth, gate access with the reverse-proxy auth layer (Caddy `basic_auth`, nginx `auth_basic`, or Authelia / Authentik for SSO).

### Restrict cloud-AI key reuse

If your team uses Path A in production, mint a **separate API key per scanner instance** and constrain it:

- **Gemini**: bind the key to the scanner host's IP via the Google Cloud Console
- **Claude / OpenAI**: use a service-account token with a low monthly cap; rotate quarterly

This caps blast radius if the key ever leaks.

### Resource limits

If you share the GPU with other workloads, limit Ollama:

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

## Docker option

The repo ships a `Dockerfile` and `docker-compose.yml`. For Path B (local AI), the Ollama container needs `--gpus all` and nvidia-container-toolkit installed on the host.

```bash
# Install nvidia-container-toolkit
distribution=$(. /etc/os-release; echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/libnvidia-container/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list \
    | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt update && sudo apt install -y nvidia-container-toolkit
sudo systemctl restart docker

# Bring up the stack
cd ~/brahmastra-dast
docker compose up -d
```

This launches three containers:

1. `ollama` (hosts the BRAHMASTRA model with GPU access)
2. `postgres` (scan state)
3. `brahmastra-dast` (FastAPI + dashboard, port 8888)

For **Path A (cloud AI)** with Docker, override the compose to skip the Ollama container:

```bash
docker compose up -d brahmastra-dast postgres
```

Then configure the cloud API key in the dashboard at scan time.

---

## Uninstall

```bash
# Stop services
sudo systemctl stop brahmastra-dast 2>/dev/null
sudo systemctl disable brahmastra-dast 2>/dev/null
sudo rm -f /etc/systemd/system/brahmastra-dast.service

# Path B only: remove the model + Ollama state
ollama rm brahmastra:0.3 2>/dev/null
sudo systemctl stop ollama 2>/dev/null

# Remove the database
sudo -u postgres dropdb brahmastra
sudo -u postgres dropuser brahmastra
sudo systemctl stop postgresql 2>/dev/null

# Remove code, venv, model file
rm -rf ~/brahmastra-dast ~/brahmastra-env
rm -f ~/brahmastra-v3.Q4_K_M.gguf ~/brahmastra-v3-Modelfile
```

To remove Postgres and Ollama themselves (they may be used by other apps):

```bash
sudo apt purge -y postgresql postgresql-contrib
sudo rm -rf /var/lib/postgresql /etc/postgresql
curl -fsSL https://ollama.com/uninstall.sh | sh
```

---

## Quick reference

```bash
# Health check (works for both paths)
curl -s http://localhost:8888/api/health | python3 -m json.tool

# Start everything (Path B has both Ollama and Postgres; Path A only Postgres)
sudo systemctl start postgresql
sudo systemctl start ollama   # Path B only
nohup python3 -m uvicorn server.api:app --host 0.0.0.0 --port 8888 > ~/brahmastra-dast.log 2>&1 &

# Stop the scanner
pkill -f "uvicorn server.api:app"

# Path B: pre-warm the local model
curl -s http://localhost:11434/api/generate \
    -d '{"model":"brahmastra:0.3","prompt":"warm","keep_alive":-1,"stream":false}' > /dev/null

# Path B: unload the local model from VRAM
curl -s http://localhost:11434/api/generate \
    -d '{"model":"brahmastra:0.3","keep_alive":0}' > /dev/null

# Path B: list models in Ollama
ollama list

# Path A: test a Gemini key quickly (replace YOUR_KEY)
curl -s "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=YOUR_KEY" \
    -H 'Content-Type: application/json' \
    -d '{"contents":[{"parts":[{"text":"hi"}]}]}' \
    | head -c 200

# Inspect Postgres state
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra -c '\dt'

# Reset the scan database (DANGEROUS: deletes all scan history)
PGPASSWORD=brahmastra psql -h 127.0.0.1 -U brahmastra -d brahmastra -c 'TRUNCATE scans CASCADE;'
```

---

## Where to go next

- **Run benchmarks**: pull [`Krishnapadala55/brahmastra-benchmark`](https://huggingface.co/datasets/Krishnapadala55/brahmastra-benchmark), replay the 6-suite eval against any backend (local or cloud), compare F1 with the published numbers
- **Customize the rule engine**: drop new detectors into `brahmastra/narayanastra/rules.py`
- **Plug in a custom AI backend**: extend `brahmastra/ai_bridge.py` (see `_call_ollama`, `_call_gemini`, `_call_claude` for examples)
- **File issues, request features, or contribute fixes**: https://github.com/krishnareddypadala/brahmastra-dast/issues

---

**Maintainer**: Krishna Padala
**Repository**: https://github.com/krishnareddypadala/brahmastra-dast
**Model**: https://huggingface.co/Krishnapadala55/brahmastra-0.3
**Last updated**: 2026-06-08
