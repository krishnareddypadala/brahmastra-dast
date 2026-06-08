#!/usr/bin/env bash
# BRAHMASTRA DAST - Path B installer (Local AI with BRAHMASTRA 0.3, GPU required)
#
# Runs scripts/install.sh first to set up the scanner core, then adds:
#   - Ollama runtime
#   - BRAHMASTRA 0.3 GGUF model downloaded from Hugging Face (~19 GB)
#   - Modelfile registration in Ollama
#   - VRAM pre-warm
#
# Result: fully on-prem DAST scanner with $0 per-scan cost. No data leaves
# your machine.
#
# Requirements:
#   - NVIDIA GPU with 24 GB+ VRAM (RTX 3090 / 4090 / A5000 / 5090 / PRO 5000)
#   - NVIDIA driver installed and `nvidia-smi` working
#   - ~40 GB free disk
#   - 1+ GB / sec network for the HF download (or be patient)
#
# Time to first scan: ~60 to 90 minutes (mostly the 19 GB model download).
#
# Usage:
#   ./scripts/install-local.sh
#
# Safe to re-run: skips steps already done.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HF_REPO="${HF_REPO:-Krishnapadala55/brahmastra-0.3-GGUF}"
GGUF_FILE="${GGUF_FILE:-brahmastra-v3.Q4_K_M.gguf}"
GGUF_PATH="${GGUF_PATH:-$HOME/brahmastra-v3.Q4_K_M.gguf}"
MODELFILE_PATH="${MODELFILE_PATH:-$HOME/brahmastra-v3-Modelfile}"
OLLAMA_MODEL_TAG="${OLLAMA_MODEL_TAG:-brahmastra:0.3}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/brahmastra-dast}"

green() { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
red() { printf "\033[31m%s\033[0m\n" "$*"; }
step() { printf "\n\033[1;34m==> %s\033[0m\n" "$*"; }

# ---------------------------------------------------------------------------
# 1. Pre-flight
# ---------------------------------------------------------------------------
step "Pre-flight: GPU + VRAM check"
if ! command -v nvidia-smi >/dev/null 2>&1; then
    red "nvidia-smi not found. Install the NVIDIA driver first:"
    red "  Ubuntu: sudo apt install nvidia-driver-575"
    red "  WSL2:   install NVIDIA Studio Driver on the Windows host"
    red ""
    red "If you do not have a GPU, run ./scripts/install.sh instead (cloud AI path)."
    exit 1
fi

VRAM_MB=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)
GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)
green "GPU: ${GPU_NAME} (${VRAM_MB} MiB VRAM)"

if [[ "${VRAM_MB}" -lt 22000 ]]; then
    red "BRAHMASTRA 0.3 Q4_K_M needs ~22 GB free VRAM. You have ${VRAM_MB} MiB."
    red "Options:"
    red "  1. Free other GPU consumers (close apps, kill processes)"
    red "  2. Use cloud AI instead: ./scripts/install.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Run the base installer (scanner core)
# ---------------------------------------------------------------------------
step "Running base installer (Path A)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "${SCRIPT_DIR}/install.sh"

# ---------------------------------------------------------------------------
# 3. Install Ollama
# ---------------------------------------------------------------------------
step "Installing Ollama"
if command -v ollama >/dev/null 2>&1; then
    green "Ollama already installed: $(ollama --version 2>/dev/null || echo unknown)"
else
    curl -fsSL https://ollama.com/install.sh | sh
fi
sudo systemctl enable --now ollama
sleep 2
if ! curl -s -m 5 http://localhost:11434/api/tags >/dev/null; then
    red "Ollama daemon is not reachable on port 11434."
    red "Check: systemctl status ollama"
    exit 1
fi
green "Ollama daemon is up."

# ---------------------------------------------------------------------------
# 4. Download GGUF from Hugging Face
# ---------------------------------------------------------------------------
step "Downloading BRAHMASTRA 0.3 GGUF (~19 GB) from Hugging Face"
if [[ -f "${GGUF_PATH}" ]] && [[ "$(stat -c%s "${GGUF_PATH}")" -gt 18000000000 ]]; then
    green "GGUF already at ${GGUF_PATH} ($(du -h "${GGUF_PATH}" | cut -f1)). Skipping download."
else
    if ! command -v huggingface-cli >/dev/null 2>&1; then
        pip install --user --quiet huggingface_hub
    fi
    HF_CLI="$(command -v huggingface-cli || echo "$HOME/.local/bin/huggingface-cli")"
    yellow "Downloading from ${HF_REPO}/${GGUF_FILE} ..."
    yellow "(This is ~19 GB. Time depends on bandwidth.)"
    "${HF_CLI}" download "${HF_REPO}" "${GGUF_FILE}" \
        --local-dir "$(dirname "${GGUF_PATH}")"
    green "Downloaded: ${GGUF_PATH} ($(du -h "${GGUF_PATH}" | cut -f1))"
fi

# ---------------------------------------------------------------------------
# 5. Create Modelfile
# ---------------------------------------------------------------------------
step "Writing Modelfile"
cat > "${MODELFILE_PATH}" <<EOF
FROM ${GGUF_PATH}
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
green "Modelfile at: ${MODELFILE_PATH}"

# ---------------------------------------------------------------------------
# 6. Register the model in Ollama
# ---------------------------------------------------------------------------
step "Registering ${OLLAMA_MODEL_TAG} in Ollama"
if ollama list 2>/dev/null | awk '{print $1}' | grep -qx "${OLLAMA_MODEL_TAG}"; then
    yellow "${OLLAMA_MODEL_TAG} already registered. Skipping (delete with: ollama rm ${OLLAMA_MODEL_TAG})"
else
    ollama create "${OLLAMA_MODEL_TAG}" -f "${MODELFILE_PATH}"
    green "Model registered."
fi

# ---------------------------------------------------------------------------
# 7. Pre-warm into VRAM
# ---------------------------------------------------------------------------
step "Pre-warming model in VRAM (loads ~20 GB, takes ~15 seconds)"
RESP=$(curl -s -m 60 http://localhost:11434/api/generate \
    -d "{\"model\":\"${OLLAMA_MODEL_TAG}\",\"prompt\":\"Say BRAHMASTRA is ready in 5 words\",\"keep_alive\":-1,\"stream\":false}" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("response","")[:80])' 2>/dev/null || echo "")
if [[ -n "${RESP}" ]]; then
    green "Model response: ${RESP}"
else
    red "Pre-warm failed. Check Ollama logs: journalctl -u ollama --no-pager -n 50"
    exit 1
fi

VRAM_USED=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | head -1)
green "VRAM in use: ${VRAM_USED} MiB (expected ~20000)"

# ---------------------------------------------------------------------------
# 8. Health check via the DAST server
# ---------------------------------------------------------------------------
step "Verifying scanner can reach the model"
sleep 2
HEALTH=$(curl -s -m 10 http://localhost:8888/api/health | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("backends",{}).get("brahmastra",{}).get("online", False))' 2>/dev/null || echo "false")
if [[ "${HEALTH}" == "True" ]]; then
    green "Scanner sees brahmastra:0.3 as ONLINE."
else
    yellow "Scanner does not see brahmastra:0.3 yet. Try restarting the scanner:"
    yellow "  pkill -f 'uvicorn server.api:app'"
    yellow "  ${INSTALL_DIR}/scripts/install.sh    # re-runs the launch step"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
green ""
green "================================================================"
green "  BRAHMASTRA 0.3 + DAST scanner are running locally."
green "    Dashboard:   http://localhost:8888"
green "    AI Mode:     'BRAHMASTRA 0.3 (32B, cleaned + DAST synth)'"
green "    Cost / scan: \$0   |   Data leaves your machine: never"
green ""
green "  Next steps:"
green "    1. Open the dashboard in your browser."
green "    2. AI Mode should default to 'BRAHMASTRA 0.3' (no key needed)."
green "    3. Enter a target URL and click Launch Scan."
green ""
green "  Cloud AI is still available as a fallback (Gemini / Claude / OpenAI)."
green "  Pick per-scan from the dropdown."
green ""
green "  Stop:                  pkill -f 'uvicorn server.api:app'"
green "  Unload model from VRAM: curl http://localhost:11434/api/generate \\"
green "                             -d '{\"model\":\"${OLLAMA_MODEL_TAG}\",\"keep_alive\":0}'"
green "  Full docs:              ${INSTALL_DIR}/SETUP.md"
green "================================================================"
