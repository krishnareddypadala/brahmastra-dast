"""
BRAHMASTRA 0.2 — Release Status aggregator.

Feeds GET /api/release/status with a single JSON blob describing:
  - HuggingFace repo state (bf16 + GGUF)
  - Ollama backend model + runtime tunables
  - Quantization artifacts on beast
  - Local release artifacts (version, changelog, readme)
  - Beast disk free

Everything that needs to ssh to beast or hit HF is cached for 30 s so
dashboard auto-refresh at 10 s cadence never spams the remote host.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

# ── Config ────────────────────────────────────────────────────────────────────

HF_BF16_REPO     = "Krishnapadala55/brahmastra-0.2"
HF_GGUF_REPO     = "Krishnapadala55/brahmastra-0.2-GGUF"
BF16_TOTAL_BYTES = 65_500_000_000   # ~65.5 GB — used to compute upload percent

BEAST_HOST = os.environ.get("BRAHMASTRA_BEAST_HOST", "beast")
BEAST_SSH  = ["ssh", "-o", "ConnectTimeout=6", "-o", "BatchMode=yes", BEAST_HOST]

# If the API is running ON beast itself, we can skip ssh entirely and run
# commands via the local shell. Detection: the F16 GGUF file is ~62 GB and
# only ever lives on beast. Presence == we are beast.
_ON_BEAST = Path("/home/krishna/brahmastra-32b-f16.gguf").exists() or \
            Path("/home/krishna/brahmastra-merged-32b-bf16").exists()

# Paths we probe on beast. Each quant file may live either at the top level
# (fresh out of llama-quantize) or inside the staging dir (after it has been
# moved there for HF upload). The shell probe checks both and returns the
# max size found.
BEAST_F16_GGUF    = "/home/krishna/brahmastra-32b-f16.gguf"
BEAST_Q4_K_M_GGUF = "/home/krishna/brahmastra-0.2-Q4_K_M.gguf"
BEAST_Q6_K_GGUF   = "/home/krishna/brahmastra-0.2-Q6_K.gguf"
BEAST_Q8_0_GGUF   = "/home/krishna/brahmastra-0.2-Q8_0.gguf"
BEAST_STAGE_DIR   = "/home/krishna/brahmastra-gguf-stage"
BEAST_LORA_GLOB   = "/home/krishna/_archive/brahmastra-lora-phases-*.tar.gz"
BEAST_SCREEN_NAME = "brahmastra-hf-push"

# Local repo artifacts
REPO_ROOT      = Path(__file__).resolve().parent.parent
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"
MODEL_CARD_CANDIDATES = (
    REPO_ROOT / ".release" / "brahmastra-0.2-README.md",        # dev workstation
    Path("/home/krishna/brahmastra-merged-32b-bf16/README.md"), # beast deployed
)
INIT_PY        = REPO_ROOT / "brahmastra" / "__init__.py"

# ── Cache ─────────────────────────────────────────────────────────────────────

_CACHE: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 30.0


def _cached(key: str, ttl: float = _CACHE_TTL):
    """Decorator for async cache helpers."""
    def deco(fn):
        async def wrapped(*args, **kwargs):
            now = time.time()
            hit = _CACHE.get(key)
            if hit and now - hit[0] < ttl:
                return hit[1]
            val = await fn(*args, **kwargs)
            _CACHE[key] = (now, val)
            return val
        return wrapped
    return deco


# ── ssh helpers ──────────────────────────────────────────────────────────────

async def _ssh(cmd: str, timeout: float = 8.0) -> tuple[int, str]:
    """
    Run a command on beast, return (returncode, stdout).

    If the API is running directly on beast, bypass ssh and execute the
    command in the local shell instead — ssh-from-self would fail unless
    the user has explicitly set up loopback key auth, and we have no reason
    to round-trip through the ssh daemon in that case.
    """
    try:
        if _ON_BEAST:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *BEAST_SSH, cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return (-1, "")
        return (proc.returncode or 0, out.decode(errors="replace"))
    except Exception:
        return (-1, "")


# ── HuggingFace probes ───────────────────────────────────────────────────────

def _hf_repo_info(repo_id: str) -> dict[str, Any]:
    """Blocking HF API call — meant to run inside asyncio.to_thread."""
    try:
        from huggingface_hub import HfApi
        api = HfApi()
        info = api.repo_info(repo_id=repo_id, repo_type="model", files_metadata=True)
        siblings = getattr(info, "siblings", []) or []
        total_size = sum((getattr(s, "size", None) or 0) for s in siblings)
        names = sorted((getattr(s, "rfilename", "") or "") for s in siblings)
        shards = [n for n in names if n.startswith("model-") and n.endswith(".safetensors")]
        ggufs  = [n for n in names if n.endswith(".gguf")]
        return {
            "exists": True,
            "file_count": len(names),
            "shard_count": len(shards),
            "gguf_count": len(ggufs),
            "total_bytes": total_size,
            "files": names[:50],  # cap for payload sanity
            "url": f"https://huggingface.co/{repo_id}",
        }
    except Exception as e:
        return {
            "exists": False,
            "error": f"{type(e).__name__}: {e}"[:200],
            "url": f"https://huggingface.co/{repo_id}",
        }


@_cached("hf_bf16")
async def _hf_bf16() -> dict[str, Any]:
    return await asyncio.to_thread(_hf_repo_info, HF_BF16_REPO)


@_cached("hf_gguf")
async def _hf_gguf() -> dict[str, Any]:
    return await asyncio.to_thread(_hf_repo_info, HF_GGUF_REPO)


@_cached("hf_bf16_progress")
async def _hf_bf16_progress() -> dict[str, Any]:
    """
    Scrape the active upload screen session for a live percent.
    Returns 100% if the screen is gone (upload finished) and the HF repo has
    all 13 shards. Returns 0% if screen missing AND repo incomplete.
    """
    rc, out = await _ssh(
        f"screen -S {BEAST_SCREEN_NAME} -X hardcopy /tmp/brahmastra-screen-dump.txt "
        f"2>/dev/null && sleep 0.3 && cat /tmp/brahmastra-screen-dump.txt 2>/dev/null"
    )
    # Parse "Processing Files (n / m)      :  XX%|...| A.BGB / C.DGB, E.FMB/s"
    dump = out or ""
    live = False
    percent = None
    uploaded_gb = None
    total_gb = None
    rate_mb_s = None

    # First find the "Processing Files" master line
    m = re.search(
        r"Processing Files.*?:\s*(\d+)%.*?([\d.]+)\s*GB\s*/\s*([\d.]+)\s*GB.*?([\d.]+)\s*MB/s",
        dump,
    )
    if m:
        live = True
        percent = int(m.group(1))
        uploaded_gb = float(m.group(2))
        total_gb = float(m.group(3))
        rate_mb_s = float(m.group(4))

    # Check screen liveness separately
    rc2, out2 = await _ssh(f"screen -ls | grep -c {BEAST_SCREEN_NAME}")
    screen_alive = (rc2 == 0 and out2.strip().isdigit() and int(out2.strip()) > 0)

    # Detect success line in the dump
    completed = "[OK] upload complete" in dump and "[OK] live at:" in dump

    return {
        "live": live,
        "screen_alive": screen_alive,
        "completed": completed,
        "percent": percent if percent is not None else (100 if completed else None),
        "uploaded_gb": uploaded_gb,
        "total_gb": total_gb,
        "rate_mb_s": rate_mb_s,
    }


# ── Ollama probes ────────────────────────────────────────────────────────────

@_cached("ollama")
async def _ollama_state() -> dict[str, Any]:
    """
    Query Ollama for:
      - list of brahmastra:* tags + their digests + sizes
      - ollama ps for GPU/CPU split
    Also reads /etc/systemd/system/ollama.service.d/override.conf to confirm
    the runtime env overrides are active.
    """
    out = {}

    # Tags via HTTP (lighter than `ollama list`)
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get("http://127.0.0.1:11434/api/tags")
        if r.status_code == 200:
            models = r.json().get("models", [])
            brahma = [m for m in models if str(m.get("name", "")).startswith("brahmastra")]
            out["tags"] = [
                {
                    "name": m.get("name", ""),
                    "size_bytes": m.get("size", 0),
                    "digest": (m.get("digest", "") or "")[:12],
                    "modified_at": m.get("modified_at", ""),
                    "param_size": (m.get("details", {}) or {}).get("parameter_size", ""),
                    "quant": (m.get("details", {}) or {}).get("quantization_level", ""),
                }
                for m in brahma
            ]
        else:
            out["tags"] = []
    except Exception as e:
        out["tags"] = []
        out["tags_error"] = f"{type(e).__name__}: {e}"[:200]

    # ps for GPU%
    rc, ps_out = await _ssh("ollama ps 2>&1 | head -20", timeout=5.0)
    out["ps_raw"] = ps_out.strip() if rc == 0 else ""
    # Parse "100% GPU" or "74%/26% CPU/GPU" pattern
    mps = re.search(r"(\d+)%\s*GPU", ps_out or "")
    out["gpu_percent"] = int(mps.group(1)) if mps else None

    # Systemd env overrides
    rc3, env_out = await _ssh(
        "cat /etc/systemd/system/ollama.service.d/override.conf 2>/dev/null",
        timeout=4.0,
    )
    env_txt = env_out or ""
    out["flash_attention"] = "OLLAMA_FLASH_ATTENTION=1" in env_txt
    out["kv_cache_type"]   = "q8_0" if "OLLAMA_KV_CACHE_TYPE=q8_0" in env_txt else ""
    out["keep_alive"]      = "-1" if "OLLAMA_KEEP_ALIVE=-1" in env_txt else ""
    out["num_parallel"]    = 1 if "OLLAMA_NUM_PARALLEL=1" in env_txt else None

    # Heuristic: identify the CURRENT brahmastra tag and whether it looks fine-tuned
    active_name = ""
    is_fine_tuned = False
    if out["tags"]:
        # Prefer an explicit :0.2, then :p6
        preferred = sorted(
            out["tags"],
            key=lambda t: (
                0 if t["name"].endswith(":0.2") else
                1 if t["name"].endswith(":p6") else 2,
                -t.get("size_bytes", 0),
            ),
        )[0]
        active_name = preferred["name"]
        # Stock deepseek-r1 Q4_K_M digest sha prefix is well-known; any mismatch = fine-tune
        # We use the digest of the current tag vs the stock tag if both exist.
        stock_digest = ""
        rc4, stock_out = await _ssh(
            "ollama list 2>/dev/null | grep deepseek-r1:32b-qwen-distill-q4_K_M | awk '{print $3}'",
            timeout=4.0,
        )
        stock_digest = (stock_out or "").strip()[:12]
        if stock_digest and preferred["digest"] and stock_digest != preferred["digest"]:
            is_fine_tuned = True
        elif stock_digest == "" and preferred["digest"]:
            # no stock tag present — assume fine-tuned
            is_fine_tuned = True
    out["active_tag"] = active_name
    out["is_fine_tuned"] = is_fine_tuned

    return out


# ── Beast disk + quant artifacts ─────────────────────────────────────────────

@_cached("beast")
async def _beast_state() -> dict[str, Any]:
    # One multiplexed ssh call — cheaper than 5 separate ones.
    # Each section uses a tag line and an end-tag line so empty values
    # never get confused with the next section's tag.
    # For each quant file, stat both the top-level path and the staging-dir
    # path and pick whichever is larger (so the file "counts" whether it's
    # pre- or post-staging).
    def _both(name: str) -> str:
        top = f"/home/krishna/{name}"
        stg = f"{BEAST_STAGE_DIR}/{name}"
        return (
            f"a=$(stat -c '%s' {top} 2>/dev/null || echo 0); "
            f"b=$(stat -c '%s' {stg} 2>/dev/null || echo 0); "
            f"[ $a -gt $b ] && echo $a || echo $b"
        )
    script = (
        "echo DISK_S; df -BG /home | tail -1; echo DISK_E; "
        f"echo F16_S; stat -c '%s' {BEAST_F16_GGUF} 2>/dev/null || echo 0; echo F16_E; "
        f"echo Q4_S; " + _both("brahmastra-0.2-Q4_K_M.gguf") + "; echo Q4_E; "
        f"echo Q6_S; " + _both("brahmastra-0.2-Q6_K.gguf")   + "; echo Q6_E; "
        f"echo Q8_S; " + _both("brahmastra-0.2-Q8_0.gguf")   + "; echo Q8_E; "
        f"echo LORA_S; ls -1 {BEAST_LORA_GLOB} 2>/dev/null | head -1 ; echo LORA_E; "
        "echo SCREEN_S; screen -ls 2>/dev/null | grep -E 'brahmastra-(hf-push|llama-build|quant|gguf-push)' ; echo SCREEN_E"
    )
    rc, out = await _ssh(script, timeout=10.0)
    data: dict[str, Any] = {
        "reachable": rc == 0,
        "disk_free_gb": None,
        "disk_used_gb": None,
        "f16_bytes": 0,
        "q4_k_m_bytes": 0,
        "q6_k_bytes": 0,
        "q8_0_bytes": 0,
        "lora_archive": "",
        "screens": [],
    }
    if rc != 0:
        return data

    # Split output into sections keyed by tag name (between _S and _E markers)
    sections: dict[str, list[str]] = {}
    lines = (out or "").splitlines()
    cur_key = None
    cur_buf: list[str] = []
    for ln in lines:
        s = ln.strip()
        if s.endswith("_S") and not s.endswith("__S"):
            cur_key = s[:-2]
            cur_buf = []
        elif s.endswith("_E") and cur_key and s[:-2] == cur_key:
            sections[cur_key] = cur_buf
            cur_key = None
            cur_buf = []
        elif cur_key is not None:
            cur_buf.append(ln)

    # DISK
    if sections.get("DISK"):
        m = re.match(r"\S+\s+(\d+)G\s+(\d+)G\s+(\d+)G", sections["DISK"][0])
        if m:
            data["disk_used_gb"] = int(m.group(2))
            data["disk_free_gb"] = int(m.group(3))

    # File sizes
    def _num(section_name: str) -> int:
        body = sections.get(section_name) or []
        if not body:
            return 0
        try:
            return int(body[0].strip())
        except ValueError:
            return 0
    data["f16_bytes"]    = _num("F16")
    data["q4_k_m_bytes"] = _num("Q4")
    data["q6_k_bytes"]   = _num("Q6")
    data["q8_0_bytes"]   = _num("Q8")

    # LoRA archive — first non-empty line, or ''
    lora_lines = [ln.strip() for ln in (sections.get("LORA") or []) if ln.strip()]
    data["lora_archive"] = lora_lines[0] if lora_lines else ""

    # Active screens
    for ln in (sections.get("SCREEN") or []):
        ms = re.search(r"(\d+)\.(brahmastra-\S+)", ln)
        if ms:
            data["screens"].append({"pid": ms.group(1), "name": ms.group(2)})

    return data


# ── Local release artifacts ─────────────────────────────────────────────────

def _local_state() -> dict[str, Any]:
    version = "unknown"
    try:
        txt = INIT_PY.read_text(encoding="utf-8")
        m = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", txt)
        if m:
            version = m.group(1)
    except Exception:
        pass
    return {
        "version": version,
        "changelog_present": CHANGELOG_PATH.is_file(),
        "model_card_present": any(p.is_file() for p in MODEL_CARD_CANDIDATES),
    }


# ── Public entry point ──────────────────────────────────────────────────────

async def get_release_status() -> dict[str, Any]:
    """
    Aggregate everything the Release Status page needs.
    Runs all four remote probes concurrently.
    """
    hf_bf16_info, hf_bf16_progress, hf_gguf_info, ollama, beast = await asyncio.gather(
        _hf_bf16(),
        _hf_bf16_progress(),
        _hf_gguf(),
        _ollama_state(),
        _beast_state(),
    )

    # Derive a clean "upload" block for the dashboard.
    # HF metadata is empty during an active upload (files are only committed
    # on success), so prefer the live screen-scrape numbers and fall back to
    # HF metadata only when the upload has actually landed.
    live_uploaded_bytes = None
    if hf_bf16_progress.get("uploaded_gb") is not None:
        live_uploaded_bytes = int(hf_bf16_progress["uploaded_gb"] * (1024 ** 3))
    hf_total_bytes = hf_bf16_info.get("total_bytes") or 0
    uploaded_bytes = live_uploaded_bytes if live_uploaded_bytes else hf_total_bytes
    percent_by_bytes = (uploaded_bytes / BF16_TOTAL_BYTES) * 100 if uploaded_bytes else 0
    bf16_percent = hf_bf16_progress.get("percent")
    if bf16_percent is None:
        bf16_percent = round(percent_by_bytes)

    return {
        "generated_at": time.time(),
        "hf": {
            "bf16": {
                **hf_bf16_info,
                "percent": bf16_percent,
                "uploaded_bytes": uploaded_bytes,
                "expected_bytes": BF16_TOTAL_BYTES,
                "live": hf_bf16_progress.get("live", False),
                "screen_alive": hf_bf16_progress.get("screen_alive", False),
                "completed": hf_bf16_progress.get("completed", False),
                "rate_mb_s": hf_bf16_progress.get("rate_mb_s"),
            },
            "gguf": hf_gguf_info,
        },
        "ollama": ollama,
        "beast": beast,
        "release": _local_state(),
    }
