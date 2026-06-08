# Changelog

All notable changes to BRAHMASTRA are documented in this file.

## 0.2.0 — 2026-04-11

Second major release. Full base-model upgrade from 7B → 32B, 6-phase LoRA
training curriculum, live multi-scan dashboard with SSE replay, AI-native
evidence-driven crawl planner, per-scan operator chat, and PostgreSQL
backend.

### Model

- **Base upgrade**: Qwen2.5-Coder-7B-Instruct → DeepSeek-R1-Distill-Qwen-32B
- **6-phase LoRA training** (p1a, p1b, p1c, p2, p3, p4, p5, p6) on ~136k
  security samples: SQLi/XSS fundamentals, SSTI/SSRF, IDOR/authn bypass,
  multi-step attack chains, WAF bypass, deserialization/crypto/race,
  business-logic/API/GraphQL, reasoning consolidation.
- **Explicit `<think>` reasoning traces** inherited from the DeepSeek-R1
  distillation — the model shows its work before the final payload.
- **Published to HuggingFace**:
  - `Krishnapadala55/brahmastra-0.2` (bf16 safetensors, 61 GB, 13 shards)
  - `Krishnapadala55/brahmastra-0.2-GGUF` (Q4_K_M + Q6_K + Q8_0 variants)

### Scanner

- **AI-native evidence-driven spider** — Garudastra crawl planner uses the
  real-time crawl state to direct the AI strategist toward the highest-value
  unprobed paths, parameters, and request shapes.
- **Per-scan operator chat** — a full chat tab inside each scan with
  structured action buttons (probe a rule, re-crawl a path, widen/narrow
  scope). Backed by `save_chat_message` / `get_chat_history` in the DB so
  history persists across reconnects.
- **AI Strategist panel reset** — previously the strategist rules/URLs would
  leak across scan switches in the dashboard; now `resetLiveState()` wipes
  the panel cleanly whenever a different scan is selected.
- **NUL-byte scrubber** in the event emit pipeline — fixes Postgres `JSONB`
  write rejections when a probe response contains raw `\x00` bytes.
- **Concurrent multi-scan support** — the PostgreSQL + asyncpg backend
  removes the SQLite single-writer lock so multiple scans run truly in
  parallel with no lock-stall.

### Dashboard

- **New Release Status tab** — live rollup of HuggingFace upload progress
  (bf16 + GGUF), Ollama backend model state, quantization artifacts on
  beast, beast disk free, and local release artifacts (version, changelog,
  model card). Auto-refreshes every 10 s via `/api/release/status`.
- **Chat tab** — per-scan AI conversation with `<think>` rendering and
  action-button follow-ups.
- **Backend-badge in scan header** — shows which AI backend each scan is
  using (brahmastra / gemini_flash / claude_haiku / etc.).

### Infrastructure

- **Ollama Q4_K_M quantization** — 20 GB on-disk, 100% GPU offload on a
  48 GB card, 5–15× prefill speedup vs the earlier F16 CPU-offloaded setup.
- **systemd env overrides** at
  `/etc/systemd/system/ollama.service.d/override.conf`:
  `OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0`,
  `OLLAMA_KEEP_ALIVE=-1`, `OLLAMA_NUM_PARALLEL=1`.
- **HF publish script** (`.release/push_0.2.py`) with strict env-var token
  handling — the token is read from `HF_TOKEN` only and never hardcoded.

### Fixes

- AI Strategist panel leaking rules/URLs across scan switches (dashboard
  state leak).
- Empty chat-reply fallback — when the AI backend times out or emits
  unparseable JSON, the user now sees an actionable error message instead
  of the literal string `(no reply)`.
- Orphan scan recovery on API restart — scans with `status='running'` at
  startup are marked `failed` with a clear `Server restarted` error.

### Internal

- `server/release_status.py` — new aggregator module for the Release tab
  (HF probes, Ollama probes, beast ssh probes, local artifacts). All
  remote calls cached for 30 s.
- `server/db.py` — async asyncpg pool, JSONB codecs, single-query
  `list_scans()` (no N+1), cascaded `DELETE FROM scans`.
- `server/api.py` — `version="0.2.0"`, new `/api/release/status` endpoint.

---

## 0.1.0 — initial release

- 7B Qwen2.5-Coder-Instruct base, 5-phase LoRA
- SQLite persistence, single-scan dashboard
- 28 Astra modules (Naagastra through Garudastra)
