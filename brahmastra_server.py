"""
Brahmastra Model Server — Ollama-compatible API
Serves the trained LoRA model via POST /api/chat
Drop-in replacement for Ollama for the Brahmastra CLI
"""
import json
import time
import torch
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse
import uvicorn
from peft import PeftModel
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import asyncio

app = FastAPI()

print("Loading Brahmastra model...")

BASE_MODEL = "unsloth/qwen2.5-coder-7b-instruct-bnb-4bit"
LORA_PATH  = "/home/krishna/brahmastra-lora-clean"

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4",
)

tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map="auto",
    torch_dtype=torch.bfloat16,
)
model = PeftModel.from_pretrained(model, LORA_PATH)
model.eval()
print("Brahmastra ready!")

@app.get("/api/tags")
async def list_models():
    return {"models": [{"name": "brahmastra", "model": "brahmastra"}]}

@app.post("/api/chat")
async def chat(request: Request):
    body = await request.json()
    messages = body.get("messages", [])
    stream   = body.get("stream", True)

    text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )
    inputs = tokenizer(text, return_tensors="pt").to("cuda")

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens = body.get("options", {}).get("num_predict", 1024),
            temperature    = body.get("options", {}).get("temperature", 0.7),
            do_sample      = True,
            pad_token_id   = tokenizer.eos_token_id,
        )

    response_text = tokenizer.decode(
        outputs[0][inputs["input_ids"].shape[1]:],
        skip_special_tokens=True
    )

    if stream:
        async def gen():
            # Stream word by word for a better UX
            words = response_text.split(" ")
            for i, word in enumerate(words):
                chunk = word + (" " if i < len(words)-1 else "")
                payload = {
                    "model": "brahmastra",
                    "message": {"role": "assistant", "content": chunk},
                    "done": False
                }
                yield json.dumps(payload) + "\n"
                await asyncio.sleep(0)
            yield json.dumps({"model": "brahmastra", "message": {"role": "assistant", "content": ""}, "done": True}) + "\n"
        return StreamingResponse(gen(), media_type="application/x-ndjson")
    else:
        return JSONResponse({
            "model": "brahmastra",
            "message": {"role": "assistant", "content": response_text},
            "done": True
        })

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=11435)
