#!/usr/bin/env python3
"""analyze_brief.py - send a capture brief to a local Ollama model, print response + timing.

Usage: python3 analyze_brief.py <brief_file> <model> [max_tokens]
"""
import json, sys, urllib.request

PROMPT_PREFIX = (
    "You are a WiFi capture analyst reviewing a 60-second passive 802.11 capture "
    "from a residential apartment complex. Frame subtype codes: 0x0008=beacon, "
    "0x0005=probe response, 0x0004=probe request, 0x0020/0x0028/0x002c/0x0024=data, "
    "0x000d=action, 0x000c=deauth. Give: (1) one-paragraph environment summary, "
    "(2) anything anomalous and why, (3) one recommended next capture. "
    "Be concise and specific.\n\n"
)

def main():
    brief_file = sys.argv[1]
    model = sys.argv[2]
    max_tokens = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    num_thread = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    brief = open(brief_file).read()
    options = {"num_predict": max_tokens}
    if num_thread > 0:
        # Thread cap for thermally/power-constrained SBCs (full-core 4B load
        # brownout-crashed an Indiedroid Nova twice; 4 threads ran stable).
        options["num_thread"] = num_thread
    payload = {
        "model": model,
        "prompt": PROMPT_PREFIX + brief,
        "stream": False,
        "think": False,
        "options": options,
    }
    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=900) as resp:
        r = json.load(resp)
    print(r.get("response", ""))
    print("---")
    print(f"model={model} eval_tokens={r.get('eval_count')} "
          f"eval_s={r.get('eval_duration',0)/1e9:.1f} total_s={r.get('total_duration',0)/1e9:.1f}")

if __name__ == "__main__":
    main()
