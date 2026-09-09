#!/usr/bin/env python3
"""analyze_brief.py - send a capture brief to a local Ollama model, print response + timing.

Usage: python3 analyze_brief.py <brief_file> <model> [max_tokens] [num_threads]
"""
import argparse, json, urllib.request

PROMPT_PREFIX = (
    "You are a WiFi capture analyst reviewing the evidence in an 802.11 capture brief. "
    "Do not infer a location, deployment type, capture duration, or collection method "
    "unless the brief states it. Separate observations from possible explanations and "
    "say when the evidence is insufficient. Frame subtype codes: 0x0008=beacon, "
    "0x0005=probe response, 0x0004=probe request, 0x0020/0x0028/0x002c/0x0024=data, "
    "0x000d=action, 0x000c=deauth. Give: (1) one-paragraph environment summary, "
    "(2) anything anomalous and why, (3) one recommended next passive capture. "
    "Be concise and specific.\n\n"
)

def nonnegative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def parse_args():
    parser = argparse.ArgumentParser(
        description="Send a deterministic capture brief to a local Ollama model."
    )
    parser.add_argument("brief_file")
    parser.add_argument("model")
    parser.add_argument("max_tokens", nargs="?", default=400, type=positive_int)
    parser.add_argument(
        "num_threads",
        nargs="?",
        default=0,
        type=nonnegative_int,
        help="Ollama thread cap; 0 leaves the model default unchanged",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    brief_file = args.brief_file
    model = args.model
    max_tokens = args.max_tokens
    num_thread = args.num_threads
    brief = open(brief_file).read()
    options = {"num_predict": max_tokens}
    if num_thread > 0:
        # Thread cap for thermally/power-constrained SBCs. Full-core 4B load
        # crashed the tested Nova; two threads completed the documented runs.
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
