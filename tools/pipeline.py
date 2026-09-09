#!/usr/bin/env python3
"""pipeline.py - capture -> summarize -> analyze, one command.

Runs on the X1S with the Marauder on /dev/ttyUSB0.
Usage: python3 pipeline.py <beacon|probe|raw> <seconds> [model] [max_tokens]
Example: python3 pipeline.py raw 60 qwen3:4b-instruct 400
"""
import sys, os, subprocess, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
# Run artifacts (raw PCAPs with third-party MACs/SSIDs) live OUTSIDE the repo
# tree by default, matching render_dashboard.py's --runs-dir default.
OUT = os.environ.get("PIPELINE_RUNS_DIR",
                     os.path.expanduser("~/marauder-analyst/pipeline_runs"))

def run(cmd, **kw):
    print(f"$ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, **kw)

def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else "raw"
    seconds = sys.argv[2] if len(sys.argv) > 2 else "60"
    model = sys.argv[3] if len(sys.argv) > 3 else "qwen3:4b-instruct"
    max_tokens = sys.argv[4] if len(sys.argv) > 4 else "400"

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    rundir = os.path.join(OUT, f"{kind}_{ts}")
    os.makedirs(rundir, exist_ok=True)

    # 1. stream capture from Marauder
    r = run(["python3", os.path.join(HERE, "marauder.py"), "stream", kind, seconds],
            capture_output=True, text=True)
    print(r.stdout)
    if r.returncode != 0 or "saved" not in r.stdout:
        print("[!] capture failed"); sys.exit(1)
    pcap = [l.split("saved ")[1].split(" (")[0]
            for l in r.stdout.splitlines() if "[+] saved" in l][0]
    run(["cp", pcap, rundir + "/"])

    # 2. deterministic brief
    brief_path = os.path.join(rundir, "brief.txt")
    with open(brief_path, "w") as fh:
        r = run(["python3", os.path.join(HERE, "summarize_pcap.py"), pcap],
                stdout=fh, text=True)
    if r.returncode != 0:
        print("[!] summarizer failed"); sys.exit(1)
    print(open(brief_path).read())

    # 3. local model analysis
    analysis_path = os.path.join(rundir, "analysis.txt")
    with open(analysis_path, "w") as fh:
        r = run(["python3", os.path.join(HERE, "analyze_brief.py"),
                 brief_path, model, max_tokens], stdout=fh, text=True)
    if r.returncode != 0:
        print("[!] analysis failed"); sys.exit(1)
    print(open(analysis_path).read())

    # 4. reconcile model claims against the data (PROBE layer)
    verify_path = os.path.join(rundir, "verification.txt")
    with open(verify_path, "w") as fh:
        r = run(["python3", os.path.join(HERE, "verify_claims.py"),
                 brief_path, analysis_path], stdout=fh, text=True)
    print(open(verify_path).read())
    if r.returncode != 0:
        print("[!] RECONCILIATION FAILED: model claims contradict the data. See verification.txt")
        sys.exit(2)
    print(f"[+] run artifacts in {rundir}")

if __name__ == "__main__":
    main()
