#!/usr/bin/env python3
"""render_dashboard.py - static HTML dashboard for marauder-analyst pipeline runs.

Scans a pipeline_runs/ directory, extracts key facts from each run's
brief.txt / analysis.txt / verification.txt, and writes a single
self-contained dashboard.html. Stdlib only, safe on the X1S.

Usage:
    python3 render_dashboard.py [--runs-dir ~/marauder-analyst/pipeline_runs]
                                [--out ~/marauder-analyst/dashboard.html]
"""
import argparse
import html
import os
import re
import sys
from datetime import datetime
from pathlib import Path


def parse_brief(text):
    facts = {}
    m = re.search(r"^Frames:\s*(\d+)", text, re.M)
    if m:
        facts["frames"] = int(m.group(1))
    m = re.search(r"^Unique APs \(by BSSID\):\s*(\d+)", text, re.M)
    if m:
        facts["aps"] = int(m.group(1))
    m = re.search(r"^Devices sending probe requests:\s*(\d+)", text, re.M)
    if m:
        facts["probers"] = int(m.group(1))
    m = re.search(r"^Deauth/disassoc frames:\s*(\d+)", text, re.M)
    if m:
        facts["deauths"] = int(m.group(1))
    m = re.search(r"^Frame mix:\s*(.+)$", text, re.M)
    if m:
        facts["frame_mix"] = m.group(1).strip()
    return facts


def parse_analysis(text):
    info = {}
    m = re.search(r"model=(\S+)\s+eval_tokens=(\d+)\s+eval_s=([\d.]+)\s+total_s=([\d.]+)", text)
    if m:
        info["model"] = m.group(1)
        info["eval_tokens"] = int(m.group(2))
        info["eval_s"] = float(m.group(3))
        info["total_s"] = float(m.group(4))
        body = text[: m.start()].strip()
    else:
        body = text.strip()
    # first 600 chars as excerpt, cut at word boundary
    excerpt = body[:600]
    if len(body) > 600:
        excerpt = excerpt.rsplit(" ", 1)[0] + " ..."
    info["excerpt"] = excerpt
    return info


def parse_verification(text):
    # matches verify_claims.py output vocabulary
    low = text.lower()
    if "failed reconciliation" in low or "[-]" in text or "fail" in low:
        return "FAIL"
    if "all quantitative claims reconcile" in low or "pass" in low:
        return "PASS"
    return "UNKNOWN"


def parse_wardrive_brief(text):
    """Parse a wardrive_summarize.py brief for dashboard display."""
    facts = {}
    m = re.search(r"Total sightings:\s*(\d+)\s*\((\d+)\s*WiFi,\s*(\d+)\s*BLE", text)
    if m:
        facts["sightings"] = f"{int(m.group(1)):,} ({m.group(2)} WiFi / {m.group(3)} BLE)"
    m = re.search(r"Unique devices:\s*(\d+)\s*WiFi APs,\s*(\d+)\s*BLE", text)
    if m:
        facts["unique_aps"] = int(m.group(1))
        facts["unique_ble"] = int(m.group(2))
    m = re.search(r"\(hidden\):\s*(\d+)", text)
    if m:
        facts["hidden"] = int(m.group(1))
    auth = re.findall(r"^\s{2}(WPA2_PSK|WPA3_PSK|OPEN|WPA_WPA2_PSK|WPA2_WPA3_PSK):\s*(\d+)$", text, re.M)
    if auth:
        facts["auth_mix"] = ", ".join(f"{k} {v}" for k, v in auth)
    windows = re.findall(r"(\[run_\d+\][^\n]+UTC)", text)
    if windows:
        facts["windows"] = windows
    return facts


def collect_runs(runs_dir):
    runs = []
    for d in sorted(Path(runs_dir).iterdir()):
        if not d.is_dir():
            continue
        run = {"name": d.name, "mtime": d.stat().st_mtime}
        brief = d / "brief.txt"
        if brief.exists():
            run["brief"] = parse_brief(brief.read_text(errors="replace"))
        wbrief = d / "wardrive_brief.txt"
        if wbrief.exists():
            run["type"] = "wardrive"
            run["wbrief"] = parse_wardrive_brief(wbrief.read_text(errors="replace"))
            maps = list(d.glob("*.png"))
            if maps:
                run["map"] = Path(runs_dir).name + "/" + d.name + "/" + maps[0].name
        analysis = d / "analysis.txt"
        if analysis.exists():
            run["analysis"] = parse_analysis(analysis.read_text(errors="replace"))
        else:
            wans = sorted(d.glob("wardrive_llm_*.txt"))
            if wans:
                run["analysis"] = parse_analysis(wans[0].read_text(errors="replace"))
        ver = d / "verification.txt"
        if ver.exists():
            vtext = ver.read_text(errors="replace")
            run["verification"] = parse_verification(vtext)
            run["verification_text"] = vtext.strip()
        pcaps = list(d.glob("*.pcap"))
        if pcaps:
            run["pcap"] = {"name": pcaps[0].name, "size": pcaps[0].stat().st_size}
        runs.append(run)
    runs.sort(key=lambda r: r["mtime"], reverse=True)
    return runs


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Marauder Analyst - Run Dashboard</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#c9d1d9; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
         margin:0; padding:24px; }}
  h1 {{ font-size:20px; color:#58a6ff; margin:0 0 4px; }}
  .sub {{ color:#8b949e; font-size:12px; margin-bottom:24px; }}
  .run {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
          padding:16px; margin-bottom:16px; }}
  .run h2 {{ font-size:15px; margin:0 0 8px; color:#e6edf3; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px;
            font-weight:bold; margin-left:8px; vertical-align:middle; }}
  .pass {{ background:#1a7f37; color:#fff; }}
  .fail {{ background:#cf222e; color:#fff; }}
  .unknown {{ background:#9e6a03; color:#fff; }}
  .nover {{ background:#30363d; color:#8b949e; }}
  .ward {{ background:#6e40c9; color:#fff; }}
  img.map {{ max-width:340px; border:1px solid #30363d; border-radius:6px; margin-top:8px; }}
  table {{ border-collapse:collapse; margin:8px 0; font-size:13px; }}
  td {{ padding:3px 14px 3px 0; color:#8b949e; }}
  td.v {{ color:#c9d1d9; }}
  details {{ margin-top:8px; }}
  summary {{ cursor:pointer; color:#58a6ff; font-size:13px; }}
  pre {{ background:#0d1117; border:1px solid #30363d; border-radius:6px;
         padding:12px; font-size:12px; white-space:pre-wrap; word-break:break-word; }}
</style>
</head>
<body>
<h1>Marauder Analyst - Run Dashboard</h1>
<div class="sub">Generated {generated} &middot; {count} run(s) &middot; {runs_dir}</div>
{body}
</body>
</html>
"""

RUN_TMPL = """<div class="run">
  <h2>{name}{badge}</h2>
  <table>
    <tr><td>time</td><td class="v">{time}</td></tr>
    <tr><td>pcap</td><td class="v">{pcap}</td></tr>
    <tr><td>frames</td><td class="v">{frames}</td></tr>
    <tr><td>unique APs</td><td class="v">{aps}</td></tr>
    <tr><td>probe devices</td><td class="v">{probers}</td></tr>
    <tr><td>deauth/disassoc</td><td class="v">{deauths}</td></tr>
    <tr><td>frame mix</td><td class="v">{frame_mix}</td></tr>
    <tr><td>model</td><td class="v">{model}</td></tr>
    <tr><td>model time</td><td class="v">{model_time}</td></tr>
  </table>
  <details><summary>analysis excerpt</summary><pre>{excerpt}</pre></details>
</div>
"""

WARD_TMPL = """<div class="run">
  <h2>{name}{badge} <span class="badge ward">WARDRIVE</span></h2>
  <table>
    <tr><td>time</td><td class="v">{time}</td></tr>
    <tr><td>sightings</td><td class="v">{sightings}</td></tr>
    <tr><td>unique APs</td><td class="v">{unique_aps}</td></tr>
    <tr><td>unique BLE/BT</td><td class="v">{unique_ble}</td></tr>
    <tr><td>hidden SSIDs</td><td class="v">{hidden}</td></tr>
    <tr><td>auth mix</td><td class="v">{auth_mix}</td></tr>
    <tr><td>run windows</td><td class="v">{windows}</td></tr>
    <tr><td>model</td><td class="v">{model}</td></tr>
    <tr><td>model time</td><td class="v">{model_time}</td></tr>
  </table>
  {map_img}
  <details><summary>analysis excerpt</summary><pre>{excerpt}</pre></details>
  {ver_detail}
</div>
"""


def render(runs, runs_dir):
    parts = []
    for r in runs:
        ver = r.get("verification")
        # Badge semantics: the verifier reconciles the analysis against the
        # deterministic brief (not the raw PCAP) and only for fields the brief
        # carries. Say so on the badge instead of implying full verification.
        if ver == "PASS":
            badge = '<span class="badge pass" title="Quantitative claims reconcile with the deterministic brief; brief-level check only">BRIEF CHECK PASS</span>'
        elif ver == "FAIL":
            badge = '<span class="badge fail" title="Analysis contradicts the deterministic brief">BRIEF CHECK FAIL</span>'
        elif ver == "UNKNOWN":
            badge = '<span class="badge unknown">BRIEF CHECK ?</span>'
        else:
            badge = '<span class="badge nover">no verify</span>'
        b = r.get("brief", {})
        a = r.get("analysis", {})
        pcap = r.get("pcap")
        pcap_s = f"{pcap['name']} ({pcap['size']:,} bytes)" if pcap else "-"
        model_time = "-"
        if "eval_s" in a:
            tok_s = a["eval_tokens"] / a["eval_s"] if a["eval_s"] else 0
            model_time = f"{a['eval_s']:.0f}s eval, {tok_s:.1f} tok/s, {a.get('total_s', 0):.0f}s total"
        ver_detail = ""
        if r.get("verification") == "FAIL" and r.get("verification_text"):
            ver_detail = ('<details open><summary>verification detail</summary><pre>'
                          + html.escape(r["verification_text"]) + "</pre></details>")
        if r.get("type") == "wardrive":
            w = r.get("wbrief", {})
            map_img = (f'<img class="map" src="{html.escape(r["map"])}" alt="schematic map">'
                       if r.get("map") else "")
            parts.append(WARD_TMPL.format(
                name=html.escape(r["name"]),
                badge=badge,
                time=datetime.fromtimestamp(r["mtime"]).strftime("%Y-%m-%d %H:%M:%S"),
                sightings=html.escape(str(w.get("sightings", "-"))),
                unique_aps=w.get("unique_aps", "-"),
                unique_ble=w.get("unique_ble", "-"),
                hidden=w.get("hidden", "-"),
                auth_mix=html.escape(str(w.get("auth_mix", "-"))),
                windows=html.escape("; ".join(w.get("windows", [])) or "-"),
                model=html.escape(a.get("model", "-")),
                model_time=model_time,
                map_img=map_img,
                excerpt=html.escape(a.get("excerpt", "(no analysis)")),
                ver_detail=ver_detail,
            ))
            continue
        parts.append(RUN_TMPL.format(
            name=html.escape(r["name"]),
            badge=badge,
            time=datetime.fromtimestamp(r["mtime"]).strftime("%Y-%m-%d %H:%M:%S"),
            pcap=html.escape(pcap_s),
            frames=b.get("frames", "-"),
            aps=b.get("aps", "-"),
            probers=b.get("probers", "-"),
            deauths=b.get("deauths", "-"),
            frame_mix=html.escape(str(b.get("frame_mix", "-"))),
            model=html.escape(a.get("model", "-")),
            model_time=model_time,
            excerpt=html.escape(a.get("excerpt", "(no analysis)")),
        ))
    return PAGE.format(
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        count=len(runs),
        runs_dir=html.escape(str(runs_dir)),
        body="\n".join(parts) if parts else "<p>No runs found.</p>",
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-dir", default=os.path.expanduser("~/marauder-analyst/pipeline_runs"))
    ap.add_argument("--out", default=os.path.expanduser("~/marauder-analyst/dashboard.html"))
    args = ap.parse_args()
    runs = collect_runs(args.runs_dir)
    Path(args.out).write_text(render(runs, args.runs_dir))
    print(f"wrote {args.out} ({len(runs)} runs)")
    print(f"serve with: python3 -m http.server 8080 --directory {os.path.dirname(args.out)}")


if __name__ == "__main__":
    sys.exit(main())
