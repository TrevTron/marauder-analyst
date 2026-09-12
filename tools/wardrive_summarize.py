#!/usr/bin/env python3
"""wardrive_summarize.py - Parse ESP32 Marauder wardrive logs (WiGLE CSV 1.4)
and POI GPX files into a publication-safe brief, stats JSON, and a
coordinate-free schematic map.

Publication rules enforced here (repo/docs/PUBLICATION_RULES.md):
- No raw GPS coordinates in any output. Only relative/derived values.
- Map is schematic: normalized 0-1 offsets, no axis values, no scale, no base map.
- Third-party MACs truncated to OUI. Third-party SSIDs anonymized.
- ALL SSIDs are anonymized by default, including your own. Naming any SSID
  (even your own lab AP) next to a walk route pairs a name with a place.
  Pass --own-ssid NAME explicitly for local-only runs if you want one named.
- Waypoints are labeled A/B/C, never by what they are (home, gym, work).
"""
import csv
import json
import math
import sys
from defusedxml.ElementTree import parse as _xml_parse
from collections import Counter, defaultdict
from pathlib import Path

# Device-generated AP names that identify the gadget, not a place. Safe to name.
SAFE_SSIDS = {"MarauderFiles"}


def haversine_m(lat1, lon1, lat2, lon2):
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def parse_wigle(path):
    rows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    # line 0 = WigleWifi header, line 1 = column header
    reader = csv.DictReader(lines[1:])
    for r in reader:
        try:
            rows.append({
                "mac": r["MAC"].strip(),
                "ssid": r["SSID"].strip(),
                "auth": r["AuthMode"].strip().strip("[]"),
                "seen": r["FirstSeen"].strip(),
                "chan": r["Channel"].strip(),
                "rssi": int(r["RSSI"]),
                "lat": float(r["CurrentLatitude"]),
                "lon": float(r["CurrentLongitude"]),
                "type": (r.get("Type") or "WIFI").strip(),
            })
        except (KeyError, ValueError):
            continue
    return rows


def parse_gpx(path):
    tree = _xml_parse(path)
    wpts = []
    for w in tree.getroot().iter():
        if not w.tag.endswith("wpt"):
            continue
        name = next((c for c in w if c.tag.endswith("name")), None)
        t = next((c for c in w if c.tag.endswith("time")), None)
        wpts.append({
            "lat": float(w.attrib["lat"]),
            "lon": float(w.attrib["lon"]),
            "name": name.text if name is not None else "POI",
            "time": t.text if t is not None else "",
        })
    return wpts


def anonymize_ssids(counter, own_ssids=frozenset()):
    """Anonymize every SSID by rank, except device-generated safe names and
    any the caller explicitly marked as own (local-only runs)."""
    mapping = {}
    n = 0
    for ssid, _ in counter.most_common():
        if ssid in SAFE_SSIDS or ssid in own_ssids:
            mapping[ssid] = ssid
        elif ssid == "":
            mapping[ssid] = "(hidden)"
        else:
            n += 1
            mapping[ssid] = f"third-party-{n:02d}"
    return mapping


def run_stats(rows, label):
    wifi = [r for r in rows if r["type"] == "WIFI"]
    ble = [r for r in rows if r["type"] in ("BLE", "BT")]
    uniq_ap = {r["mac"] for r in wifi}
    uniq_ble = {r["mac"] for r in ble}
    times = sorted(r["seen"] for r in rows if r["seen"])
    # path length from successive sightings
    path_m = 0.0
    for a, b in zip(rows, rows[1:]):
        path_m += haversine_m(a["lat"], a["lon"], b["lat"], b["lon"])
    auth = Counter(r["auth"] for r in wifi)
    return {
        "label": label,
        "sightings_total": len(rows),
        "sightings_wifi": len(wifi),
        "sightings_ble": len(ble),
        "unique_aps": len(uniq_ap),
        "unique_ble": len(uniq_ble),
        "first_seen_utc": times[0] if times else None,
        "last_seen_utc": times[-1] if times else None,
        "path_length_m": round(path_m),
        "auth_mix": dict(auth.most_common()),
    }


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("indir", help="dir with wardrive_*.log and wardrive_poi_*.gpx")
    ap.add_argument("outdir", help="output dir for brief/json/map")
    ap.add_argument("--map", default="wardrive_schematic.png")
    ap.add_argument("--own-ssid", action="append", default=[],
                    help="SSID you own that may be named in output (local-only runs)")
    args = ap.parse_args()

    indir = Path(args.indir)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    logs = sorted(indir.glob("wardrive_*.log"))
    gpxs = sorted(indir.glob("wardrive_poi_*.gpx"))
    runs = [parse_wigle(p) for p in logs]
    pois = [parse_gpx(p) for p in gpxs]

    all_rows = [r for run in runs for r in run]
    ssid_counter = Counter(r["ssid"] for r in all_rows if r["type"] == "WIFI")
    ssid_map = anonymize_ssids(ssid_counter, own_ssids=frozenset(args.own_ssid))

    stats = {
        "files": [p.name for p in logs],
        "runs": [run_stats(runs[i], f"run_{i}") for i in range(len(runs))],
        "combined": run_stats(all_rows, "combined"),
        "poi_counts": [len(p) for p in pois],
        "poi_times_utc": [[w["time"] for w in p] for p in pois],
    }

    # relative waypoint separation (never labeled by what the waypoint is)
    if pois and len(pois[0]) >= 2:
        d = haversine_m(pois[0][0]["lat"], pois[0][0]["lon"],
                        pois[0][1]["lat"], pois[0][1]["lon"])
        stats["waypoint_ab_straight_line_m"] = round(d)

    # top SSIDs (anonymized) and OUI histogram
    top_ssids = [(ssid_map[s], c) for s, c in ssid_counter.most_common(15)]
    oui_counter = Counter(r["mac"][:8].upper() for r in all_rows)
    stats["top_ssids_anonymized"] = top_ssids
    stats["top_ouis"] = oui_counter.most_common(10)

    # ---- brief text (publication-safe) ----
    c = stats["combined"]
    lines = []
    lines.append("WARDRIVE CAPTURE BRIEF (sanitized, no coordinates)")
    lines.append("")
    lines.append(f"Files: {', '.join(stats['files'])}")
    lines.append(f"Runs: {len(runs)} (run_0 = outbound leg, run_1 = return leg)")
    lines.append(f"Total sightings: {c['sightings_total']} "
                 f"({c['sightings_wifi']} WiFi, {c['sightings_ble']} BLE/BT)")
    lines.append(f"Unique devices: {c['unique_aps']} WiFi APs, {c['unique_ble']} BLE/BT")
    lines.append(f"POI bookmarks: {stats['poi_counts']} per run (waypoint A, waypoint B)")
    if "waypoint_ab_straight_line_m" in stats:
        lines.append(f"Waypoint A-to-B straight line: ~{stats['waypoint_ab_straight_line_m']} m")
    for rs in stats["runs"]:
        lines.append("")
        lines.append(f"[{rs['label']}] {rs['first_seen_utc']} to {rs['last_seen_utc']} UTC")
        lines.append(f"  sightings {rs['sightings_total']} "
                     f"({rs['sightings_wifi']} WiFi / {rs['sightings_ble']} BLE), "
                     f"unique APs {rs['unique_aps']}, unique BLE {rs['unique_ble']}, "
                     f"path ~{rs['path_length_m']} m")
        mix = ", ".join(f"{k}:{v}" for k, v in list(rs["auth_mix"].items())[:6])
        lines.append(f"  auth mix: {mix}")
    lines.append("")
    lines.append("Combined auth mix (unique-device sightings):")
    for k, v in c["auth_mix"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Top SSIDs by sightings (third-party names anonymized):")
    for name, cnt in top_ssids:
        lines.append(f"  {name}: {cnt}")
    lines.append("")
    lines.append("Top device OUIs (first 3 bytes only):")
    for oui, cnt in stats["top_ouis"]:
        lines.append(f"  {oui}: {cnt}")
    brief = "\n".join(lines) + "\n"
    (outdir / "wardrive_brief.txt").write_text(brief, encoding="utf-8")
    (outdir / "wardrive_stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")

    # ---- schematic map (normalized, no axes, no scale) ----
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    try:
        from daimon_runtime import setup_plot
        setup_plot()
    except Exception:
        pass

    lats = [r["lat"] for r in all_rows]
    lons = [r["lon"] for r in all_rows]
    lat0, lat1 = min(lats), max(lats)
    lon0, lon1 = min(lons), max(lons)
    span = max(lat1 - lat0, lon1 - lon0, 1e-9)

    def norm(lat, lon):
        return ((lon - lon0) / span, (lat - lat0) / span)

    fig, ax = plt.subplots(figsize=(7, 7))
    colors = {0: "#4c9aff", 1: "#f77825"}
    labels = {0: "outbound leg", 1: "return leg"}
    for i, run in enumerate(runs):
        xs = [norm(r["lat"], r["lon"])[0] for r in run if r["type"] == "WIFI"]
        ys = [norm(r["lat"], r["lon"])[1] for r in run if r["type"] == "WIFI"]
        ax.scatter(xs, ys, s=10, alpha=0.35, color=colors.get(i, "#888888"),
                   label=f"AP sightings, {labels.get(i, f'run {i}')}", linewidths=0)
    # waypoints labeled A/B, never by what they are
    if pois and len(pois[0]) >= 2:
        hx, hy = norm(pois[0][0]["lat"], pois[0][0]["lon"])
        gx, gy = norm(pois[0][1]["lat"], pois[0][1]["lon"])
        ax.scatter([hx], [hy], s=180, marker="H", color="#2ecc71", zorder=5, label="Waypoint A (POI)")
        ax.scatter([gx], [gy], s=180, marker="*", color="#e74c3c", zorder=5, label="Waypoint B (POI)")
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_title("Wardrive schematic (relative layout, not to scale)")
    ax.legend(loc="best", fontsize=8, framealpha=0.9)
    fig.savefig(outdir / args.map, bbox_inches="tight", dpi=150)
    print(f"wrote {outdir / 'wardrive_brief.txt'}")
    print(f"wrote {outdir / 'wardrive_stats.json'}")
    print(f"wrote {outdir / args.map}")
    print(f"unique APs={c['unique_aps']} BLE={c['unique_ble']} sightings={c['sightings_total']}")


if __name__ == "__main__":
    main()
