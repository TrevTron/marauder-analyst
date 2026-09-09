#!/usr/bin/env python3
"""summarize_pcap.py - deterministic PCAP-to-brief summarizer for 802.11 captures.

Layer 1 of the analyst pipeline (see FRAMEWORK_SOURCES.md): no LLM involved.
Turns a Marauder PCAP into a compact text brief sized for a small local model
(target: 500-5000 tokens, per PROBE's working representation range).

Marauder PCAPs are linktype 105 (raw 802.11, no radiotap), so no per-frame RSSI.
Usage: python3 summarize_pcap.py <file.pcap> [--top N]
"""
import subprocess, sys, collections, argparse, re

def decode_ssid(s):
    """tshark emits SSIDs as hex when they contain separators; decode if so."""
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0 and len(s) >= 4:
        try:
            decoded = bytes.fromhex(s).decode("utf-8")
            if all(c.isprintable() for c in decoded):
                return decoded
        except (ValueError, UnicodeDecodeError):
            pass
    return s

def tshark_fields(pcap, fields, display_filter=None):
    cmd = ["tshark", "-r", pcap]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields"] + [f for kv in fields for f in ("-e", kv)]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"tshark failed: {out.stderr[:300]}")
    return [line.split("\t") for line in out.stdout.splitlines()]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    rows = tshark_fields(args.pcap, ["wlan.fc.type_subtype", "wlan.sa", "wlan.da",
                                     "wlan.bssid", "wlan.ssid", "frame.len"])
    n = len(rows)
    sub = collections.Counter(r[0] for r in rows)
    talkers = collections.Counter(r[1] for r in rows if len(r) > 1 and r[1])
    aps = {}
    probes_from = collections.Counter()
    probed_ssids = collections.Counter()
    deauths = []
    eapol_count = 0

    for r in rows:
        st = r[0] if r else ""
        sa = r[1] if len(r) > 1 else ""
        ssid = decode_ssid(r[4]) if len(r) > 4 else ""
        if st == "0x0008" and len(r) > 3:  # beacon
            bssid = r[3]
            if bssid and bssid not in aps:
                aps[bssid] = decode_ssid(ssid)
        elif st == "0x0004":  # probe request
            probes_from[sa] += 1
            if ssid:
                probed_ssids[ssid] += 1
        elif st in ("0x000c", "0x000a"):  # deauth / disassoc
            deauths.append((sa, r[2] if len(r) > 2 else ""))

    brief = []
    brief.append(f"CAPTURE BRIEF: {args.pcap}")
    brief.append(f"Frames: {n}")
    brief.append("Frame mix: " + ", ".join(f"{k}={v}" for k, v in sub.most_common()))
    brief.append(f"Unique APs (by BSSID): {len(aps)}")
    for b, s in list(aps.items())[: args.top]:
        brief.append(f"  AP {b}  SSID=\"{s}\"")
    brief.append(f"Top talkers (by frames): " + ", ".join(f"{m}({c})" for m, c in talkers.most_common(args.top)))
    brief.append(f"Devices sending probe requests: {len(probes_from)}")
    for m, c in probes_from.most_common(args.top):
        brief.append(f"  {m} sent {c} probes")
    if probed_ssids:
        brief.append("Most probed SSIDs: " + ", ".join(f'"{s}"({c})' for s, c in probed_ssids.most_common(args.top)))
    brief.append(f"Deauth/disassoc frames: {len(deauths)}")
    if deauths:
        dc = collections.Counter(s for s, _ in deauths)
        brief.append("  Deauth sources: " + ", ".join(f"{m}({c})" for m, c in dc.most_common(args.top)))

    # EAPOL pass: 4-way handshake material (EAPOL frames ride inside QoS data
    # frames, so the type_subtype mix above cannot see them).
    eapol_rows = tshark_fields(args.pcap, ["wlan.sa", "wlan.da", "_ws.col.Info"],
                               display_filter="eapol")
    brief.append(f"EAPOL (handshake) frames: {len(eapol_rows)}")
    if eapol_rows:
        msgs = collections.Counter()
        pairs = collections.Counter()
        for sa, da, info in eapol_rows:
            m = re.search(r"Message (\d) of 4", info)
            msgs[f"M{m.group(1)}" if m else "other"] += 1
            pairs[f"{sa} -> {da}"] += 1
        brief.append("  Handshake messages: " + ", ".join(f"{k}={v}" for k, v in sorted(msgs.items())))
        for p, c in pairs.most_common(args.top):
            brief.append(f"  {p} ({c})")
        have = set(msgs)
        if {"M1", "M2"} <= have or {"M2", "M3"} <= have:
            brief.append("  Handshake completeness: crackable material present (M1+M2 or M2+M3)")
        else:
            brief.append("  Handshake completeness: partial only, not enough to crack")
    print("\n".join(brief))

if __name__ == "__main__":
    main()
