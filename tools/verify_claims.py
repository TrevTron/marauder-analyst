#!/usr/bin/env python3
"""verify_claims.py - reconcile model analysis against the deterministic brief.

Layer 2 of the analyst pipeline, per PROBE (arXiv:2606.06871): never trust the
model's numbers; check quantitative claims against the ground-truth brief.

SCOPE, stated plainly: this reconciles the analysis against the BRIEF, not
against the raw PCAP. The brief is deterministic from the PCAP (tshark), so a
PASS means "the analysis matches the deterministic summary." It checks only
fields the brief carries:

  pcap briefs (summarize_pcap.py): total frames, unique APs, probing devices,
    deauth/disassoc counts, deauth source counts, EAPOL totals, handshake
    message counts (M1/M2/M3), handshake-completeness verdicts, MAC citations
  wardrive briefs (wardrive_summarize.py): sightings, unique devices, hidden
    SSIDs and their percentage, auth mix, OUI counts, run durations, invented
    frame-level evidence (wardrive logs contain NO frame-level data, so any
    frame-type claim about the data itself is invented evidence by definition)

It does NOT verify subtype mixes, directionality, timing, or interpretive
conclusions. A PASS is necessary, not sufficient.

Usage: python3 verify_claims.py <brief.txt> <analysis.txt>
Exit 0 if no contradictions, 1 if any found, 2 if the brief is unparseable.
"""
import sys, re
from datetime import datetime


def parse_brief(text):
    facts = {}
    m = re.search(r"Frames:\s*(\d+)", text)
    if m: facts["frames"] = int(m.group(1))
    m = re.search(r"Unique APs \(by BSSID\):\s*(\d+)", text)
    if m: facts["aps"] = int(m.group(1))
    m = re.search(r"Devices sending probe requests:\s*(\d+)", text)
    if m: facts["probers"] = int(m.group(1))
    m = re.search(r"Deauth/disassoc(?: frames)?:\s*(\d+)", text)
    if m: facts["deauths"] = int(m.group(1))
    m = re.search(r"Deauth sources:\s*([0-9a-f:]+)\((\d+)\)", text)
    if m: facts["deauth_src"] = m.group(1); facts["deauth_src_count"] = int(m.group(2))
    m = re.search(r"EAPOL \(handshake\) frames:\s*(\d+)", text)
    if m: facts["eapol"] = int(m.group(1))
    m = re.search(r"Handshake messages:\s*(.*)", text)
    if m:
        for k, v in re.findall(r"(M[123]|other)=(\d+)", m.group(1)):
            facts[k.lower()] = int(v)
    m = re.search(r"Handshake completeness:\s*(.*)", text)
    if m:
        facts["completeness"] = "crackable" if "crackable material present" in m.group(1) else "partial"
    return facts


def parse_wardrive_brief(text):
    facts = {}
    m = re.search(r"Total sightings:\s*(\d+)\s*\((\d+)\s*WiFi,\s*(\d+)\s*BLE", text)
    if m:
        facts["sightings_total"] = int(m.group(1))
        facts["sightings_wifi"] = int(m.group(2))
        facts["sightings_ble"] = int(m.group(3))
    m = re.search(r"Unique devices:\s*(\d+)\s*WiFi APs,\s*(\d+)\s*BLE", text)
    if m:
        facts["unique_aps"] = int(m.group(1))
        facts["unique_ble"] = int(m.group(2))
    m = re.search(r"\(hidden\):\s*(\d+)", text)
    if m: facts["hidden"] = int(m.group(1))
    for m in re.finditer(r"^\s{2}(WPA2_PSK|WPA3_PSK|OPEN|WPA_WPA2_PSK|WPA2_WPA3_PSK):\s*(\d+)$", text, re.M):
        facts.setdefault("auth", {})[m.group(1)] = int(m.group(2))
    for m in re.finditer(r"^\s{2}([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2}):\s*(\d+)$", text, re.M):
        facts.setdefault("ouis", {})[m.group(1).upper()] = int(m.group(2))
    durations = []
    for m in re.finditer(r"\[run_\d+\]\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*to\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", text):
        t0 = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        t1 = datetime.strptime(m.group(2), "%Y-%m-%d %H:%M:%S")
        durations.append(int((t1 - t0).total_seconds()))
    if durations:
        facts["run_durations_s"] = durations
        facts["total_duration_s"] = sum(durations)
    return facts


CHECKS = [
    # (regex in analysis, fact key, human label)
    (r"(\d+)\s*(?:unique\s*)?(?:access points|APs)", "aps", "AP count"),
    (r"(\d+)\W{0,12}deauth", "deauths", "deauth count"),
    (r"(\d+)\s*(?:devices|stations).{0,30}prob", "probers", "probing device count"),
    # total frame counts in these captures are in the thousands; the >=1000 gate
    # avoids flagging legitimate sub-counts like "82 missing-SSID frames"
    (r"(\d[\d,]{3,})\s*frames", "frames", "total frame count"),
]

# Any-magnitude phrasings that unambiguously mean the TOTAL frame count.
# The >=1000 gate above misses small captures; these patterns close that hole
# without flagging sub-counts, because they only fire on total-claim wording.
FRAME_TOTAL_PATTERNS = [
    r"(\d[\d,]*)\s*total\s*frames",
    r"total\s*of\s*(\d[\d,]*)\s*frames",
    r"(\d[\d,]*)\s*frames\s+(?:in|across|over)\s+the\s+(?:capture|pcap|brief|file)",
    r"(?:capture|pcap|file)\s+(?:contains|contained|holds|held|has|had)\s*(\d[\d,]*)\s*frames",
    # colon-first phrasing ("Frames: 701 were recorded"); found by adversarial
    # probe 2026-09-09, previously slipped every gate
    r"frames:\s*(\d[\d,]*)",
]


def verify_pcap(brief, analysis, facts):
    problems = []
    for pattern, key, label in CHECKS:
        if key not in facts:
            continue
        for m in re.finditer(pattern, analysis, re.IGNORECASE):
            claimed = int(m.group(1).replace(",", ""))
            actual = facts[key]
            if claimed != actual:
                problems.append(f"CONTRADICTION: {label}: model said {claimed}, data says {actual}")

    if "frames" in facts:
        for pattern in FRAME_TOTAL_PATTERNS:
            for m in re.finditer(pattern, analysis, re.IGNORECASE):
                claimed = int(m.group(1).replace(",", ""))
                if claimed != facts["frames"]:
                    msg = f"CONTRADICTION: total frame count: model said {claimed}, data says {facts['frames']}"
                    if msg not in problems:
                        problems.append(msg)

    # EAPOL / handshake checks (brief carries these when the capture has them)
    if "eapol" in facts:
        for m in re.finditer(r"(\d[\d,]*)\s*EAPOL", analysis, re.IGNORECASE):
            claimed = int(m.group(1).replace(",", ""))
            if claimed != facts["eapol"]:
                problems.append(f"CONTRADICTION: EAPOL count: model said {claimed}, data says {facts['eapol']}")
    for msg in ("m1", "m2", "m3"):
        if msg in facts:
            for m in re.finditer(msg.upper() + r"[^\d]{0,10}(\d+)", analysis):
                claimed = int(m.group(1))
                if claimed != facts[msg]:
                    problems.append(f"CONTRADICTION: {msg.upper()} count: model said {claimed}, data says {facts[msg]}")
            for m in re.finditer(r"(\d+)\s*(?:x\s*)?" + msg.upper(), analysis):
                claimed = int(m.group(1))
                if claimed != facts[msg]:
                    problems.append(f"CONTRADICTION: {msg.upper()} count: model said {claimed}, data says {facts[msg]}")
    if facts.get("completeness") == "partial":
        for m in re.finditer(r"crackable", analysis, re.IGNORECASE):
            problems.append("UNSUPPORTED VERDICT: analysis claims crackable material; brief says partial only, not enough to crack")
    if facts.get("completeness") == "crackable":
        for m in re.finditer(r"not\s+crackable|uncrackable|cannot\s+be\s+cracked", analysis, re.IGNORECASE):
            problems.append("CONTRADICTION: analysis denies crackable material; brief says crackable material present")

    # MAC citation check: any MAC in the analysis should appear in the brief
    brief_macs = set(re.findall(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", brief))
    for mac in set(re.findall(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", analysis.lower())):
        if mac not in brief_macs:
            problems.append(f"UNVERIFIABLE MAC: {mac} cited in analysis but not present in brief")
    return problems


def verify_wardrive(analysis, facts):
    problems = []

    def claim_check(pattern, key, label):
        if key not in facts:
            return
        for m in re.finditer(pattern, analysis, re.IGNORECASE):
            claimed = int(m.group(1).replace(",", ""))
            if claimed != facts[key]:
                problems.append(f"CONTRADICTION: {label}: model said {claimed}, data says {facts[key]}")

    claim_check(r"(\d[\d,]*)\s*unique\s*(?:WiFi\s*)?(?:access points|APs)", "unique_aps", "unique AP count")
    # BLE counts are ambiguous in prose: both sightings (88) and unique devices (82)
    # are real numbers in the brief, so accept either; only flag true outsiders
    for m in re.finditer(r"(\d[\d,]*)\s*(?:unique\s*)?BLE", analysis, re.IGNORECASE):
        claimed = int(m.group(1).replace(",", ""))
        valid = {facts.get("unique_ble"), facts.get("sightings_ble")} - {None}
        if valid and claimed not in valid:
            problems.append(f"CONTRADICTION: BLE count: model said {claimed}, data has unique={facts.get('unique_ble')} sightings={facts.get('sightings_ble')}")
    claim_check(r"(\d[\d,]*)\s*(?:APs?\s+(?:with|using)\s+)?hidden\s+SSIDs?", "hidden", "hidden SSID count")
    claim_check(r"(\d[\d,]*)\s+hidden\s+SSIDs?", "hidden", "hidden SSID count")

    # percentages tied to "hidden" must be computed against WiFi sightings
    if "hidden" in facts and "sightings_wifi" in facts:
        expected = 100.0 * facts["hidden"] / facts["sightings_wifi"]
        for m in re.finditer(r"hidden[^.]{0,60}?(\d+(?:\.\d+)?)\s*%|(\d+(?:\.\d+)?)\s*%[^.]{0,60}?hidden", analysis, re.IGNORECASE):
            pct = float(m.group(1) or m.group(2))
            if abs(pct - expected) > 1.0:
                problems.append(f"SUSPECT PERCENTAGE: hidden-SSID share: model said {pct}%, of WiFi sightings it is {expected:.1f}%")

    # auth mix counts
    for kind, count in facts.get("auth", {}).items():
        tag = kind.replace("_PSK", "").replace("_", "[_ /]?")
        for m in re.finditer(tag + r"\D{0,15}?\(?\s*(\d[\d,]*)", analysis, re.IGNORECASE):
            claimed = int(m.group(1).replace(",", ""))
            if claimed != count:
                problems.append(f"CONTRADICTION: {kind} count: model said {claimed}, data says {count}")

    # OUI sighting counts
    for oui, count in facts.get("ouis", {}).items():
        for m in re.finditer(re.escape(oui) + r"\D{0,15}?\(?\s*(\d[\d,]*)", analysis):
            claimed = int(m.group(1).replace(",", ""))
            if claimed != count:
                problems.append(f"CONTRADICTION: OUI {oui} count: model said {claimed}, data says {count}")

    # duration claims: any "N-second capture/window" must match a real run window
    if "run_durations_s" in facts:
        valid = set(facts["run_durations_s"]) | {facts["total_duration_s"]}
        for m in re.finditer(r"(\d+)[- ]second\s+(?:wardrive\s+)?(?:capture|window|sniff|run|log)", analysis, re.IGNORECASE):
            claimed = int(m.group(1))
            if not any(abs(claimed - v) <= 30 for v in valid):
                problems.append(f"CONTRADICTION: capture duration: model said {claimed}s, actual run windows are {facts['run_durations_s']}s")

    # invented frame-level evidence: wardrive logs have NO frame types
    for m in re.finditer(r"0x[0-9a-fA-F]{4}", analysis):
        problems.append(f"INVENTED EVIDENCE: frame subtype code {m.group(0)} cited; wardrive logs contain no frame-level data")
    for m in re.finditer(r"(?:lack|absence|presence|count)s?\s+of[^.]{0,60}?(?:probe request|beacon frame|deauth|EAPOL|handshake)", analysis, re.IGNORECASE):
        problems.append(f"INVENTED EVIDENCE: frame-level claim about the data ('{m.group(0)[:70]}'); wardrive logs contain no frame-level data")

    # full MACs cannot come from a wardrive brief (OUIs only)
    for mac in set(re.findall(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", analysis.lower())):
        problems.append(f"UNVERIFIABLE MAC: {mac} cited in analysis; wardrive briefs carry OUIs only")
    return problems


def main():
    brief = open(sys.argv[1]).read()
    analysis = open(sys.argv[2]).read()
    if brief.startswith("WARDRIVE CAPTURE BRIEF"):
        mode = "wardrive"
        facts = parse_wardrive_brief(brief)
        problems = verify_wardrive(analysis, facts) if facts else None
    else:
        mode = "pcap"
        facts = parse_brief(brief)
        problems = verify_pcap(brief, analysis, facts) if facts else None
    if not facts:
        print("[!] could not parse any facts from brief"); sys.exit(2)
    print(f"[i] mode: {mode}")
    print(f"[i] ground truth: {facts}")
    if problems is None:
        problems = []
    if problems:
        print("\n".join(problems))
        print(f"\n[!] {len(problems)} claim(s) failed reconciliation")
        sys.exit(1)
    print("[+] all quantitative claims reconcile with the data")
    sys.exit(0)


if __name__ == "__main__":
    main()
