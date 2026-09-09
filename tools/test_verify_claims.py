#!/usr/bin/env python3
"""test_verify_claims.py - regression tests for verify_claims.py.

Runs the verifier against:
  1. the adversarial case from the 2026-09-08 external pre-publication review
     (a 3-digit total-frame claim plus invented EAPOL/handshake counts that
     slipped past the first version of the verifier)
  2. the shipped passing example pair (must PASS)
  3. the shipped wardrive FAIL pair (must FAIL with the documented catches)
  4. a truthful analysis of the adversarial brief (must PASS, guarding
     against over-flagging)

Usage: python3 tools/test_verify_claims.py
Exit 0 if all tests pass, 1 otherwise.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
VERIFIER = os.path.join(HERE, "verify_claims.py")

ADVERSARIAL_BRIEF = """\
CAPTURE BRIEF: adversarial regression case
Frames: 702
Frame mix: 0x0008=694, 0x0000=8
Unique APs (by BSSID): 3
Devices sending probe requests: 0
Deauth/disassoc frames: 8
EAPOL (handshake) frames: 8
Handshake messages: M1=4, M2=4, M3=0, other=0
Handshake completeness: partial material (M1 total 4, M2 total 4)
"""

# The reviewer's attack shape: small-magnitude total-frame claim, invented
# EAPOL total, invented handshake message counts, unsupported verdict.
ADVERSARIAL_ANALYSIS = """\
The capture contains 701 total frames. I observed 999 EAPOL frames, indicating
extensive handshake activity. There were 12 deauth events. M1 appeared 9 times,
M2 7 times, M3 2 times. This is crackable material.
"""

ADVERSARIAL_EXPECTED = [
    "total frame count: model said 701, data says 702",
    "EAPOL count: model said 999, data says 8",
    "deauth count: model said 12, data says 8",
    "M1 count: model said 9, data says 4",
    "M2 count: model said 7, data says 4",
    "M3 count: model said 2, data says 0",
    "UNSUPPORTED VERDICT",
]

TRUTHFUL_ANALYSIS = """\
The capture contains 702 total frames across 3 unique access points. No devices
sent probe requests. There were 8 deauth events. The sniffer saw 8 EAPOL frames:
M1 4 times, M2 4 times, M3 0 times. That is partial material, not enough to crack.
"""

# Colon-first total-frame phrasing slipped every gate until the 2026-09-09
# adversarial probe; locked in as a regression.
COLON_ATTACK_ANALYSIS = """\
Frames: 701 were recorded. The capture shows 3 unique access points.
"""

WARDRIVE_FAIL_EXPECTED = [
    "unique AP count: model said 246, data says 282",
    "INVENTED EVIDENCE",
    "capture duration",
]


def run_verifier(brief_path, analysis_path):
    proc = subprocess.run(
        [sys.executable, VERIFIER, brief_path, analysis_path],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail and not ok else ""))
    return ok


def main():
    all_ok = True

    with tempfile.TemporaryDirectory() as tmp:
        adv_brief = os.path.join(tmp, "adv_brief.txt")
        adv_analysis = os.path.join(tmp, "adv_analysis.txt")
        ok_analysis = os.path.join(tmp, "ok_analysis.txt")
        for path, text in ((adv_brief, ADVERSARIAL_BRIEF),
                           (adv_analysis, ADVERSARIAL_ANALYSIS),
                           (ok_analysis, TRUTHFUL_ANALYSIS)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)

        # 1. adversarial case must FAIL with every expected catch
        code, out = run_verifier(adv_brief, adv_analysis)
        all_ok &= check("adversarial case exits 1", code == 1, f"exit {code}\n{out}")
        for expected in ADVERSARIAL_EXPECTED:
            all_ok &= check(f"adversarial catch: {expected}", expected in out)

        # 4. truthful analysis of the same brief must PASS
        code, out = run_verifier(adv_brief, ok_analysis)
        all_ok &= check("truthful analysis exits 0", code == 0, f"exit {code}\n{out}")

        # 5. colon-first total-frame phrasing must FAIL (2026-09-09 probe)
        colon_analysis = os.path.join(tmp, "colon_analysis.txt")
        with open(colon_analysis, "w", encoding="utf-8") as fh:
            fh.write(COLON_ATTACK_ANALYSIS)
        code, out = run_verifier(adv_brief, colon_analysis)
        all_ok &= check("colon-first attack exits 1", code == 1, f"exit {code}\n{out}")
        all_ok &= check(
            "colon-first catch: total frame count",
            "total frame count: model said 701, data says 702" in out,
        )

    # 2. shipped passing example pair must PASS
    code, out = run_verifier(
        os.path.join(REPO, "examples", "example_brief.txt"),
        os.path.join(REPO, "examples", "example_analysis_qwen3-4b.txt"),
    )
    all_ok &= check("shipped pcap example pair exits 0", code == 0, f"exit {code}\n{out}")

    # 3. shipped wardrive FAIL pair must FAIL with the documented catches
    code, out = run_verifier(
        os.path.join(REPO, "examples", "example_wardrive_brief.txt"),
        os.path.join(REPO, "examples", "example_wardrive_analysis_qwen3-4b_FAILS.txt"),
    )
    all_ok &= check("shipped wardrive FAIL pair exits 1", code == 1, f"exit {code}\n{out}")
    for expected in WARDRIVE_FAIL_EXPECTED:
        all_ok &= check(f"wardrive catch: {expected}", expected in out)

    print("\n" + ("ALL TESTS PASS" if all_ok else "TESTS FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
