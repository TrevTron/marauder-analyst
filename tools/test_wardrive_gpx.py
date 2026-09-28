#!/usr/bin/env python3
"""test_wardrive_gpx.py - regression tests for GPX parsing in wardrive_summarize.py.

Covers:
  1. a normal POI GPX parses to the expected waypoints
  2. a GPX with an internal entity declaration is rejected (no expansion)
  3. a GPX with an external entity is rejected (the referenced file is not read)
  4. the CLI reports a rejected GPX as a clean error, not a traceback

Usage: python3 tools/test_wardrive_gpx.py
Exit 0 if all tests pass, 1 otherwise.
"""
import os
import subprocess  # nosec B404  # subprocess used with an argv list, never shell=True
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SUMMARIZER = os.path.join(HERE, "wardrive_summarize.py")
sys.path.insert(0, HERE)

from wardrive_summarize import GPXError, parse_gpx  # noqa: E402

NORMAL_GPX = """\
<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="test" xmlns="http://www.topografix.com/GPX/1/1">
  <wpt lat="10.5" lon="-20.25"><time>2026-09-01T12:00:00Z</time><name>A</name></wpt>
  <wpt lat="10.6" lon="-20.35"><name>B</name></wpt>
</gpx>
"""

INTERNAL_ENTITY_GPX = """\
<?xml version="1.0"?>
<!DOCTYPE gpx [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<gpx><wpt lat="1" lon="2"><name>&b;</name></wpt></gpx>
"""

EXTERNAL_ENTITY_GPX = """\
<?xml version="1.0"?>
<!DOCTYPE gpx [<!ENTITY x SYSTEM "file://{target}">]>
<gpx><wpt lat="1" lon="2"><name>&x;</name></wpt></gpx>
"""

LOCAL_FILE_MARKER = "NOT-FOR-THE-BRIEF"


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail and not ok else ""))
    return ok


def write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def rejects(path):
    try:
        parse_gpx(path)
    except GPXError as e:
        return True, str(e)
    except Exception as e:  # any other exception is the bug under test
        return False, f"raised {type(e).__name__}: {e}"
    return False, "parsed without error"


def main():
    all_ok = True

    with tempfile.TemporaryDirectory() as tmp:
        # 1. normal GPX must still parse
        normal = os.path.join(tmp, "wardrive_poi_normal.gpx")
        write(normal, NORMAL_GPX)
        wpts = parse_gpx(normal)
        expected = [
            {"lat": 10.5, "lon": -20.25, "name": "A", "time": "2026-09-01T12:00:00Z"},
            {"lat": 10.6, "lon": -20.35, "name": "B", "time": ""},
        ]
        all_ok &= check("normal GPX parses to expected waypoints", wpts == expected, repr(wpts))

        # 2. internal entity declaration must be rejected, not expanded
        internal = os.path.join(tmp, "wardrive_poi_internal.gpx")
        write(internal, INTERNAL_ENTITY_GPX)
        ok, detail = rejects(internal)
        all_ok &= check("internal-entity GPX rejected with GPXError", ok, detail)

        # 3. external entity must be rejected and its target never read
        target = os.path.join(tmp, "local.txt")
        write(target, LOCAL_FILE_MARKER)
        external = os.path.join(tmp, "wardrive_poi_external.gpx")
        write(external, EXTERNAL_ENTITY_GPX.format(target=target))
        ok, detail = rejects(external)
        all_ok &= check("external-entity GPX rejected with GPXError", ok, detail)
        all_ok &= check("external entity target not in error text", LOCAL_FILE_MARKER not in detail)

        # 4. CLI: rejected GPX exits non-zero with a one-line error, no traceback
        indir = os.path.join(tmp, "in")
        os.mkdir(indir)
        write(os.path.join(indir, "wardrive_poi_bad.gpx"), INTERNAL_ENTITY_GPX)
        proc = subprocess.run(  # nosec B603  # argv list, runs the sibling summarizer via sys.executable, no shell
            [sys.executable, SUMMARIZER, indir, os.path.join(tmp, "out")],
            capture_output=True, text=True,
        )
        all_ok &= check("CLI exits non-zero on rejected GPX", proc.returncode != 0,
                        f"exit {proc.returncode}")
        all_ok &= check("CLI prints a clean error", proc.stderr.startswith("error: "), proc.stderr)
        all_ok &= check("CLI prints no traceback", "Traceback" not in proc.stderr, proc.stderr)

    print("\n" + ("ALL TESTS PASS" if all_ok else "TESTS FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
