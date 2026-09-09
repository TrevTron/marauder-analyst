# marauder-analyst

Turn an ESP32 Marauder into an automated WiFi capture analyst. A Marauder captures
802.11 traffic; a small single-board computer (we use a Youyeetoo X1S, N5095, 16 GB,
no discrete GPU, all inference CPU-only) receives the capture over the stock USB
serial path or the optional WiFi offload path, reduces it to a compact deterministic
brief, and hands that brief to a small local language model that writes the analysis.
No cloud, no API keys, and no monitor-mode WiFi adapter on the analyst host.

The full build story, including the failed runs and the limits of the checker,
is at [unland.dev](https://unland.dev/blog/esp32-marauder-local-llm-capture-analyst).

Built on a JustCallMeKoko Marauder v6.1 running stock firmware (built and tested on
v1.15.1; v1.16.0 shipped 2026-09-08 and has not been tested with this project).
The USB serial path works with official firmware; no fork or custom build required.
An optional WiFi offload path (captures served straight off the SD card over HTTP,
so the card never leaves the device) uses a small custom FileServe module; see
docs/BUILD.md. FileServe is lab-grade access control, not a security boundary:
the token is optional, the AP password is hardcoded, and the token rides in the
URL. Fine for your own bench, nothing more.

## What this is

- `tools/marauder.py` - serial CLI controller. Run sniffs, list the SD card, stop
  scans, and stream live PCAPs over USB using the stock firmware's `-serial` flag.
- `tools/summarize_pcap.py` - deterministic PCAP-to-brief summarizer (tshark).
  Produces a brief ranging from a few hundred bytes to about 2 KB in the
  measured runs: frame mix, AP census, top talkers, probe
  behavior, deauth sources, EAPOL/handshake counts. No LLM involved.
- `tools/analyze_brief.py` - sends a brief to a local Ollama model and records
  the response plus timing.
- `tools/verify_claims.py` - the reconciliation step. Checks the model's
  quantitative claims against the deterministic brief: frame totals, AP counts,
  probing devices, deauth counts, EAPOL totals, handshake message counts, MAC
  citations, and (for wardrive briefs) sightings, auth mix, OUIs, and invented
  frame-level evidence. It checks the brief, not the raw PCAP, and only the
  fields the brief carries. A pass is necessary, not sufficient.
- `tools/wardrive_summarize.py` - privacy-safe wardrive/GPS log summarizer
  (no coordinates out, all SSIDs anonymized by default, MACs as OUI only,
  waypoints labeled A/B, never by what they are).
- `tools/render_dashboard.py` - renders all pipeline runs to a local HTML
  dashboard, including reconciliation results.
- `tools/pipeline.py` - the whole loop as one command: stream a capture,
  summarize it, analyze it, save all artifacts to a timestamped run folder
  (default: ~/marauder-analyst/pipeline_runs, outside the repo tree).
- `docs/EVIDENCE_LEDGER.md` - the sanitized extract of the project's private
  capture log: the article's run-specific measurements traced to log entries, with
  third-party identifiers removed. The raw log stays private on purpose.

## Quick start

On the analyst host (Linux SBC, Python 3, pyserial, tshark, Ollama):

```bash
pip install -r requirements.txt
# Marauder connected over USB, shows up as /dev/ttyUSB0

python3 tools/marauder.py cmd "help"        # verify the serial link
python3 tools/marauder.py ls                # list the SD card
python3 tools/marauder.py sniff beacon 60   # 60s capture to the SD card
python3 tools/marauder.py stream raw 60     # 60s capture streamed live to disk
python3 tools/pipeline.py raw 60 qwen3:4b-instruct 400   # capture -> brief -> analysis
```

Each command supports `--help`. The pipeline stores raw run artifacts outside the
repository by default. The serial and end-to-end commands require the Marauder;
the summarizer, verifier, examples, and regression tests can be used without it.

## Examples

`examples/` contains a real pcap brief and its (passing) analysis, plus a wardrive
brief whose qwen3:4b analysis FAILS verification in three places: a wrong count,
invented frame-level evidence, hallucinated durations. Reproduce with:

```bash
python3 tools/verify_claims.py examples/example_wardrive_brief.txt \
  examples/example_wardrive_analysis_qwen3-4b_FAILS.txt   # exits 1, 3 catches
```

The failing example is the point: small local models invent plausible detail, and
the reconciliation step is what catches it. All examples are sanitized per
docs/PUBLICATION_RULES.md (no third-party SSIDs, OUI-only MACs, no coordinates).
Raw captures and the project's full capture log are NOT in this repo for the
same reason; .gitignore keeps it that way structurally, not by convention.

## Tests

```bash
python3 tools/test_verify_claims.py
```

Regression suite for the verifier: the adversarial case from an external
pre-publication review (small-magnitude frame totals, invented EAPOL and
handshake counts, an unsupported "crackable" verdict), the shipped passing
example, the shipped wardrive FAIL example, and a truthful-analysis guard
against over-flagging. 19 checks, exit 0 on success.

## What we measured (2026-08-31 to 2026-09-02, hardware as above)

- Live serial streaming at 115200 baud is byte-exact in a matched test: the
  streamed PCAP and the SD-card copy of the same 60s capture were identical
  (sha256 match, 1,718 frames each, zero observed UART loss at ~29 fps).
  The real ceiling is bandwidth math: 115200 baud is ~11.5 KB/s theoretical,
  so a capture stream that exceeds that ceiling will overflow the serial link.
  SD-card capture is the safer option as measured throughput approaches it.
- qwen3.5:0.8b analyzed a raw-capture brief at ~7.4 tok/s and hallucinated
  (wrong deauth counts, invented topology). On the same brief,
  qwen3:4b-instruct ran at ~1 tok/s and correctly reported the measured counts.
  A later attack brief ran at ~1.3 tok/s. These are two models from different Qwen
  generations, not a controlled size ladder and not evidence of a general
  parameter threshold.
- This specific 64 GB FAT32 SD card wrote valid PCAPs on v1.15.1 throughout
  testing, despite the wiki's documented 32 GB guidance. One card, one
  firmware version: an existence proof, not a refutation of the limit.

## Legal and scope

This toolkit is for capturing and analyzing traffic on networks and devices you
own or are explicitly authorized to test. The demo environment for this project
is a private lab network and passively received ambient broadcast metadata
(SSIDs, BSSIDs, frame types). Do not point this at other people's networks.
You are responsible for knowing the law where you are.

## Acknowledgments

Hardware sponsored by JustCallMeKoko. Analysis-layer design informed by
published work on LLM packet-capture analysis (LLMcap, PLUME, PROBE); see
docs/sources.md.
