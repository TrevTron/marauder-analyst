# Evidence ledger (sanitized)

This is the publication-safe extract of the project's private capture log
(58 timestamped entries plus #37b, 2026-08-31 to 2026-09-09). The raw log
stays private under PUBLICATION_RULES.md: it contains third-party MACs and
SSIDs, location data, and lab network details. What follows is the evidence
chain behind every number in the article, with those identifiers removed.
Entry numbers match the private log so the chain is auditable in principle;
the raw entries themselves are not published.

Conventions: MACs are OUI-only or fully redacted. SSIDs are anonymized.
"Lab AP" is the author's own hotspot. Coordinates never appear; wardrive
waypoints are A and B.

## Capture and streaming

- Firmware: the v6.1 unit was SD-card updated from v1.8.5 to v1.15.1 just
  before logging began; every log entry runs on v1.15.1 (pinned commit in
  BUILD.md). v1.16.0 shipped 2026-09-08, after testing wrapped, and is
  untested with this project.
- #4: 64 GB FAT32 card (reports 60,906 MB) passed a write-integrity test and
  wrote/read multi-megabyte captures cleanly for the whole project, despite
  the wiki's 32 GB guidance. One card, one firmware version.
- #6: serial streaming mechanism located in firmware source
  (`Buffer::saveSerial`, `[BUF/BEGIN]` markers, `-serial` flag; the path
  originates in the Flipper companion ecosystem). First throughput finding:
  60 s raw to SD captured 4,474 frames vs 1,337 streamed.
- #46 (the mea culpa): a hostile audit of the article caught that the #6
  comparison was wrong: the SD capture was 197 s, not 60 s. Corrected by
  experiment: `sniffraw -serial` writes the same buffer flush to SD and
  stream; matched 60 s run in the same airspace produced byte-identical
  files (same sha256, 1,718 frames each, 520,589 bytes). Zero observed UART
  loss at ~28.6 fps (~8.7 KB/s vs ~11.5 KB/s theoretical at 115200 baud).
- #35: full SD backlog mirrored off the Marauder wirelessly; all PCAPs
  validated (v2.4 headers, zero truncated frames, zero leftover bytes).

## Models vs briefs (X1S, CPU-only)

- #8: first local-model test. qwen3.5:0.8b at ~7.4 tok/s. The same brief
  carried the day-one anomaly: 83 deauthentication frames in 60 s of passive
  listening, all from one source MAC in the shared RF environment.
- #10: 0.8b vs 4b on an identical brief. The 0.8b hallucinated: "140 deauth
  events" where the data said 83, an invented dual-AP topology. The 4b was
  accurate on every number.
- #11: the 4b inferred the capture was beacon-filtered from the frame mix
  alone. It was right; the capture was a `sniffbeacon` run.
- #16: the limitation that shaped the verifier's honest labeling: a 0.8b
  beacon-run analysis claimed "potential spoofing by a single entity" and
  mangled the frame mix, yet PASSED reconciliation because its quoted numbers
  happened to match the brief. Right numbers, wrong conclusion; a pass is
  necessary, not sufficient.

## The day-one anomaly

- #8: the 83-deauth observation itself (above).
- #45: 45-minute follow-up pattern sniff. The day-one source never
  reappeared. What dominated: unicast deauths from one radio to a single
  client, reason code 15 (4-way handshake timeout) in 250 of 268 frames,
  mean interval ~17 s in clusters, one 27-min quiet gap. Consistent with a
  struggling client or mesh steering; no attack verdict either way.

## Ground-truth attack on the author's own lab AP

- #31: targeted PMKID workflow (`sniffpmkid -d -l`) headless over serial.
  First clean run: 4 EAPOL Message-2 frames from the victim client (the
  Nova), whose journal shows 4way_handshake -> disconnected in the same
  second window. Brief verdict: partial material, not enough to crack. The
  demo also exposed two tooling bugs (missing `-l`; EAPOL invisible to the
  summarizer because handshakes ride in QoS data). Both fixed.
- #36: an earlier run against a Windows hotspot was stopped: Windows Mobile
  Hotspot shares the host radio, so a "self-targeted" attack on it is not
  self-contained. The clean target was the phone hotspot (own radio, LTE
  uplink). Neither hotspot enforced PMF (802.11w), which is why deauths
  landed at all.
- #37, #37b: run one (client across the room): 8 EAPOL, 5 M1, 3 M3, 0 M2.
  M3 implies M2 was sent; the ESP32 could not hear the quiet client. Run two
  (antenna pointed, ~0.3 m, 300 s): 33 EAPOL, 26 M1, 4 M2, 3 M3; verdict
  flipped to crackable material present (M1+M2). Analysis verified, with one
  PROBE-style caveat: the model muddled message direction in prose. Also:
  the phone rotates its hotspot BSSID between sessions.
- #42: verdict validation: hashcat run once with the author's own known
  passphrase as the only candidate. It cracked, proving the material was
  real. No hash, passphrase, or timing published.

## FileServe and wireless offload

- #21, #25-27: FileServe module written, integrated into a custom v1.15.1
  build (idempotent patch script), flashed (1,716,087 bytes), post-flash
  regression green. `/health` `/list` `/get` on :8080 behind an optional
  token. Lab-grade by design; see BUILD.md.
- #26, #30, #32: heap telemetry: ~92K free idle, ~35K with AP+server up,
  degraded to 12,468 after a long scan/attack session, at which point `/get`
  reset connections while `/health` answered. Reboot restored it.
- #30, #32: wireless offload verified end to end: Nova joined the Marauder's
  AP, pulled a 27,917 B probe capture (exact match to `/list`), summarized,
  analyzed on its own CPU-only Ollama, verified. No cable, no card, no
  cloud. Nova throughput ~4 tok/s, roughly 3x the X1S.
- #32: Nova hard-crashed 3 times running the 4B model at full core count
  (instant power-loss, journal cut mid-line). Stable at 2 threads, 65 C
  peak. Suspected power instability, not proven.
- #35: the 1,863,208 B raw capture pulled over WiFi with curl retries across
  the Nova's then-flapping driver. Small files hash-checked; the large one
  verified by clean tshark parse and matching frame counts.

## Wardrive

- #39: two runs, ~450 m walk between waypoints A and B. 633 sightings: 545
  WiFi, 88 BLE. 282 unique APs, 82 unique BLE devices, 92 hidden SSIDs.
  Auth mix: WPA2 445, OPEN 34, WPA3 30, transitional 36. 2 POIs per run.
  All 4 logs (40,295 B + 26,255 B + 2 GPX) pulled over FileServe. qwen3:4b
  on the Nova (2 threads, ~3.9 tok/s, no crash) reproduced two PROBE failure
  modes on this input type: invented frame-level evidence ("no probe
  requests (0x0004)") and fabricated durations/statistics. Ships as the
  repo's FAIL example.

## Review, hardening, and tests

- #40, #47: article evidence audit (4 mismatches found and fixed); PLUME
  (arXiv:2603.13647) and PROBE citations verified against primary sources.
- #52: external pre-publication review (2026-09-08): all findings verified
  then fixed (sanitization, verifier hardening, FileServe lab-grade docs,
  pipeline output containment, article corrections).
- #55: regression suite added (tools/test_verify_claims.py).
- #58: fresh adversarial probe found a colon-first total-frame evasion
  ("Frames: 701"); fixed and locked in. Suite: 16 checks, all passing.
