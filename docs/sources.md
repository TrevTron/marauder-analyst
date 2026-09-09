# Sources

The analysis layer design draws on published academic work and practitioner
projects. These are the ones that actually shaped decisions.

## Academic

- **LLMcap** (B-Yond, 2024, arXiv:2407.06085): DistilBERT learns the grammar of
  normal PCAPs via masked-token reconstruction and flags failures by
  reconstruction error. The paper reports 9.5 to 10 seconds per PCAP for its
  packet-ordered dictionary variants in an AWS G5.xlarge test environment.
  Lesson taken: learn grammar, not magic; generalization dropped sharply on a
  dissimilar external service.
- **PLUME** (Cisco, 2026, arXiv:2603.13647): a 140M-parameter protocol-aware
  model matched frontier models on the paper's wireless-trace prediction
  tasks. Lesson taken: purpose-built representations can let compact models
  compete on a narrow evaluated task. This is not a general model-size claim.
  Also: pin your tshark version.
- **PROBE** (Cisco, 2026, arXiv:2606.06871): single-pass LLM beat a human expert
  baseline on capture verdicts but missed critical frames in 35% of cases.
  Naive majority-vote ensembling made results worse; a reconciliation step that
  evaluates candidate diagnoses against packet evidence reached 0.957 weighted F1 with
  96% auto-accept. Their documented failure modes (invented frames, run-to-run
  flip-flopping, right observation wrong conclusion) informed our acceptance tests.
  Their capture representation (500 to 5,000 tokens) sized our brief format.
- **Abkenar (2025, arXiv:2506.06943)**: I/Q signal classification (RadioML
  2018.01A), not PCAP analysis. We keep its 802.11 pathology taxonomy
  (contention, frame loss, hidden terminal, interference) and its LoRA
  parameter-reduction result. Its headline accuracy numbers are RF-domain and
  must not be cited as PCAP results.

## Practitioner

- **justcallmekoko/ESP32Marauder**: the firmware. The `-serial` sniff flag and
  the `[BUF/BEGIN]`/`[BUF/CLOSE]` buffer markers in `Buffer::saveSerial()` are
  what make live streaming possible on stock firmware.
- **0xchocolate's Flipper Zero Marauder companion app**: the protocol
  inspiration for single-UART PCAP transfer; the mechanism is upstream in
  official firmware since v0.13.7.
- **Lecheeel/esp32-s3-wifi-handshake-sniffer** and **ElectronicCats/marauder-ui-pro**:
  reference designs for store-and-forward wireless offload (management AP,
  capture, HTTP download after). Our wireless transport (the FileServe module,
  see docs/BUILD.md) follows the same pattern, built into the firmware instead
  of alongside it.
