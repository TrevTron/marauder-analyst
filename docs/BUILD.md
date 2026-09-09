# Building Marauder + FileServe from source (v6.1, verified 2026-08-31)

Base: justcallmekoko/ESP32Marauder tag **v1.15.1**, commit
`91724fd8e964cb6f55cd7da60a3320570919de5b`. Clone with
`git clone --recurse-submodules -b v1.15.1 https://github.com/justcallmekoko/ESP32Marauder.git`.
(v1.16.0 shipped 2026-09-08, after this recipe was verified; it has NOT been
tested with this module.)

The wiki's build page is stale for the current master tree. The authoritative
recipe is the CI matrix in `.github/workflows/build_parallel.yml`. This is the
exact setup that produced a working flash on real v6.1 hardware.

## Toolchain

- arduino-cli 1.5.2 (x86_64; the Youyeetoo X1S is an Intel Celeron N5095, not ARM)
- Core: `esp32:esp32@3.3.4`
- FQBN: `esp32:esp32:d32:PartitionScheme=min_spiffs`
- Board flag in `configs.h`: `#define MARAUDER_V6_1`

## Libraries (exact CI pins)

| Library | Version |
| --- | --- |
| NimBLE-Arduino | 2.3.8 |
| ESPAsyncWebServer | ESP32Async v3.8.1 |
| AsyncTCP | v3.4.8 |
| ESP32Ping | 1.6 |
| MicroNMEA | v2.0.6 |
| XPT2046_Touchscreen | v1.4 |
| lv_arduino | 3.0.0 |
| JPEGDecoder | 1.8.0 |
| ArduinoJson | v6.18.2 |
| LinkedList | v1.3.3 |
| EspSoftwareSerial | 8.1.0 (8.2.0 is broken: needs `circular_queue.h` from a deleted upstream repo) |
| Adafruit_BusIO | 1.15.0 |
| Adafruit_MAX1704X | 1.0.2 |
| Adafruit_NeoPixel | 1.12.0 |
| TFT_eSPI | Bodmer V2.5.34 |
| SwitchLib | justcallmekoko master |

Notes:

- The repo's `esp32_marauder/libraries/*` are empty git submodules. Clone with
  `--recurse-submodules` or install the pins above into the sketchbook.
- TFT: copy all repo-root `User_Setup*.h` into the TFT_eSPI folder, keep the
  repo's `User_Setup_Select.h`, and uncomment
  `#include <User_Setup_og_marauder.h>`. (The other CI workflow,
  `build_installer_manifests.yml`, deletes the Select file and uses the generic
  root `User_Setup.h`; that path does NOT build the v6.1 release binaries.)
- platform.txt (3.3.4): prepend `-Wl,-zmuldefs ` to
  `compiler.c.elf.extra_flags=`; replace `-fexceptions` with `-fno-exceptions`
  in every `esp32-arduino-libs/*/cpp_flags`.

## FileServe integration

The FileServe module is vendored in `firmware/filesrv/`, taken from the exact
tree that produced the verified build (base: stock v1.15.1 source):

- `FileServe.cpp` / `FileServe.h` - new files, copy into the sketch folder as-is.
- `CommandLine.cpp` / `CommandLine.h` - stock v1.15.1 files with the `filesrv`
  command registration added. Diff them against upstream v1.15.1 to see the
  touch points, or copy them over the stock files wholesale.

Then compile and upload:

```bash
arduino-cli compile --fqbn esp32:esp32:d32:PartitionScheme=min_spiffs \
  --output-dir build-filesrv ~/Arduino/esp32_marauder
arduino-cli upload --fqbn esp32:esp32:d32:PartitionScheme=min_spiffs \
  -p /dev/ttyUSB0 --input-dir build-filesrv ~/Arduino/esp32_marauder
```

## Safety

- Before flashing: `esptool --chip esp32 --port /dev/ttyUSB0 --baud 460800
  read_flash 0x0 0x400000 stock_flash_backup.bin`
- Keep the stock release `_v6_1.bin` on the SD card; Device > Update Firmware >
  SD Update restores stock in minutes.

## Verified results

- Stock build: 1,710,099 bytes (86% of app partition), boots clean.
- FileServe build: 1,716,087 bytes (87%), boots clean, `filesrv -k <token>`
  starts AP `MarauderFiles` with HTTP on `192.168.4.1:8080`
  (`/health`, `/list`, `/get?file=...`). `filesrv` or `stopscan` stops it.
- Post-flash regression: scanall, list -a, CLI all normal.

## FileServe security: lab-grade, read this before relying on it

FileServe is an experimental owned-lab module, not a security boundary:

- Running `filesrv` without `-k` starts the server with NO key check at all
  (empty key means open access to anyone on the AP).
- The AP password is hardcoded (`marauderfiles`) in CommandLine.cpp. Anyone who
  reads this repo can join the AP. Change it for your own build.
- The key travels as a URL query parameter (`?key=...`), so it appears in
  serial logs and any HTTP intermediary. Treat it as a casual access token,
  not a credential.
- `/list` returns file SIZES, not hashes. "Matches the listing" proves size
  only. If you need integrity, hash the pulled file yourself and compare
  against a hash taken over serial or from a second pull.

For a bench in your own lab this is fine. Do not expose it beyond that.
