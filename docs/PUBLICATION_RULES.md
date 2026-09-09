# Publication rules

These rules apply to anything that leaves the lab: blog posts, repo examples,
screenshots, dashboards, shared captures, and issue reports.

## Location and telemetry

- Never publish raw GPS coordinates. Not in text, tables, logs, GPX files, or
  image metadata.
- Maps are schematic or relative-only: normalized offsets, no axis values, no
  scale bar tied to real distance, no base map that identifies the area.
- Wardrive and GPS-derived artifacts stay local. Public versions must be
  re-derived from the raw data with coordinates stripped or normalized.
- Do not publish anything that triangulates home, the gym, or any routine
  location: no SSID + location pairings, no "APs visible from my desk" lists
  tied to a place.

## Devices and identifiers

- Third-party MAC addresses are truncated or hashed before publication.
  Lab devices (own APs, own clients) may be shown in full when the owner
  approves.
- Third-party SSIDs may be shown only when they carry no personal information
  and no location linkage. When in doubt, redact.
- Neighbor findings (for example the 83-deauth source) are described by
  pattern, never by identity.

## Captures and handshakes

- Handshake material from own lab APs may be referenced by completeness
  verdict ("crackable material present") but the crackable artifacts
  themselves are not published.
- No passphrase candidates, no hashes, no time-to-crack figures.

## Scope framing

- Every published piece carries the scope note: own devices, own lab, active
  attacks only against own APs, everything else passive reception.
- Educational purpose is stated as a design constraint, not a disclaimer.
