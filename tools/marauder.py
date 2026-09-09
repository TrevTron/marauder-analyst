#!/usr/bin/env python3
"""marauder.py - serial CLI controller for ESP32 Marauder from the X1S.

Usage:
  python3 marauder.py cmd "ls /"
  python3 marauder.py sniff beacon 60        # timed sniff to SD, auto-stop, verify file
  python3 marauder.py stream raw 60          # live PCAP streamed over serial, saved on X1S
  python3 marauder.py stop                   # persistent stop attempts
  python3 marauder.py ls

Notes from 2026-08-31 bench session:
- CP2102 bridge enumerates as /dev/ttyUSB0, 115200 8N1.
- CLI echoes each command char-by-char with a "#" progress-style redraw; prompts are ">".
- Targeted sniffs (sniffbeacon/sniffprobe) accept stopscan fine.
- sniffraw floods serial with live stats and starves the parser; stopscan may not
  land. Mitigation: send stopscan repeatedly with gaps, watch for stats to halt.
"""
import os, sys, time

PORT = "/dev/ttyUSB0"
BAUD = 115200

def open_port():
    try:
        import serial
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "pyserial is required for Marauder serial access. "
            "Install it with: pip install -r requirements.txt"
        ) from exc
    ser = serial.Serial(PORT, BAUD, timeout=0.2)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    return ser


def parse_seconds(value):
    try:
        seconds = int(value)
    except ValueError as exc:
        raise SystemExit("seconds must be a positive integer") from exc
    if seconds <= 0:
        raise SystemExit("seconds must be a positive integer")
    return seconds

def drain(ser, seconds=1.0):
    """Read whatever comes for N seconds, return decoded text."""
    end = time.time() + seconds
    buf = b""
    while time.time() < end:
        chunk = ser.read(4096)
        if chunk:
            buf += chunk
    return buf.decode(errors="replace")

def cmd(ser, command, wait=3.0):
    ser.reset_input_buffer()
    ser.write(command.encode() + b"\r\n")
    return drain(ser, wait)

def ls_root(ser):
    out = cmd(ser, "ls /", wait=8.0)
    files = {}
    for line in out.replace("\r", "\n").split("\n"):
        line = line.strip().lstrip("#>").strip()
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            files[parts[0]] = int(parts[1])
    return files

def sniff(ser, kind, seconds):
    start_cmds = {"beacon": "sniffbeacon", "probe": "sniffprobe", "raw": "sniffraw", "pmkid": "sniffpmkid -d", "pmkidt": "sniffpmkid -d -l"}
    if kind not in start_cmds:
        raise SystemExit(f"unknown sniff kind: {kind}")
    before = set(ls_root(ser))
    print(f"[+] starting {kind} sniff for {seconds}s")
    print(cmd(ser, start_cmds[kind], wait=3.0).replace("\r", "")[:200])
    time.sleep(seconds)
    # persistent stop: raw floods the parser, so hammer politely
    for attempt in range(10):
        out = cmd(ser, "stopscan", wait=2.0)
        if "Stopping" in out:
            print(f"[+] stopped (attempt {attempt+1})")
            break
        time.sleep(1)
    else:
        print("[!] stopscan not acknowledged after 10 attempts; screen tap may be required")
    time.sleep(2)
    after = ls_root(ser)
    new = {k: v for k, v in after.items() if k not in before}
    print(f"[+] new files: {new if new else 'NONE - check device'}")
    return new

def stream(ser, kind, seconds, outdir=None):
    """Run a sniff with -serial, reassemble BUF segments, save timestamped PCAP."""
    import re, datetime
    start_cmds = {"beacon": "sniffbeacon", "probe": "sniffprobe", "raw": "sniffraw", "pmkid": "sniffpmkid -d", "pmkidt": "sniffpmkid -d -l"}
    if kind not in start_cmds:
        raise SystemExit(f"unknown sniff kind: {kind}")
    outdir = outdir or os.path.expanduser("~/marauder-analyst/captures")
    os.makedirs(outdir, exist_ok=True)
    ser.reset_input_buffer()
    ser.write(start_cmds[kind].encode() + b" -serial\r\n")
    print(f"[+] streaming {kind} for {seconds}s")
    buf = b""
    end = time.time() + seconds
    while time.time() < end:
        chunk = ser.read(8192)
        if chunk:
            buf += chunk
    ser.write(b"stopscan\r\n")
    end = time.time() + 8
    while time.time() < end:
        chunk = ser.read(8192)
        if chunk:
            buf += chunk
    parts = re.findall(rb"\[BUF/BEGIN\](.*?)\[BUF/CLOSE\]", buf, re.DOTALL)
    pcap = b"".join(parts)
    if len(pcap) < 24 or pcap[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        print(f"[!] assembled stream is not a valid PCAP ({len(pcap)} bytes, {len(parts)} segments)")
        return None
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(outdir, f"{kind}_{ts}.pcap")
    with open(path, "wb") as fh:
        fh.write(pcap)
    print(f"[+] saved {path} ({len(pcap)} bytes, {len(parts)} segments)")
    return path

def main():
    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help"}:
        print(__doc__)
        return
    action = sys.argv[1]
    if action == "cmd" and len(sys.argv) < 3:
        raise SystemExit('usage: python3 marauder.py cmd "<marauder command>"')
    if action in {"sniff", "stream"} and len(sys.argv) < 3:
        raise SystemExit(f"usage: python3 marauder.py {action} <beacon|probe|raw|pmkid|pmkidt> [seconds]")
    if action not in {"cmd", "ls", "sniff", "stream", "stop"}:
        raise SystemExit(f"unknown action: {action}\n\n{__doc__}")
    seconds = parse_seconds(sys.argv[3]) if action in {"sniff", "stream"} and len(sys.argv) > 3 else 60
    with open_port() as ser:
        drain(ser, 0.5)
        if action == "cmd":
            print(cmd(ser, " ".join(sys.argv[2:]), wait=6.0).replace("\r", ""))
        elif action == "ls":
            for name, size in ls_root(ser).items():
                print(f"{name}\t{size}")
        elif action == "sniff":
            sniff(ser, sys.argv[2], seconds)
        elif action == "stream":
            stream(ser, sys.argv[2], seconds)
        elif action == "stop":
            for attempt in range(15):
                out = cmd(ser, "stopscan", wait=2.0)
                if "Stopping" in out:
                    print(f"[+] stopped (attempt {attempt+1})")
                    return
                time.sleep(1)
            print("[!] no acknowledgment; tap the screen")

if __name__ == "__main__":
    main()
