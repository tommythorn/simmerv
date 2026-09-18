#!/usr/bin/env python3
"""Drive simmerv-cli's guest console non-interactively.

Usage: drive.py [--timeout S] [--log F] -- <simmerv cmd...> <<'EOF'
expect <regex>
send <text>          # \n appended
sendraw <text>       # no \n
EOF
"""
import argparse, os, re, selectors, subprocess, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--timeout", type=float, default=120.0)
ap.add_argument("--log")
ap.add_argument("cmd", nargs=argparse.REMAINDER)
a = ap.parse_args()
cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd

script = [l.rstrip("\n") for l in sys.stdin if l.strip() and not l.startswith("#")]

p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, bufsize=0)
sel = selectors.DefaultSelector()
sel.register(p.stdout, selectors.EVENT_READ)
buf, logf = "", open(a.log, "w") if a.log else None

def emit(s):
    sys.stdout.write(s); sys.stdout.flush()
    if logf: logf.write(s); logf.flush()

def wait_for(pat, timeout):
    global buf
    rx, end = re.compile(pat), time.time() + timeout
    while time.time() < end:
        if rx.search(buf):
            buf = buf[rx.search(buf).end():]
            return True
        if not sel.select(0.5):
            if p.poll() is not None: return False
            continue
        chunk = os.read(p.stdout.fileno(), 65536)
        if not chunk: return False
        t = chunk.decode("utf-8", "replace")
        buf += t; emit(t)
    return False

rc = 0
try:
    for line in script:
        op, _, arg = line.partition(" ")
        if op == "expect":
            emit(f"\n[drive] expect {arg!r}\n")
            if not wait_for(arg, a.timeout):
                emit(f"\n[drive] TIMEOUT waiting for {arg!r}\n"); rc = 2; break
        elif op in ("send", "sendraw"):
            emit(f"\n[drive] send {arg!r}\n")
            data = arg.encode().decode("unicode_escape").encode("latin-1")
            if op == "send":
                data += b"\n"
            p.stdin.write(data); p.stdin.flush()
        else:
            emit(f"[drive] bad op {op!r}\n"); rc = 3; break
finally:
    # Keep draining until the child exits. Without this the pipe fills and the
    # guest blocks mid-write, which looks exactly like a hang in the workload.
    if p.poll() is None:
        try: p.stdin.close()
        except Exception: pass
        end = time.time() + 120
        while p.poll() is None and time.time() < end:
            if sel.select(0.5):
                chunk = os.read(p.stdout.fileno(), 65536)
                if not chunk: break
                emit(chunk.decode("utf-8", "replace"))
        if p.poll() is None:
            emit("\n[drive] child still running; killing\n"); p.kill()
sys.exit(rc)
