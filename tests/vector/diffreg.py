#!/usr/bin/env python3
"""Explain a differing transcript line: which vector register, scratch byte or
CSR the two simulators disagree about."""
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "tests/vector/out"
want = [int(a) for a in sys.argv[2:]] or None

qemu = open(f"{out}/qemu.txt").read().splitlines()
simm = open(f"{out}/simmerv.txt").read().splitlines()
labels = open(f"{out}/labels.txt").read().splitlines()
CSRS = ["vl", "vtype", "fflags", "vxsat", "vstart"]


def split(line):
    trap = None
    if line.startswith("T"):
        trap, line = line[1:17], line[18:]
    body, *tail = line.split(" ")
    return trap, body, [t for t in tail if t]


for n, (q, s) in enumerate(zip(qemu, simm), start=1):
    if q == s or (want and n not in want):
        continue
    label = labels[n - 1] if n <= len(labels) else f"line {n}"
    qt, qb, qc = split(q)
    st, sb, sc = split(s)
    print(f"\n=== {label}")
    if qt != st:
        print(f"  trap:    qemu={qt or 'none':<16} simmerv={st or 'none'}")
    for name, a, b in zip(CSRS, qc, sc):
        if a != b:
            print(f"  {name}: qemu={a} simmerv={b}")
    # 512 bytes of vector registers, then 256 bytes of scratch memory
    qv, qm = qb[:1024], qb[1024:]
    sv, sm = sb[:1024], sb[1024:]
    for r in range(32):
        a, b = qv[r * 32:(r + 1) * 32], sv[r * 32:(r + 1) * 32]
        if a != b:
            print(f"  v{r:<2} qemu={a}")
            print(f"      sim ={b}")
    for off in range(0, len(qm), 32):
        a, b = qm[off:off + 32], sm[off:off + 32]
        if a != b:
            print(f"  mem[{off // 2:#05x}] qemu={a}")
            print(f"              sim ={b}")
