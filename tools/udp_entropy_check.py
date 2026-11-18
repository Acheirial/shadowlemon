#!/usr/bin/env python3
"""Audit the first UDP payload of each flow in a pcap capture.

Pure standard library (no scapy). This is the UDP counterpart of
``tools/gfw-search.rs`` (TCP FET exemption rules) and of QDPI ixEngine's
``entropy_score`` as reimplemented in ``/tmp/opencode/qdpi_check.py``.

For every flow (5-tuple by default, source port with ``--by-source-port``) the
first UDP payload is measured for Shannon entropy, printable-byte ratio,
longest printable run, mean popcount and the QDPI-style ``entropy_score``.
High entropy / low printability are the traits a censor uses to flag fully
encrypted traffic; compare a ``before_udp.pcap`` and an ``after_udp.pcap``.
"""

import argparse
import math
import statistics
import struct
import sys
from collections import Counter

# QDPI ixEngine entropy_score lookup table (net4people/bbs#677), identical to
# the one used by qdpi_check.py. Lower scores mean more "normal" traffic;
# QDPI treats scores above ~100 as high-entropy / drop + RST.
SCORE = [
    10000, 9988, 9953, 9898, 9825, 9735, 9631, 9513, 9384, 9246, 9098, 8943, 8781, 8614, 8442, 8266,
    8088, 7907, 7725, 7541, 7358, 7174, 6990, 6808, 6626, 6446, 6268, 6092, 5918, 5747, 5578, 5412,
    5249, 5089, 4932, 4779, 4628, 4481, 4337, 4197, 4060, 3926, 3796, 3669, 3546, 3425, 3309, 3195,
    3084, 2977, 2873, 2772, 2674, 2579, 2487, 2397, 2311, 2227, 2146, 2067, 1991, 1918, 1847, 1778,
    1712, 1648, 1586, 1526, 1468, 1413, 1359, 1307, 1257, 1209, 1162, 1117, 1074, 1032, 992, 953,
    916, 880, 845, 812, 780, 749, 719, 691, 663, 636, 611, 586, 563, 540, 518, 497,
    477, 458, 439, 421, 404, 388, 372, 357, 342, 328, 314, 302, 289, 277, 266, 255,
    244, 234, 224, 215, 206, 197, 189, 181, 174, 166, 159, 153, 146, 140, 134, 128,
    123, 118, 113, 108, 103, 99, 95, 91, 87, 83, 80, 76, 73, 70, 67, 64,
    61, 59, 56, 54, 51, 49, 47, 45, 43, 41, 39, 38, 36, 34, 33, 32,
    30, 29, 28, 26, 25, 24, 23, 22, 21, 20, 19, 18, 18, 17, 16, 15,
    15, 14, 14, 13, 12, 12, 11, 11, 10, 10, 9, 9, 9, 8, 8, 8,
    7, 7, 7, 6, 6, 6, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4,
    3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
]
assert len(SCORE) == 251, len(SCORE)


def _runs(byte):
    bits = [(byte >> (7 - i)) & 1 for i in range(8)]
    return 1 + sum(1 for i in range(1, 8) if bits[i] != bits[i - 1])


RUNS = [_runs(b) for b in range(256)]
ZEROS = [8 - bin(b).count("1") for b in range(256)]


def entropy_score(buf):
    """QDPI ixEngine entropy_score for a byte buffer (0 for empty input)."""
    n = len(buf)
    if n == 0:
        return 0
    bits = n * 8
    nz = nr = 0
    for i, c in enumerate(buf):
        c &= 0xFF
        nz += ZEROS[c]
        nr += RUNS[c]
        if i > 0 and ((c >> 7) == (buf[i - 1] & 1)):
            nr -= 1
    q1 = (nz - bits // 2) ** 2 * 40 // bits
    q2 = nz * (bits - nz) * 4 // bits
    q3 = (q2 - 1) * (q2 - 3) // (bits - 1)
    q4 = (2 * nr - q2 - 1) ** 2 * 10 // (q3 if q3 > 0 else 1)

    mz = mr = 0
    prev = 0xFF
    for c in buf:
        c &= 0xFF
        if (c & 0x80) == 0:
            mz += 1
        if (c & 0x80) != (prev & 0x80):
            mr += 1
        prev = c & 0x80
    q5 = (mz - n // 2) ** 2 * 40 // n
    q6 = mz * (n - mz) * 4 // n
    q7 = (q6 - 1) * (q6 - 3) // (n - 1) if n > 1 else 0
    q8 = (2 * mr - q6 - 1) ** 2 * 10 // (q7 if q7 > 0 else 1)

    s = q1 + q4 + q5 + q8
    return SCORE[s] if s < len(SCORE) else 0


def _u16(data, off):
    return (data[off] << 8) | data[off + 1]


def _classic_pcap_packets(raw):
    """Yield (linktype, frame) records from a classic pcap file."""
    if len(raw) < 24:
        return
    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian = ">"
    else:
        return
    linktype = struct.unpack_from(endian + "I", raw, 20)[0]
    off = 24
    while off + 16 <= len(raw):
        incl = struct.unpack_from(endian + "I", raw, off + 8)[0]
        off += 16
        if incl > len(raw) - off:
            return
        yield linktype, raw[off : off + incl]
        off += incl


def _pcapng_packets(raw):
    """Yield (linktype, frame) records from a pcapng file (EPB / SPB)."""
    endian = None
    if len(raw) >= 12:
        # The SHB byte-order magic sits at offset 8; block type 0x0A0D0D0A is
        # byte-order agnostic, so it cannot be used to detect endianness.
        if raw[8:12] == b"\x4d\x3c\x2b\x1a":
            endian = "<"
        elif raw[8:12] == b"\x1a\x2b\x3c\x4d":
            endian = ">"
    if endian is None:
        return
    u32 = lambda off: struct.unpack_from(endian + "I", raw, off)[0]
    u16 = lambda off: struct.unpack_from(endian + "H", raw, off)[0]
    links = []
    off = 0
    while off + 12 <= len(raw):
        btype = u32(off)
        total = u32(off + 4)
        if total < 12 or off + total > len(raw):
            return
        body = off + 8
        if btype == 0x0A0D0D0A:  # Section Header Block
            links = []
        elif btype == 0x00000001:  # Interface Description Block
            links.append(u16(body))
        elif btype == 0x00000006 and total >= 32:  # Enhanced Packet Block
            iface = u32(body)
            cap_len = u32(body + 12)
            start = body + 20
            if iface < len(links) and cap_len <= off + total - 4 - start:
                yield links[iface], raw[start : start + cap_len]
        elif btype == 0x00000003 and total >= 16:  # Simple Packet Block
            orig = u32(body)
            start = body + 4
            cap_len = min(orig, off + total - 4 - start)
            if links and cap_len > 0:
                yield links[0], raw[start : start + cap_len]
        off += total


def read_packets(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                   b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        yield from _classic_pcap_packets(raw)
    else:
        yield from _pcapng_packets(raw)


def _strip_l2(frame, linktype):
    """Return (ip_packet, ip_version) or None for non-IP frames."""
    if linktype == 1:  # Ethernet (possibly VLAN-tagged)
        if len(frame) < 14:
            return None
        ethertype = _u16(frame, 12)
        off = 14
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype = _u16(frame, 16)
            off = 18
        if ethertype == 0x0800:
            return frame[off:], 4
        if ethertype == 0x86DD:
            return frame[off:], 6
        return None
    if linktype in (101, 12, 228, 229):  # raw IP
        return frame, None
    if linktype == 113:  # LINUX_SLL
        if len(frame) < 16:
            return None
        proto = _u16(frame, 14)
        if proto == 0x0800:
            return frame[16:], 4
        if proto == 0x86DD:
            return frame[16:], 6
        return None
    if linktype == 0:  # NULL / loopback
        if len(frame) < 4:
            return None
        family = struct.unpack_from("<I", frame, 0)[0]
        if family == 2:
            return frame[4:], 4
        if family in (24, 28, 30):
            return frame[4:], 6
        return None
    return None


def udp_datagrams(path):
    """Yield ((src, sport, dst, dport), payload) for every UDP datagram."""
    for linktype, frame in read_packets(path):
        stripped = _strip_l2(frame, linktype)
        if stripped is None:
            continue
        ip, version = stripped
        if not ip:
            continue
        if version is None:
            version = ip[0] >> 4
        if version == 4:
            if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
                continue
            ihl = (ip[0] & 0x0F) * 4
            if ihl < 20 or len(ip) < ihl + 8:
                continue
            if _u16(ip, 6) & 0x1FFF:  # non-initial fragment: no UDP header
                continue
            total = _u16(ip, 2)
            if 0 < total <= len(ip):
                ip = ip[:total]
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])
            l4 = ip[ihl:]
        elif version == 6:
            if len(ip) < 48 or (ip[0] >> 4) != 6 or ip[6] != 17:
                continue
            plen = _u16(ip, 4)
            l4 = ip[40 : 40 + plen] if plen else ip[40:]
            src = struct.unpack_from("!16s", ip, 8)[0].hex()
            dst = struct.unpack_from("!16s", ip, 24)[0].hex()
        else:
            continue
        if len(l4) < 8:
            continue
        sport, dport, udp_len = struct.unpack_from("!HHH", l4, 0)
        if udp_len < 8:
            continue
        payload = l4[8:udp_len] if udp_len <= len(l4) else l4[8:]
        if payload:
            yield (src, sport, dst, dport), bytes(payload)


def first_payloads(path, by_source_port=False):
    """Return {flow_key: first_payload} for the capture at `path`."""
    flows = {}
    for key, payload in udp_datagrams(path):
        flow = key[1] if by_source_port else key
        flows.setdefault(flow, payload)
    return flows


def is_printable(byte):
    return 0x20 <= byte <= 0x7E


def shannon_entropy(buf):
    counts = Counter(buf)
    n = len(buf)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable_ratio(buf):
    return sum(1 for b in buf if is_printable(b)) / len(buf)


def longest_printable_run(buf):
    best = current = 0
    for b in buf:
        current = current + 1 if is_printable(b) else 0
        best = max(best, current)
    return best


def mean_popcount(buf):
    return sum(b.bit_count() for b in buf) / len(buf)


def metrics(payload, limit):
    sample = payload[:limit]
    return {
        "shannon_bits": shannon_entropy(sample),
        "printable_ratio": printable_ratio(sample),
        "printable_run": longest_printable_run(sample),
        "mean_popcount": mean_popcount(sample),
        "qdpi_score": entropy_score(sample),
    }


METRIC_LABELS = [
    ("shannon_bits", "shannon(bits/B)"),
    ("printable_ratio", "printable_ratio"),
    ("printable_run", "printable_run(max)"),
    ("mean_popcount", "mean_popcount"),
    ("qdpi_score", "qdpi_score"),
]


def _summary(values):
    ordered = sorted(values)
    return statistics.fmean(ordered), statistics.median(ordered), ordered[-1]


def report(path, args):
    flows = first_payloads(path, args.by_source_port)
    print(f"== {path}: {len(flows)} UDP flows (first payload each) ==")
    if not flows:
        print("   (no UDP payloads found)")
        return
    rows = [metrics(payload, args.limit) for payload in flows.values()]
    print(f"   {'metric':<20}{'mean':>10}{'median':>10}{'max':>10}")
    for key, label in METRIC_LABELS:
        mean, median, maximum = _summary([row[key] for row in rows])
        if key == "shannon_bits" or key == "mean_popcount":
            print(f"   {label:<20}{mean:>10.3f}{median:>10.3f}{maximum:>10.3f}")
        elif key == "printable_ratio":
            print(f"   {label:<20}{mean:>10.3f}{median:>10.3f}{maximum:>10.3f}")
        else:
            print(f"   {label:<20}{mean:>10.1f}{median:>10.1f}{maximum:>10.1f}")

    total = len(rows)
    checks = [
        (f"shannon >= {args.entropy_threshold}",
         sum(r["shannon_bits"] >= args.entropy_threshold for r in rows)),
        (f"printable_ratio > {args.printable_threshold}",
         sum(r["printable_ratio"] > args.printable_threshold for r in rows)),
        (f"printable_run > {args.run_threshold}",
         sum(r["printable_run"] > args.run_threshold for r in rows)),
        (f"popcount in [{args.popcount_low}, {args.popcount_high}]",
         sum(args.popcount_low <= r["mean_popcount"] <= args.popcount_high for r in rows)),
        (f"qdpi_score > {args.qdpi_threshold}",
         sum(r["qdpi_score"] > args.qdpi_threshold for r in rows)),
    ]
    print("   threshold hits (flows / share):")
    for label, count in checks:
        print(f"   {label:<34}{count:>4}/{total:<4}{count / total:>7.1%}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Measure first-payload entropy/printability of UDP flows in pcap files."
    )
    parser.add_argument("pcap", nargs="+", help="classic pcap or pcapng capture file(s)")
    parser.add_argument("--by-source-port", action="store_true",
                        help="group flows by source port instead of the full 5-tuple")
    parser.add_argument("--limit", type=int, default=256,
                        help="bytes per payload to analyse (default: 256, QDPI processed_bytes_limit)")
    parser.add_argument("--entropy-threshold", type=float, default=7.5,
                        help="Shannon bits/byte considered high entropy (default: 7.5)")
    parser.add_argument("--printable-threshold", type=float, default=0.5,
                        help="printable ratio above which a payload looks plaintext (default: 0.5)")
    parser.add_argument("--run-threshold", type=int, default=20,
                        help="longest printable run considered revealing (default: 20)")
    parser.add_argument("--popcount-low", type=float, default=3.4,
                        help="lower bound of the suspicious mean-popcount band (default: 3.4)")
    parser.add_argument("--popcount-high", type=float, default=4.6,
                        help="upper bound of the suspicious mean-popcount band (default: 4.6)")
    parser.add_argument("--qdpi-threshold", type=int, default=100,
                        help="QDPI entropy_score above which traffic is flagged (default: 100)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.limit <= 0:
        build_parser().error("--limit must be positive")
    for path in args.pcap:
        try:
            report(path, args)
        except OSError as exc:
            print(f"== {path}: {exc} ==", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
