#!/usr/bin/env python3
"""
ndpi_tcp_fp.py - print the nDPI TCP fingerprint of every TCP flow in a pcap.

Implements the nDPI TCP Fingerprint format, draft v0.5:
https://github.com/ntop/nDPI/blob/dev/fingerprint/nDPI_TCP_fingerprint.md

    <tcp_flags>_<ttl_bucket>_<tcp_window>_<options_hash>

The fingerprint is computed once per flow, from the first SYN (ACK clear).
The MSS and the TCP Fast Open state are not part of the fingerprint; they are
printed next to it as informative values.

Pure standard library. Reads classic pcap and pcapng files.

Usage: ndpi_tcp_fp.py capture.pcap [--raw]
       --raw   also print the raw (pre-hash) options string, e.g. 2,4,8,1,3:7
"""
import ipaddress
import struct
import sys


# ---------------------------------------------------------------- fingerprint
# Follows Appendix B (reference implementation) of the specification.

def murmur3_32(data, seed=0):
    """MurmurHash3_x86_32; 4-octet blocks are read little-endian."""
    c1, c2, M = 0xcc9e2d51, 0x1b873593, 0xFFFFFFFF
    rotl = lambda x, r: ((x << r) | (x >> (32 - r))) & M
    h, n = seed, len(data)
    for b in range(0, n - n % 4, 4):
        k = int.from_bytes(data[b:b + 4], "little")
        k = rotl((k * c1) & M, 15) * c2 & M
        h = (rotl(h ^ k, 13) * 5 + 0xe6546b64) & M
    tail = data[n - n % 4:]
    if tail:
        k = int.from_bytes(tail, "little")
        h ^= rotl((k * c1) & M, 15) * c2 & M
    h ^= n
    h ^= h >> 16; h = (h * 0x85ebca6b) & M
    h ^= h >> 13; h = (h * 0xc2b2ae35) & M
    return h ^ (h >> 16)


def ttl_bucket(ttl):
    return 32 if ttl <= 32 else 64 if ttl <= 64 else 128 if ttl <= 128 \
        else 192 if ttl <= 192 else 255


def value_len(kind, opts, i):
    """Value octets to keep for an option (section 7), or -1 to drop it."""
    n = len(opts)
    if kind in (2, 8, 19, 29):            # MSS, Timestamps, TCP-MD5, TCP-AO: kind only
        return 0
    if kind == 30:                        # MPTCP: subtype/version (+ MP_CAPABLE flags)
        return (2 if (opts[i + 2] >> 4) == 0 else 1) if i + 2 < n else 0
    if kind == 34:                        # TCP Fast Open: dropped
        return -1
    if kind in (253, 254):                # RFC 6994: keep the ExID, drop experimental TFO
        if i + 3 < n:
            return -1 if (opts[i + 2], opts[i + 3]) == (0xF9, 0x89) else 2
        return 0
    return 255                            # anything else: all value octets


def parse_options(opts):
    """Serialize the option region. Returns (raw_string, tcp_mss, tcp_fastopen)."""
    toks, mss, tfo, i, n = [], 0, 0, 0, len(opts)
    nop_start, skip_nops = None, False
    while i < n:
        kind = opts[i]
        if kind == 1:                     # NOP
            if skip_nops:                 # padding right after a dropped option
                i += 1
                continue
            if nop_start is None:
                nop_start = len(toks)
            toks.append("1")
            i += 1
            continue
        vl = value_len(kind, opts, i) if kind > 1 else 0
        if vl < 0:                        # dropped option: also drop NOPs before it
            if nop_start is not None:
                del toks[nop_start:]
            skip_nops = True
        else:
            skip_nops = False
        nop_start = None
        if kind == 0:                     # EOL: the rest is padding
            toks.append("0")
            break
        if vl >= 0:
            toks.append("%u" % kind)
        if i + 1 >= n:                    # truncated option
            break
        olen = opts[i + 1]
        if olen == 0:                     # malformed option
            break
        if kind == 2 and olen == 4 and i + 4 <= n:
            mss = int.from_bytes(opts[i + 2:i + 4], "big")
        if vl < 0:                        # TFO: 1 = cookie request, 2 = cookie
            tfo = max(tfo, 2 if olen > (2 if kind == 34 else 4) else 1)
        if olen > 2 and vl > 0:
            toks[-1] += "".join(":%u" % b for b in opts[i + 2:min(i + olen, n)][:vl])
        i += olen
    return ",".join(toks), mss, tfo


def tcp_fingerprint(tcp, ttl):
    """tcp: TCP header + options (+ payload); ttl: IPv4 TTL / IPv6 Hop Limit.
    Returns (fingerprint, raw_options, mss, tfo), or None if the segment does
    not qualify (not a SYN, or SYN+ACK, or a truncated header)."""
    if len(tcp) < 20:
        return None
    flags = int.from_bytes(tcp[12:14], "big") & 0x0FFF
    if not flags & 0x002 or flags & 0x010:          # SYN set, ACK clear
        return None
    doff = (tcp[12] >> 4) * 4
    if doff < 20 or len(tcp) < doff:
        return None
    win = int.from_bytes(tcp[14:16], "big")
    raw, mss, tfo = parse_options(tcp[20:doff])
    oh = "%08x" % murmur3_32(raw.encode("ascii"), 0)
    return "%u_%u_%u_%s" % (flags, ttl_bucket(ttl), win, oh), raw, mss, tfo


# ------------------------------------------------------------ pcap / pcapng

def read_packets(f):
    """Yield (linktype, packet_bytes) from a classic pcap or pcapng stream."""
    magic = f.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        f.seek(0)
        yield from read_pcapng(f)
        return
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        sys.exit("error: not a pcap/pcapng file")
    linktype = struct.unpack(e + "I", f.read(20)[16:20])[0]
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return
        caplen = struct.unpack(e + "I", rec[8:12])[0]
        pkt = f.read(caplen)
        if len(pkt) < caplen:
            return
        yield linktype, pkt


def read_pcapng(f):
    e, ifaces = "<", []
    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            return
        if hdr[:4] == b"\x0a\x0d\x0d\x0a":          # Section Header Block
            e = "<" if f.read(4) == b"\x4d\x3c\x2b\x1a" else ">"
            f.read(struct.unpack(e + "I", hdr[4:8])[0] - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack(e + "II", hdr)
        if blen < 12:
            return
        body = f.read(blen - 12)
        f.read(4)
        if btype == 1:                              # Interface Description Block
            ifaces.append(struct.unpack(e + "H", body[:2])[0])
        elif btype == 6:                            # Enhanced Packet Block
            iface, _, _, caplen = struct.unpack(e + "IIII", body[:16])
            if iface < len(ifaces):
                yield ifaces[iface], body[20:20 + caplen]


def strip_link_layer(linktype, pkt):
    """Return the IP packet inside a link-layer frame, or None."""
    if linktype == 1:                               # Ethernet, with VLAN tags
        off = 12
        et = int.from_bytes(pkt[off:off + 2], "big")
        while et in (0x8100, 0x88A8):
            off += 4
            et = int.from_bytes(pkt[off:off + 2], "big")
        return pkt[off + 2:] if et in (0x0800, 0x86DD) else None
    if linktype == 113:                             # Linux cooked capture
        return pkt[16:]
    if linktype == 276:                             # Linux cooked capture v2
        return pkt[20:]
    if linktype in (0, 108):                        # BSD loopback
        return pkt[4:]
    if linktype in (101, 228, 229):                 # raw IP
        return pkt
    return None


def parse_ip(ip):
    """Return (src, dst, ttl, tcp_bytes) for an unfragmented IP packet that
    carries TCP, else None."""
    if not ip:
        return None
    ver = ip[0] >> 4
    if ver == 4 and len(ip) >= 20:
        ihl = (ip[0] & 15) * 4
        tot = int.from_bytes(ip[2:4], "big") or len(ip)   # 0 = TSO offload
        if ip[9] != 6 or ihl < 20 or int.from_bytes(ip[6:8], "big") & 0x3FFF:
            return None                                   # not TCP, or fragmented
        return ip[12:16], ip[16:20], ip[8], ip[ihl:tot]
    if ver == 6 and len(ip) >= 40:
        nh, off = ip[6], 40
        while nh in (0, 43, 60) and len(ip) >= off + 8:   # skip extension headers
            nh, off = ip[off], off + (ip[off + 1] + 1) * 8
        if nh != 6:                                       # (this drops fragments, too)
            return None
        plen = int.from_bytes(ip[4:6], "big")
        return ip[8:24], ip[24:40], ip[7], ip[off:40 + plen if plen else len(ip)]
    return None


def endpoint(addr, port):
    a = ipaddress.ip_address(addr)
    return ("[%s]:%d" if a.version == 6 else "%s:%d") % (a, port)


# ---------------------------------------------------------------------- main

def main():
    paths = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(paths) != 1:
        sys.exit(__doc__)
    show_raw = "--raw" in sys.argv
    seen = set()                                    # flows already fingerprinted
    with open(paths[0], "rb") as f:
        for linktype, pkt in read_packets(f):
            parsed = parse_ip(strip_link_layer(linktype, pkt))
            if not parsed or len(parsed[3]) < 20:
                continue
            src, dst, ttl, tcp = parsed
            sport = int.from_bytes(tcp[0:2], "big")
            dport = int.from_bytes(tcp[2:4], "big")
            flow = frozenset(((src, sport), (dst, dport)))
            if flow in seen:                        # one fingerprint per flow
                continue
            res = tcp_fingerprint(tcp, ttl)
            if res is None:
                continue
            seen.add(flow)
            fp, raw, mss, tfo = res
            line = "%s -> %s  %s  MSS=%d  TFO=%s" % (
                endpoint(src, sport), endpoint(dst, dport), fp, mss,
                ("none", "cookie request", "cookie")[tfo])
            if show_raw:
                line += "  raw=%s" % raw
            print(line)


if __name__ == "__main__":
    main()
