# nDPI TCP Fingerprint Format

**A Passive, Single-Packet TCP/IP Stack Fingerprint Derived from the Connection-Opening Segment**

**Draft Specification — Version 0.5**


---

## Status of This Memo

This document specifies the **nDPI TCP Fingerprint** (hereafter *TCPFP*), the default TCP fingerprint computed by the `nDPI` deep packet inspection library (`metadata.tcp_fingerprint_format = 0`, symbol `NDPI_NATIVE_TCP_FINGERPRINT`). It describes the format as implemented in `src/lib/ndpi_main.c`, so that third-party producers can generate byte-identical fingerprints and consumers can interpret them. Where the implementation behaves in a non-obvious way on malformed input, that behaviour is documented as normative, because interoperability depends on it.

This revision of the format removes ephemeral options and path-dependent values from the hash, hashes the options with MurmurHash3 instead of a truncated SHA-256, and exports the MSS and the TCP Fast Open state as separate informative values next to the fingerprint. Fingerprints produced by earlier nDPI versions are **not** compatible with it (§15).

> **Implementation status (v0.5).** Implemented in `src/lib/ndpi_main.c` (fingerprint, raw options string, `tcp_mss`, `tcp_fastopen`), `src/lib/ndpi_utils.c` (JSON/TLV export), `src/lib/ndpi_os_fingerprint.c.inc` (OS database), `example/ndpiReader.c` and `wireshark/ndpi.lua`. All of them reproduce the test vectors of Appendix A.

## Copyright and License

Copyright © 2026, ntop. This draft is released under the Creative Commons Attribution 4.0 International (CC BY 4.0). Implementations may use, adapt, and redistribute the format and examples with attribution.

---

## Table of Contents

1. [Terminology and Conventions](#1-terminology-and-conventions)
2. [Scope](#2-scope)
3. [Design Rationale](#3-design-rationale)
4. [Data Model](#4-data-model)
5. [String Format](#5-string-format)
6. [Low-Level Calculation Mechanism](#6-low-level-calculation-mechanism)
7. [Option Value Policy](#7-option-value-policy)
8. [Malformed and Degenerate Input](#8-malformed-and-degenerate-input)
9. [Matching Semantics and OS Inference](#9-matching-semantics-and-os-inference)
10. [Side Effects: Flow Risks](#10-side-effects-flow-risks)
11. [Configuration and Export](#11-configuration-and-export)
12. [Relationship to JA4T and MuonFP](#12-relationship-to-ja4t-and-muonfp)
13. [Stability Considerations](#13-stability-considerations)
14. [Security and Privacy Considerations](#14-security-and-privacy-considerations)
15. [Changes from the Previous Native Format](#15-changes-from-the-previous-native-format)
16. [Conformance Requirements](#16-conformance-requirements)
- [Appendix A — Test Vectors](#appendix-a--test-vectors)
- [Appendix B — Reference Implementation (Python)](#appendix-b--reference-implementation-python)
- [Appendix C — TCP Option Kind Reference (Informative)](#appendix-c--tcp-option-kind-reference-informative)
- [Change Log](#change-log)

---

## Abstract

Different TCP/IP stacks emit visibly different connection-opening segments: they set different flag combinations (ECN negotiation), start from different initial TTLs, advertise different receive windows, and, above all, lay out TCP options in a stack-specific order. **TCPFP** condenses these properties into a short, fixed-structure ASCII string computed from a *single* packet, the first SYN of a flow, with no need for handshake completion, payload, or bidirectional visibility.

The fingerprint is the underscore-separated concatenation of four fields:

```
<tcp_flags>_<ttl_bucket>_<tcp_window>_<options_hash>
```

where `<options_hash>` is the 32-bit MurmurHash3 (seed 0) of a human-readable, comma-separated decimal serialization of the TCP options **in wire order** (e.g. `2,4,8,1,3:7` for Linux). The serialization keeps the option layout (which options are present, their order, the NOP placement) and the option values that are constant for a given stack. It removes every input that is not a property of the sending stack:

- the MSS value (path-dependent);
- the Timestamp value (per connection);
- TCP-MD5 and TCP-AO MACs (per segment);
- MPTCP keys, tokens and nonces (per connection);
- TCP Fast Open, completely, including its NOP padding (per destination);
- everything after the first End-of-Option-List (padding).

The complete list of skipped options and values is in §7.1. Two of them carry useful information that is not a property of the stack, so they are exported **next to** the fingerprint as separate informative values (§11), but never hashed:

- `tcp_mss`, the advertised MSS, which describes the network path (tunnels, VPNs, PPPoE, MSS clamping);
- `tcp_fastopen`, the TCP Fast Open state (none, cookie request, cookie), without the cookie.

This follows the same approach TLSPF applies to ephemeral TLS extensions. The reference implementation is in `nDPI` (`src/lib/ndpi_main.c`, functions `ndpi_init_packet()` and `ndpi_tcp_fp_option_value_len()`). The fingerprint-to-OS database is in `src/lib/ndpi_os_fingerprint.c.inc`, and a Lua port is in `wireshark/ndpi.lua`.

## Normative and Informative References

- **[R1]** ntop, *nDPI — Open Source Deep Packet Inspection Library*: <https://github.com/ntop/nDPI>
- **[R2]** RFC 9293, *Transmission Control Protocol (TCP)*
- **[R3]** RFC 7323, *TCP Extensions for High Performance* (Window Scale, Timestamps)
- **[R4]** RFC 2018, *TCP Selective Acknowledgment Options*
- **[R5]** RFC 3168, *The Addition of Explicit Congestion Notification (ECN) to IP*
- **[R6]** RFC 7413, *TCP Fast Open*
- **[R7]** RFC 6824 / RFC 8684, *TCP Extensions for Multipath Operation with Multiple Addresses* (v0 / v1)
- **[R8]** RFC 2385, *Protection of BGP Sessions via the TCP MD5 Signature Option*
- **[R9]** RFC 5925, *The TCP Authentication Option*
- **[R10]** RFC 6994, *Shared Use of Experimental TCP Options*
- **[R11]** RFC 2119 / RFC 8174, *Key words for use in RFCs to Indicate Requirement Levels*
- **[R12]** A. Appleby, *MurmurHash3* (SMHasher), `MurmurHash3_x86_32`: <https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp>
- **[R13]** MuonFP: <https://github.com/sundruid/muonfp>
- **[R14]** FoxIO, *JA4T: TCP Fingerprinting*: <https://foxio.io/blog/ja4t-tcp-fingerprinting>; JA4+ specifications: <https://github.com/FoxIO-LLC/ja4>

---

## 1. Terminology and Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals, as shown here.

| Term | Definition |
|---|---|
| **Qualifying segment** | A TCP segment with `SYN` set and `ACK` clear (§6.2). |
| **Flag field** | The low 12 bits of the 16-bit big-endian word at TCP header offset 12, i.e. everything after the 4-bit Data Offset: 3 reserved bits, the `AE` (formerly `NS`) bit, then `CWR ECE URG ACK PSH RST SYN FIN`. |
| **Option region** | Bytes `[20, doff*4)` of the TCP header, where `doff` is the Data Offset field. |
| **Option kind** | The first octet of a TCP option (IANA *TCP Option Kind Numbers*). |
| **Option value** | For a TLV option with length octet `L > 2`, the `L − 2` octets following the length octet. |
| **Ephemeral option** | An option whose presence or encoding depends on per-connection or per-destination state rather than on the stack configuration. It is removed from the hash completely, kind octet included (§7.1). |
| **Raw options string** (`R`) | The comma-separated decimal serialization of the option region defined in §6.4, e.g. `2,4,8,1,3:7`. It is the MurmurHash3 input, and can be exported as is (§11). |
| **Option token** | The part of `R` describing one option: `Dec(kind)`, followed by `":" Dec(octet)` for each value octet kept by §7 (e.g. `3:7`, `30:0:129`). Tokens are separated by `,` (§6.4.1). |
| **MurmurHash3** | `MurmurHash3_x86_32` [R12], 32-bit output, seed `0` (§6.5). |
| **Informative value** | A value extracted by the same option pass but exported next to the fingerprint instead of being part of it: `tcp_mss` and `tcp_fastopen` (§11). |
| **TTL bucket** | The observed IPv4 TTL / IPv6 Hop Limit rounded up to one of `{32, 64, 128, 192, 255}` (§6.3). |
| **Dec(x)** | The unsigned decimal encoding of integer `x` with no leading zeros and no sign (`printf("%u")`). |

## 2. Scope

This specification covers:

- the conditions under which a packet is selected for fingerprinting;
- the exact byte-to-string transformation, including the hash input;
- the informative values exported next to the fingerprint;
- behaviour on malformed option encodings;
- how nDPI maps a fingerprint to an operating-system hint and which flow risks are raised during computation.

It does **not** cover the MuonFP format (`metadata.tcp_fingerprint_format = 1`) or FoxIO's JA4T, except for the comparison in §12, nor the nDPI TLS/JA4-derived fingerprints that embed TCPFP as a component.

## 3. Design Rationale

| Field | Why it discriminates | Why it is normalized the way it is |
|---|---|---|
| Flags | ECN-capable stacks send `SYN+ECE+CWR` (RFC 3168 §6.1.1); others send a bare `SYN`. Reserved/`AE` bits expose AccECN-capable or unusual stacks. | Emitted as the numeric 12-bit value, so every bit that the sender controls is retained and no bit is interpreted. |
| TTL | Stacks pick a well-known initial TTL (64 for Linux/macOS/BSD/Android, 128 for Windows, 255 for many network devices). | The observed value has been decremented by the path. Rounding up to the next bucket restores the likely initial value and removes the dependence on hop count. |
| Window | The initial receive window is a tunable, often stack- or version-specific constant (e.g. 64240, 65535, 29200, 8192). | Emitted verbatim. It is **not** multiplied by the window-scale factor, because window scaling does not apply to SYN segments (RFC 7323 §2.2). |
| Options | The option *order*, the `NOP` placement, and constant option values (e.g. the window-scale shift) are the strongest per-stack discriminator. | Hashed to a fixed 32-bit width so the fingerprint stays short and fixed-length regardless of option count. Per-connection, per-segment, per-destination and per-path values are removed (§7). |

**Why the MSS is not a fingerprint field.** The MSS follows from the sender's MTU and the path: 1460 on Ethernet over IPv4, 1440 over IPv6, lower behind tunnels, VPNs, PPPoE or MSS-clamping middleboxes, 65475 over the IPv6 loopback (Appendix A, R11). Putting it in the fingerprint would give the same stack a different fingerprint on every network, which breaks OS lookups, aggregation by fingerprint and "new fingerprint" alerting. Before v0.3, 24 of the 63 distinct entries of the built-in OS database differed from another entry only in the MSS (§15). The MSS is still useful for path analysis, so it is exported as the separate value `tcp_mss` (§11).

**Why TFO is not a fingerprint field.** Whether a SYN carries a TFO option, and in which form, depends on the application and on the client's cookie cache for the destination, not on the stack (Appendix A, R2 vs R3). Its state is exported as `tcp_fastopen` (§11). The cookie itself is never exported (§14).

## 4. Data Model

Given a qualifying segment, the producer extracts:

| Symbol | Source | Width | Use |
|---|---|---|---|
| `F` | `ntohs(*(u16*)&tcp[12]) & 0x0FFF` | 12 bits | Fingerprint. Data Offset nibble masked out. |
| `T` | IPv4 `ttl` or IPv6 `ip6_hlim` | 8 bits | Fingerprint. Bucketed per §6.3 → `T'`. |
| `W` | `ntohs(tcp->window)` | 16 bits | Fingerprint. Unscaled. |
| `O` | Option region, `doff*4 − 20` bytes | 0–40 octets | Fingerprint. Serialized per §6.4 → `R`. |
| `M` | MSS option value (kind 2) | 16 bits | Informative (`tcp_mss`). `0` if absent (§6.4 note 9). |
| `Q` | TCP Fast Open option (kind 34, or kind 253/254 with ExID `0xF989`) | 0, 1, 2 | Informative (`tcp_fastopen`). `0` none, `1` cookie request, `2` cookie (§6.4 note 10). |

## 5. String Format

### 5.1 Grammar (ABNF, RFC 5234)

```
tcpfp        = flags "_" ttl-bucket "_" window "_" options-hash
flags        = 1*4DIGIT          ; Dec(F), 0..4095
ttl-bucket   = "32" / "64" / "128" / "192" / "255"
window       = 1*5DIGIT          ; Dec(W), 0..65535
options-hash = 8LHEXDIG          ; MurmurHash3_x86_32(R, seed 0), lowercase hex
LHEXDIG      = DIGIT / %x61-66   ; 0-9 a-f
```

### 5.2 Properties

- Character set: `[0-9a-f_]`.
- Length: minimum 15 characters (`0_32_0_` + 8), maximum 23 characters (`4095_255_65535_` + 8).
- Exactly three `_` separators; the fourth field is always exactly 8 characters, **including when `R` is empty** (§6.5).
- The decimal fields are **not** zero-padded. `2_64_8192_...` and `002_064_08192_...` are different strings; the latter is non-conformant. The options hash, in contrast, is **always** zero-padded to 8 characters (`%08x`).

### 5.3 Common Flag Values

| `F` | Hex | Bits | Typical sender |
|---|---|---|---|
| `2` | `0x002` | `SYN` | Non-ECN SYN (most clients) |
| `194` | `0x0C2` | `SYN ECE CWR` | ECN-setup SYN (RFC 3168), e.g. recent Windows, macOS/iOS |
| `450` | `0x1C2` | `AE SYN ECE CWR` | AccECN-setup SYN |

## 6. Low-Level Calculation Mechanism

### 6.1 Preconditions

A producer **MUST** compute TCPFP only when all of the following hold:

1. The IP packet is not fragmented and the L4 header is fully present (`transport_len >= 20`).
2. The TCP header is fully captured: `transport_len >= doff*4`.
3. `doff*4 >= 20`. Otherwise the segment is not fingerprinted.
4. No fingerprint has already been recorded for the flow. TCPFP is computed **at most once per flow**, from the first qualifying segment in either direction. Retransmitted SYNs therefore do not overwrite the value. The informative values `M` and `Q` are taken from the same segment.

### 6.2 Segment Selection

```
qualify = (F & SYN (0x002)) != 0  &&  (F & ACK (0x010)) == 0
```

`SYN-ACK` segments are excluded, so on a normally observed flow TCPFP describes the **initiator's** stack. The `ECE`/`CWR` bits of a qualifying SYN are still part of `F`, so ECN negotiation remains part of the fingerprint.

### 6.3 TTL Bucketing

```
T' = 32   if T <=  32
     64   if T <=  64
     128  if T <= 128
     192  if T <= 192
     255  otherwise
```

The comparisons are inclusive upper bounds, evaluated in order. IPv6 uses the Hop Limit with the same table.

### 6.4 Option Serialization

`R`, `M` and `Q` are built by a single left-to-right pass over the option region `O[0..n)`, `n = doff*4 − 20`. `V(k, O, i)` is the value policy of §7: it returns the number of value octets to emit, or `DROP` for an ephemeral option. The cursor `i` **MUST** be at least 16 bits wide (§8.5).

`R` is a list of option tokens, joined with `","` at the end. Each token is the decimal kind, followed by `":"` and the decimal value of each value octet kept by `V`.

```
T = []; M = 0; Q = 0; i = 0; nop_start = NONE; skip_nops = false   # T: list of tokens
while i < n:
    k = O[i]

    if k == 1:                                     # NOP
        if skip_nops: i += 1; continue             # (a) padding after a dropped option
        if nop_start == NONE: nop_start = |T|      # remember start of NOP run
        append "1" to T; i += 1; continue

    v = V(k, O, i) if k != 0 else 0
    if v == DROP:
        if nop_start != NONE: truncate T to nop_start tokens   # (b) padding before a dropped option
        skip_nops = true
    else:
        skip_nops = false
    nop_start = NONE

    if k == 0: append "0" to T; break              # (c) EOL: stop, rest is padding
    if v != DROP: append Dec(k) to T               # (d) dropped options emit nothing
    if i + 1 >= n: break                           # (e) truncated option
    L = O[i+1]
    if L == 0: break                               # (f) malformed: stop
    if k == 2 and L == 4 and i + 4 <= n:           # (g) MSS: value goes to M, not R
        M = (O[i+2] << 8) | O[i+3]
    if v == DROP:                                  # (h) TFO: state goes to Q
        base = 2 if k == 34 else 4                 #     kind 34, or 253/254 + ExID F989
        Q = max(Q, 2 if L > base else 1)
    if L > 2 and v > 0:
        for j in [i+2, min(i+L, n, i+2+v)):        # (i) at most v value octets,
            last token of T += ":" || Dec(O[j])    #     appended to this option's token
    i += L                                         # (j) advance by declared length

R = join(T, ",")                                   # e.g. "2,4,8,1,3:7"
```

Normative notes:

1. **Wire order is preserved.** Options are not sorted, deduplicated, or reordered.
2. **The length octet is never emitted.** Only the kind and the value octets selected by `V` are.
3. **Dropped options leave no trace in `R`.** Neither their kind nor their length is emitted. This is what makes the TFO cookie-request, cookie and absent states produce the same fingerprint.
4. **NOP padding of dropped options.** A run of consecutive NOPs *immediately* preceding a dropped option is removed from `R`, and NOPs *immediately* following it are skipped. Stacks align TFO with NOPs (Linux emits `…,wscale,tfo,nop,nop`), so without this rule a TFO SYN would still differ from a plain SYN. NOPs that are not adjacent to a dropped option are kept, because NOP placement is a stack discriminator (e.g. Windows `mss,nop,ws,nop,nop,sackOK` vs FreeBSD `mss,nop,ws,sackOK,ts`).
5. **EOL terminates.** RFC 9293 defines everything after `EOL` as padding. The first `EOL` contributes the token `0` and parsing stops, so the number of trailing `EOL` octets (which follows from the preceding layout anyway) and any garbage padding do not affect the hash.
6. **Kinds without values.** The kinds of MSS, Timestamps, TCP-MD5 and TCP-AO are emitted, so their position in the option order still counts, but their values are not (§7).
7. **Value octets are clamped to the option region.** If `i + L > n`, only the octets up to `n` are emitted, and the loop then terminates because `i + L >= n`.
8. **Output bound.** An option of `L` octets produces at most `4L − 5` characters plus one separator (kind up to 3 digits, then up to 4 characters `":255"` per value octet), and a NOP or EOL produces 2. With at most 40 option octets, `R` is therefore at most **155 characters** (a single 40-octet option of unknown kind with all values ≥ 100). Producers **MUST** size the buffer for `R` to hold at least 155 characters plus the terminator; the reference implementation uses 192 bytes.
9. **MSS extraction (`M`).** `M` is taken only from a well-formed MSS option (`L == 4`, fully inside the option region) reached by the pass. If several MSS options are present, the last one wins. An MSS option after the first `EOL`, or after the point where parsing stopped (steps e, f), is not seen. A malformed MSS option still contributes its token `2` to `R`, but leaves `M` unchanged.
10. **TFO state (`Q`).** Every dropped option is a TFO option: kind 34 (RFC 7413), or kind 253/254 carrying ExID `0xF989`. Its "empty" length (`base`) is 2 for kind 34 and 4 for the experimental encoding, which also carries the 2-octet ExID. `L <= base` is a cookie request (`Q = 1`), `L > base` carries a cookie (`Q = 2`). If several TFO options are present, the highest state wins. A TFO option without a length octet, or with `L == 0`, is not counted, because parsing stops first. The cookie octets are never copied anywhere.
11. **Encoding.** All numbers are `Dec()`: unsigned decimal, no leading zeros, no padding, no spaces. `","` separates options and `":"` separates a kind from each of its kept value octets, one octet at a time (MPTCP v0 MP_CAPABLE: `30:0:129`). The encoding is unambiguous: every token starts with a kind, so a kind can never be confused with a value octet. This was not the case with the hex encoding of v0.4, where, for example, window scale 0 (`0300`) looked like a window scale option followed by an `EOL`.

### 6.4.1 Reading the Raw Options String

`R` is meant to be read by humans as well as hashed. Its structure is:

- `,` (comma) separates **options**, in wire order. There is exactly one comma-separated token per option that survives §7.
- `:` (colon) separates an option's **kind** from its **kept value octets**. A token is the kind, followed by one `:<octet>` for each value octet that §7 keeps for that option. Each octet is written separately in decimal (0–255).
- A token without `:` is an option whose value is not part of the fingerprint: either it has no value (NOP, EOL, SACK-Permitted), or its value is ephemeral (MSS, Timestamps, TCP-MD5, TCP-AO; §7.1).

Grammar (ABNF, RFC 5234):

```
raw-options = [ token *( "," token ) ]   ; empty when no option survives
token       = kind *( ":" octet )
kind        = dec-octet                  ; TCP option kind
octet       = dec-octet                  ; one kept value octet
dec-octet   = "0" / %x31-39 *2DIGIT      ; 0..255, no leading zeros
```

The first number of a token is therefore always an option kind, and every number after a `:` is always a value octet. Without the colon, Linux would serialize to `2,4,8,1,3,7`, and the window-scale shift `7` would be indistinguishable from an option of kind 7.

Options that can carry `:` values (the kept octets are defined in §7):

| Kind | Option | Token | Example | Meaning of the example |
|---|---|---|---|---|
| 3 | Window Scale | `3:<shift>` | `3:7` | Shift count 7 (Linux); `3:8` is Windows, `3:6` recent Apple stacks, `3:10` Android |
| 5 | SACK | `5:<octet>:…` | — | All block edges; not normally present in a SYN |
| 28 | User Timeout (RFC 5482) | `28:<octet>:<octet>` | `28:129:44` | Granularity bit and 15-bit timeout (`0x812c`: 300 minutes) |
| 30 | MPTCP, MP_CAPABLE | `30:<subtype\|version>:<flags>` | `30:0:129` | Subtype 0 (MP_CAPABLE), version 0; flags `0x81` (checksum required, HMAC-SHA1 per RFC 6824) |
| 30 | MPTCP, MP_JOIN | `30:<subtype\|B>` | `30:16` | Subtype 1 (MP_JOIN), backup bit clear |
| 253, 254 | Experimental (RFC 6994), non-TFO | `<kind>:<ExID high>:<ExID low>` | `254:18:52` | Experiment identifier `0x1234` |
| any other | Unknown kind | `<kind>:<octet>:…` | — | All value octets |

Options that never carry a `:`: EOL (`0`), NOP (`1`), MSS (`2`), SACK-Permitted (`4`), Timestamps (`8`), TCP-MD5 (`19`), TCP-AO (`29`). TFO (kind 34, and 253/254 with ExID `0xF989`) never appears at all.

Multi-octet values are written **one octet at a time**, not as a single integer: the experiment identifier `0x1234` is `254:18:52`, not `254:4660`. This keeps the encoding independent of the meaning of each option, and the same rule works for options of unknown kind and length.

Examples from Appendix A:

| `R` | Reading |
|---|---|
| `2,4,8,1,3:7` | MSS, SACK-Permitted, Timestamps, NOP, Window Scale 7 (Linux, R1) |
| `2,4,8,1,3:10` | Same layout, Window Scale 10 (Android, R2/R3) |
| `2,1,3:6,1,1,8,4,0` | MSS, NOP, Window Scale 6, NOP, NOP, Timestamps, SACK-Permitted, EOL (Apple release 27, R5–R8) |
| `2,1,3:8,1,1,4` | MSS, NOP, Window Scale 8, NOP, NOP, SACK-Permitted (Windows 10/11, R10–R12) |
| `2,1,3:6,4,8` | MSS, NOP, Window Scale 6, SACK-Permitted, Timestamps (FreeBSD 15, R4) |
| `2,4,8,1,3:7,30:0:129` | Linux layout followed by MPTCP v0 MP_CAPABLE with flags `0x81` (vector 5) |
| `2,19,1,1` | MSS, TCP-MD5, NOP, NOP (BGP session, vector 8) |
| `2` | MSS only: the experimental TFO option and its padding were dropped (vector 9) |

### 6.5 Hash

```
h   = MurmurHash3_x86_32( ASCII(R), len = |R|, seed = 0 )   # input is the TEXT of R, no NUL
oh  = sprintf("%08x", h)                                     # 32 bits, 8 chars
```

The hash input is the **ASCII text of `R`**, commas and colons included, not the raw option bytes. For example, `R = "2,4,8,1,3:7"` is hashed as the 11 octets `0x32 0x2c 0x34 0x2c …`.

Interoperability requirements for the hash:

- The variant is **`MurmurHash3_x86_32`**. `MurmurHash3_x86_128` and `MurmurHash3_x64_128` produce different values, even when truncated, and **MUST NOT** be used.
- The seed is **`0`**.
- The 4-octet blocks of the input are read as **little-endian** 32-bit integers, independently of the host byte order. This is the canonical algorithm. A C implementation that casts the input to `uint32_t *` (as the SMHasher reference does) is correct on little-endian hosts only, and **MUST** byte-swap the blocks on big-endian hosts. nDPI's `MurmurHash()` assembles each block byte by byte, so it is host-independent.
- The 32-bit result `h` is printed as an unsigned number, most significant nibble first, zero-padded to 8 lowercase hex characters. It is **not** the hex dump of `h` in memory order.

Known-answer tests: `MurmurHash3_x86_32("", 0) = 00000000`, `MurmurHash3_x86_32("hello", 0) = 248bfa47`.

When `R` is empty, `oh = 00000000`.

nDPI already ships the function as `MurmurHash()` (`src/lib/third_party/src/hll/MurmurHash3.c`, used by the HyperLogLog and filter code), so no additional dependency is needed. The Wireshark Lua port no longer needs a SHA-256 implementation.

### 6.6 Assembly

```
TCPFP = Dec(F) || "_" || Dec(T') || "_" || Dec(W) || "_" || oh
```

`M` and `Q` are not part of `TCPFP`. They are exported separately (§11).

### 6.7 Worked Example (Linux)

SYN, IPv4 TTL 64, window 64240, options (20 octets):

```
02 04 05 b4                    MSS = 1460
04 02                          SACK-Permitted
08 0a 2d 79 a0 50 00 00 00 00  Timestamp (TSval, TSecr=0)
01                             NOP
03 03 07                       Window Scale, shift = 7
```

| Step | Option | `V` | Emitted into `R` | Informative |
|---|---|---|---|---|
| 1 | `02 04 05b4` | 0 | `2` | `M = 1460` |
| 2 | `04 02` | 255 (no value) | `4` | |
| 3 | `08 0a …` | 0 | `8` | |
| 4 | `01` | — | `1` | |
| 5 | `03 03 07` | 255 | `3:7` | |

```
R     = "2,4,8,1,3:7"
h     = MurmurHash3_x86_32("2,4,8,1,3:7", 0) = 0x789c1d1f
TCPFP = 2_64_64240_789c1d1f          tcp_mss = 1460, tcp_fastopen = 0
```

This is the SYN of `tests/pcap/fp_tcp_linux_ubuntu24.pcap` (Ubuntu 24, vector R1 in Appendix A). The same stack over IPv6 (MSS 1440, window 64800) produces `2_64_64800_789c1d1f` with `tcp_mss = 1440`: only the window differs in the fingerprint.

## 7. Option Value Policy

`V(k, O, i)` (`ndpi_tcp_fp_option_value_len()` in the reference implementation):

| Kind `k` | `V` | Rationale |
|---|---|---|
| 0 (EOL), 1 (NOP) | — | Handled by the serializer (§6.4) |
| 2 (MSS) | 0 | Path-dependent: MTU, IPv4 vs IPv6, VPNs, MSS clamping. Exported as `tcp_mss` |
| 8 (Timestamps) | 0 | Per-connection clock (`TSval`) and echo (`TSecr`) |
| 19 (TCP-MD5) | 0 | Per-segment digest |
| 29 (TCP-AO) | 0 | Per-segment MAC |
| 30 (MPTCP) | `2` if `O[i+2] >> 4 == 0` (MP_CAPABLE), else `1`; `0` if `i+2 >= n` | Keep subtype, version and the MP_CAPABLE flags (e.g. the HMAC algorithm); drop keys, tokens, nonces and address IDs |
| 34 (TCP Fast Open) | `DROP` | Per-server cookie; presence depends on the cookie cache and on the application. State exported as `tcp_fastopen` |
| 253, 254 (RFC 6994) | `DROP` if `O[i+2..i+3] == F9 89` (experimental TFO), else `2`; `0` if `i+3 >= n` | Keep the ExID, drop the experiment data |
| any other | all (255) | Assumed to be a stack constant (e.g. the Window Scale shift, the User Timeout) |

MPTCP value layouts relevant to `V`:

| Subtype in SYN | Value octets | Kept | Dropped |
|---|---|---|---|
| MP_CAPABLE v0 (RFC 6824), `L = 12` | `subtype\|ver`, `flags`, 8-octet key | first 2 | key |
| MP_CAPABLE v1 (RFC 8684), `L = 4` | `subtype\|ver`, `flags` | all | — |
| MP_JOIN, `L = 12` | `subtype\|B`, address ID, token, nonce | first 1 | address ID, token, nonce |

The MSS value is excluded from `R` only. It is still parsed, exported as `tcp_mss`, and used by the scanner heuristics of §10 and by the MuonFP format.

### 7.1 Ephemeral Options and Values Skipped by the Options Hash

The following inputs are skipped when computing `R`, and therefore `<options_hash>`. "Fully dropped" means that neither the kind, the length nor the value is emitted, and that adjacent NOP padding is removed as well (§6.4 note 4). "Value skipped" means that the kind is still emitted, so the option's position in the layout still counts. The last column says whether the skipped information is exported as an informative value (§11).

| Kind | Option | Treatment | What is skipped | Why it is ephemeral | Exported separately |
|---|---|---|---|---|---|
| 34 | TCP Fast Open Cookie (RFC 7413) | **Fully dropped** | Kind, length, cookie (or empty cookie request), adjacent NOPs | Cookie is per server; presence depends on the client cookie cache and on whether the application uses TFO | **State only**, as `tcp_fastopen`. Never the cookie |
| 253, 254 | Experimental TFO (RFC 6994, ExID `0xF989`) | **Fully dropped** | Kind, length, ExID, cookie, adjacent NOPs | Pre-standard encoding of TFO; same reasons as kind 34 | **State only**, as `tcp_fastopen`. Never the cookie |
| 2 | Maximum Segment Size | Value skipped | 2-octet MSS value | Path-dependent (MTU, IPv4/IPv6, tunnels, clamping) | **Yes**, as `tcp_mss` |
| 8 | Timestamps (RFC 7323) | Value skipped | `TSval`, `TSecr` | Per-connection clock | No: would enable uptime and clock-skew tracking (§14) |
| 19 | TCP MD5 Signature (RFC 2385) | Value skipped | 16-octet digest | Per segment | No: no meaning on its own |
| 29 | TCP Authentication Option (RFC 5925) | Value skipped | KeyID, RNextKeyID, MAC | Per segment | No: no meaning on its own |
| 30 | Multipath TCP (RFC 6824 / RFC 8684) | Value partly skipped | MP_CAPABLE v0 key; MP_JOIN address ID, token, nonce | Per connection. Subtype, version and MP_CAPABLE flags are kept | No: the v0 key is session key material (§14) |
| 253, 254 | Other experimental options (RFC 6994) | Value partly skipped | Experiment data after the 2-octet ExID | Unknown semantics. The ExID identifies the experiment and is kept | No |
| 0 | End of Option List | Trailing octets skipped | Everything after the first EOL | Padding (RFC 9293) | No |

All other option kinds, including Window Scale (3), SACK-Permitted (4), User Timeout (28) and unknown kinds, are hashed with their full value, because they are assumed to be stack constants.

The presence of Timestamps, TCP-MD5, TCP-AO and MPTCP does not need a separate value: their kinds are in `R`, which can be exported with `metadata.tcp_fingerprint_raw` (§11). TFO is the only option that leaves no trace in `R`, which is why its state gets its own value.

## 8. Malformed and Degenerate Input

A conformant producer **MUST** reproduce the following behaviours exactly, because they determine the fingerprint of crafted packets, which are the most interesting ones from a security standpoint.

### 8.1 Truncated option (no length octet)

A non-`EOL`/`NOP` kind in the last octet of the region: the kind is emitted (unless dropped), then parsing stops (§6.4 step e).

### 8.2 Zero length octet (`L == 0`)

The kind is emitted (unless dropped), then parsing stops (§6.4 step f).

### 8.3 Oversized declared length

`L` larger than the remaining region: value octets are emitted up to the region end (§6.4 note 7), and the loop then ends.

### 8.4 Garbage after EOL

Ignored (§6.4 note 5).

### 8.5 Cursor width

`i + L` can exceed 255 (`i ≤ 39`, `L ≤ 255`). The cursor **MUST NOT** wrap: `i + L >= n` ends the loop. With an 8-bit cursor, a crafted sequence of dropped options (e.g. `22 03 xx 22 fd …`) wraps `i` back to 0. Dropped options emit nothing, so the output bound can never stop the loop, and the parser loops forever.

### 8.6 Empty option region / empty `R`

An empty option region gives `R = ""`, `oh = 00000000`, `M = 0`, `Q = 0`, and raises the flow risk of §10. `R` can also be empty for a non-empty option region (e.g. only TFO). That produces the same `oh` but does **not** raise the "Massive scanner" risk, which is based on the option region length.

## 9. Matching Semantics and OS Inference

- TCPFP values are compared by **exact, case-sensitive string equality**. The format has no partial or per-field matching semantics. Consumers that want to match on a subset of fields (e.g. ignore the window) **MUST** split on `_` and compare fields individually.
- The informative values `tcp_mss` and `tcp_fastopen` are **not** part of the match. They do not affect the OS hint.
- After computing TCPFP, nDPI looks it up in a hash table (`ndpi_get_os_from_tcp_fingerprint()`) and stores the result in `flow->metadata.l4.tcp.os_hint` as an `ndpi_os` value:

  | `ndpi_os` | Value | `ndpiReader` label |
  |---|---|---|
  | `ndpi_os_unknown` | 0 | `Unknown` |
  | `ndpi_os_windows` | 1 | `Windows` |
  | `ndpi_os_apple` | 2 | `macOS/iOS/iPad` |
  | `ndpi_os_android` | 3 | `Android` |
  | `ndpi_os_linux` | 4 | `Linux` |
  | `ndpi_os_freebsd` | 5 | `FreeBSD` |

- At initialization, `ndpi_load_tcp_fingerprints()` seeds the table with the built-in list `tcp_fps[]` (`src/lib/ndpi_os_fingerprint.c.inc`) when the native format is configured. No built-in list is loaded for MuonFP. Each built-in entry is annotated with its raw options string `R`. The table can be extended at run time with `ndpi_add_tcp_fingerprint()` or `ndpi_load_tcp_fingerprint_file()`. The file format is one entry per line:

  ```
  # comment
  <TCPFP>,<numeric ndpi_os>
  2_64_64240_789c1d1f,4
  2_64_65535_58b6a464,3
  ```

  Duplicate fingerprints are rejected (first insertion wins), and OS values `>= ndpi_os_MAX_OS` are ignored.
- The mapping is many-to-one, and a fingerprint may legitimately match multiple OS families. For example, `2_64_65535_e76f0f14` is shared by iOS 18/27 (Appendix A, R7, R8), and the same options hash with `F = 194` by macOS 27 and iPadOS 27 (R5, R6). The OS hint is a **hint**, not an identification.

## 10. Side Effects: Flow Risks

While computing TCPFP, nDPI raises `NDPI_MALICIOUS_FINGERPRINT` in two cases:

| Condition | Risk message | Rationale |
|---|---|---|
| Option region empty (`doff == 5`) | `Massive scanner detected (probably masscan)` if `W == 1024`; `… (probably zmap)` if `W == 65535`; otherwise `Massive scanner detected` | Stateless scanners craft minimal SYNs with no options. Every mainstream stack sends at least MSS. |
| Option region is exactly 4 octets **and** an MSS option with a non-zero value was parsed, **and** the source is IPv6 or a public IPv4 address | `Unusual TCP fingerprint (scanner detected?)` | MSS-only SYNs are typical of scanners (e.g. `nmap -sS`). Private IPv4 sources are exempt to avoid false positives from legacy or embedded devices. |

These risks are independent of the fingerprint string and do not alter it.

## 11. Configuration and Export

| Parameter | Default | Effect |
|---|---|---|
| `metadata.tcp_fingerprint` | `enable` | Master switch. When disabled, no TCP fingerprint and no informative value is computed. |
| `metadata.tcp_fingerprint_format` | `0` | `0` = TCPFP (this document), `1` = MuonFP. |
| `metadata.tcp_fingerprint_raw` | `disable` | Also export `R` (the pre-hash raw options string, e.g. `2,4,8,1,3:7`) when `|R| > 0`. |
| `metadata.ndpi_fingerprint_ignore_tcp_fp` | `disable` | When disabled, TCPFP is used as the L4 component of the composite nDPI client fingerprint. |

Exported fields:

| Value | C API (`flow->metadata.l4.tcp.`) | JSON/TLV | Notes |
|---|---|---|---|
| Fingerprint | `fingerprint` | `"tcp_fingerprint"` | §5 |
| Raw options string | `fingerprint_raw` | `"tcp_fingerprint_raw"` | Only with `metadata.tcp_fingerprint_raw` |
| OS hint | `os_hint` | — | §9 |
| MSS | `mss` (`u_int16_t`) | `"tcp_mss"` | `M`; `0` = no MSS option |
| TCP Fast Open state | `fastopen` (`u_int8_t`) | `"tcp_fastopen"` | `Q`; `0` = none, `1` = cookie request, `2` = cookie |

`tcp_mss` and `tcp_fastopen` are informative values. They:

- are extracted from the same segment and by the same option pass as the fingerprint (§6.4), at no extra cost;
- are exported whenever a TCP fingerprint is computed, independently of `metadata.tcp_fingerprint_format`, with no separate configuration switch, since they carry no identifying data (§14);
- describe the client SYN only;
- **MUST NOT** be used to derive the OS hint.

Other outputs:

- `ndpiReader`: `[TCP Fingerprint: <TCPFP>/<OS>][MSS: <M>]`, followed by `[TFO: cookie request]` or `[TFO: cookie]` when `Q != 0`, e.g. `[TCP Fingerprint: 2_64_65535_58b6a464/Android][MSS: 1212][TFO: cookie request]`.
- Wireshark (`wireshark/ndpi.lua`): fields `ntop.tcp_fingerprint`, `ntop.tcp_mss` and `ntop.tcp_fastopen`.

Exporting `R` is **RECOMMENDED** when building or auditing fingerprint databases, because it makes hash collisions directly visible and allows the database to be recomputed if the format changes. Because `R` is comma-separated decimal, it can be read directly: `2,1,3:8,1,1,4` is MSS, NOP, window scale 8, NOP, NOP, SACK-Permitted (Windows).

## 12. Relationship to JA4T and MuonFP

### 12.1 JA4T

JA4T is FoxIO's TCP client fingerprint, part of the JA4+ suite [R14]. Like TCPFP, it is computed passively from the client SYN. It is a human-readable string of four `_`-separated fields:

```
JA4T = <window>_<option kinds, "-" separated, in wire order>_<MSS>_<window scale>
```

The JA4+ suite also defines two related fingerprints:
- **JA4TS**, the same format computed on the server SYN-ACK;
- **JA4TScan**, an active variant that also records the server's SYN-ACK retransmission timing.

Applying the JA4T rules to the vectors of Appendix A gives:

| Vector | JA4T | TCPFP | `tcp_mss` / `tcp_fastopen` |
|---|---|---|---|
| 1 Linux, IPv4 | `64240_2-4-8-1-3_1460_7` | `2_64_64240_789c1d1f` | 1460 / 0 |
| 2 Linux, IPv6 | `64800_2-4-8-1-3_1440_7` | `2_64_64800_789c1d1f` | 1440 / 0 |
| 3 Linux + TFO cookie request | `64240_2-4-8-1-3-34-1-1_1460_7` | `2_64_64240_789c1d1f` | 1460 / 1 |
| 5 Linux + MPTCP | `64240_2-4-8-1-3-30_1460_7` | `2_64_64240_1d00dd35` | 1460 / 0 |
| 6 Darwin | `65535_2-1-3-1-1-8-4-0-0_1460_5` | `2_64_65535_2b6d3038` | 1460 / 0 |
| 7 Darwin, ECN SYN, 7 hops | `65535_2-1-3-1-1-8-4-0-0_1460_5` | `194_64_65535_2b6d3038` | 1460 / 0 |
| R2 Android 13 (capture) | `65535_2-4-8-1-3-34-1-1_1212_10` | `2_64_65535_58b6a464` | 1212 / 1 |
| R3 Android 16 (capture) | `65535_2-4-8-1-3_1460_10` | `2_64_65535_58b6a464` | 1460 / 0 |
| R7 iOS 27 (capture) | `65535_2-1-3-1-1-8-4-0-0_1460_6` | `2_64_65535_e76f0f14` | 1460 / 0 |
| R6 iPadOS 27 (capture) | `65535_2-1-3-1-1-8-4-0-0_1460_6` | `194_64_65535_e76f0f14` | 1460 / 0 |
| R11 Windows 11, IPv6 loopback (capture) | `65535_2-1-3-1-1-4_65475_8` | `2_128_65535_47466ece` | 65475 / 0 |
| R12 Windows 11, IPv4 (capture) | `65535_2-1-3-1-1-4_1460_8` | `2_128_65535_47466ece` | 1460 / 0 |

The two fingerprints start from the same observation: window, option layout and a few option values identify a TCP/IP stack. They make different trade-offs:

| Aspect | JA4T | TCPFP |
|---|---|---|
| Packet | Client SYN (JA4TS: server SYN-ACK) | Client SYN only |
| Representation | Clear text, variable length | `flags_ttl_win` in clear + 32-bit hash of the options, fixed layout |
| TCP flags (ECN negotiation) | Not included | Included (`F`) |
| Initial TTL | Not included | Included, bucketed (§6.3) |
| Window | Included | Included |
| Option kinds and order | Included, all kinds | Included; ephemeral kinds (TFO, experimental TFO) and their NOP padding removed; stops at the first EOL |
| MSS value | Included | **Excluded**; exported separately as `tcp_mss` |
| TFO | Included as kind 34 | **Excluded**; state exported separately as `tcp_fastopen` |
| Window-scale shift | Included | Included (inside the hash) |
| Other option values (MPTCP version and flags, RFC 6994 ExID, unknown options) | Not included | Included (inside the hash) |
| Partial matching | Natural: fields and option lists can be compared or wildcarded directly | Only on `flags`, `ttl` and `window`; option-level matching needs the raw string `R` (§11) |
| Active variant | JA4TScan (retransmission timing) | None; TCPFP is passive only |

**The main design difference is MSS.** JA4T keeps the MSS in the fingerprint on purpose. An MSS below what the link MTU would allow (e.g. 1460 minus tunnel overhead) reveals VPNs, tunnels and proxies on the path, and FoxIO presents this as a JA4T use case. TCPFP removes the MSS from the fingerprint so that one stack yields one fingerprint regardless of path, and exports it as `tcp_mss` so that the path information is not lost. R11 and R12, the same Windows 11 host over the IPv6 loopback and over IPv4, have different JA4T strings but the same TCPFP. TCPFP is therefore the better key for stack/OS identification and database lookups. For path analysis, TCPFP plus `tcp_mss` carries the same information as JA4T.

**TCPFP sees more of the stack in two respects:**
- **Flags and TTL.** Vectors 6 and 7, and the captures R6 and R7, have the same JA4T, but TCPFP separates them (`2` vs `194`). ECN negotiation and the initial TTL (64 vs 128 vs 255) are strong OS discriminators that JA4T leaves out.
- **Option values beyond MSS and WS.** TCPFP hashes the MPTCP version and flags, the RFC 6994 ExIDs and the values of unknown options. JA4T records these options only by their kind.

**TFO.** JA4T includes TFO in the option list, which makes the JA4T of a client depend on whether it has a TFO cookie for the server, or uses TFO at all. The captures R2 and R3 show this on real devices: the two Android releases have different JA4T option lists only because Android 13 requested a TFO cookie, while their TCPFP is identical. It is the same session-state drift TLSFP removes for TLS, and TCPFP removes it for TCP (§13). The information is still available as `tcp_fastopen`. JA4T also lists every trailing EOL (`…-0-0`), which follows from the option layout and adds no information.

**Readability vs compactness.** JA4T can be read and matched by eye; the TCPFP options hash cannot. The raw string `R` closes most of the gap: `2,4,8,1,3:7` reads like the JA4T option list `2-4-8-1-3` and also shows the kept option values. On the other hand, TCPFP has a fixed, bounded layout that suits hash-table lookups (`ndpi_get_os_from_tcp_fingerprint()`) and flow export.

**Licensing.** At the time of writing, FoxIO publishes JA4 (TLS client) under the BSD 3-Clause license and the other JA4+ methods, including JA4T, under the FoxIO License 1.1, which restricts some commercial uses. Check FoxIO's current terms before embedding JA4T. TCPFP is specified under CC BY 4.0 (this document) and implemented in nDPI under the LGPLv3.

### 12.2 MuonFP

MuonFP (`metadata.tcp_fingerprint_format = 1`) carries essentially the same information as JA4T: window, option kinds, MSS and window scale, in clear text with `:` as the separator (e.g. `64240:2-4-8-1-3:1460:7`). nDPI users who need a JA4T-style fingerprint can therefore use format 1, which differs from JA4T mainly in field separators and in how an absent MSS or window scale is encoded. It is computed by the same parser pass as TCPFP:

| Aspect | TCPFP (format 0) | MuonFP (format 1) |
|---|---|---|
| Layout | `flags_ttl_win_hash8` | `win:kinds:mss:wscale` |
| Flags / TTL | Included | Not included |
| Option kinds | In order, hashed; ephemeral kinds removed; stops at EOL | In order, in clear; all kinds |
| Option values | Only stack constants (WS shift, MPTCP version, unknown options) | MSS and WS shift, in clear |
| MSS | Not in the fingerprint; exported as `tcp_mss` | In clear (empty if absent) |
| Length | Fixed-width last field | Variable |
| Human-readable | No | Yes |

The two formats share segment selection (`SYN` without `ACK`), the zero-length-option rule (§8.2) and the 16-bit cursor (§8.5). `tcp_mss` and `tcp_fastopen` are exported with both formats.

## 13. Stability Considerations

| Source of drift | Handled | Notes |
|---|---|---|
| MSS clamping, IPv4 vs IPv6 MSS, tunnels, loopback | Yes | MSS not in the fingerprint; visible in `tcp_mss` (Appendix A, R11 vs R12) |
| TCP Fast Open (request / cookie / absent) | Yes | TFO and its NOP padding removed; visible in `tcp_fastopen` (R2 vs R3) |
| MPTCP keys, tokens, nonces | Yes | Version and flags kept |
| TCP-MD5 / TCP-AO | Yes | MAC not hashed |
| Trailing EOL count / garbage padding | Yes | Parsing stops at the first EOL |
| Window tied to MSS (Linux uses the largest multiple of MSS ≤ 65535: 64240 = 44×1460, 64800 = 45×1440) | Partially | The options hash is identical, but the window field differs |
| TTL near a bucket edge | No | Rare in practice |
| Middlebox ECN bleaching (`ECE/CWR` cleared) | No | `F` flips between `194` and `2` |
| ECN setup varying within an OS family (Apple) | No | Devices of the same release are seen with `F = 194` and `F = 2` (R6 vs R7); a database needs both entries |
| Presence of MPTCP (application-dependent on iOS) | No | Kept on purpose as a stack signal |

Because the window is usually still stack-specific, consumers that need to match across IPv4 and IPv6 **MAY** match on the flags, TTL and options-hash fields only.

## 14. Security and Privacy Considerations

- **Spoofability.** Every TCPFP input is sender-controlled, so a crafted SYN can impersonate any fingerprint. TCPFP **MUST NOT** be used as an authentication signal.
- **Non-cryptographic hash.** MurmurHash3 is not collision resistant: an attacker can construct an `R` with a chosen hash value cheaply. This does not weaken TCPFP, because every input is already sender-controlled, and the simplest way to produce a target fingerprint is to copy the target's options, which no hash can prevent. Accidental collisions are bounded by the 32-bit width: with `N` distinct option layouts, the probability of at least one collision is about `N² / 2^33`, i.e. about 0.01% for 1,000 layouts and about 1% for 10,000. Real-world databases contain a few hundred distinct layouts. Exporting `R` (§11) makes any collision directly visible.
- **Evasion.** MSS, TFO and MAC perturbation do not change TCPFP. Unknown option values are still hashed, so a tool can change its TCPFP by adding or altering one. A tool can also pad a SYN with TFO options, which are removed, without changing its fingerprint; `tcp_fastopen` makes this visible. Detection logic **SHOULD** combine TCPFP with the structural risks of §10, with `tcp_mss` and, where available, with the raw string `R`.
- **Parser safety.** The parser reads only within the option region and writes only within the fixed output buffer. With a 16-bit cursor (§8.5), crafted `L == 0` or oversized `L` values cannot cause out-of-bounds access or non-termination.
- **Privacy.** TCPFP identifies a TCP/IP **stack configuration**, not an individual. The values that could link connections from the same host are excluded from the hash, from `R` and from the informative values:
  - **Timestamps** (`TSval`/`TSecr`): they expose the sender's clock, which allows uptime and clock-skew estimation and counting hosts behind a NAT.
  - **TFO cookies**: a cookie is an identifier for a client-server pair. Only the state is exported. `tcp_fastopen = 2` still reveals that the client has contacted the server before.
  - **MPTCP keys**: the MP_CAPABLE v0 key is the session secret from which tokens and HMACs are derived, so exporting it would leak security material.

  `tcp_mss` reveals the path MTU class of the client (e.g. VPN or PPPoE use), which is the purpose of exporting it.

## 15. Changes from the Previous Native Format

nDPI has used three native fingerprint layouts. **Fingerprints of different layouts are not comparable**, and databases built with earlier versions (including custom files loaded with `ndpi_load_tcp_fingerprint_file()`) **MUST** be regenerated.

| Aspect | Legacy native (before v0.3) | v0.3–v0.4 | Current (v0.5) |
|---|---|---|---|
| Layout | `flags_ttl_win_hash12` | `flags_ttl_win_hash12` | `flags_ttl_win_hash8` |
| Raw options string `R` | Hex | Hex, e.g. `020408010307` | Comma-separated decimal, e.g. `2,4,8,1,3:7` |
| Hash | SHA-256 of `R`, first 6 octets | SHA-256 of `R`, first 6 octets | MurmurHash3_x86_32 of `R`, seed 0 |
| Segment selection | `SYN`, `ECE` or `CWR` set, `ACK` clear | `SYN` set, `ACK` clear | `SYN` set, `ACK` clear |
| MSS | Kind + value in the hash | Kind only in the hash; value discarded | Kind only in the hash; value exported as `tcp_mss` |
| TCP Fast Open | Kind + cookie | Removed with its NOP padding | Removed with its NOP padding; state exported as `tcp_fastopen` |
| TCP-MD5, TCP-AO, MPTCP, experimental options | Kind + full value | Per §7 | Per §7 |
| EOL | Parsing continued after it | Parsing stops | Parsing stops |
| `L == 0` | Kind re-emitted until the 128-byte buffer filled | Stop | Stop |
| Cursor | 8-bit (could wrap) | 16-bit | 16-bit |

v0.5 keeps the same options and values in `R` as v0.3–v0.4, but encodes them as comma-separated decimal tokens and hashes them with MurmurHash3. A v0.4 database annotated with hex raw option strings (as `src/lib/ndpi_os_fingerprint.c.inc` is) can therefore be converted mechanically: split the hex string into options using the value lengths of §7 (e.g. `020408010307` → `02`, `04`, `08`, `01`, `03 07` → `2,4,8,1,3:7`), hash the result, and keep the other three fields. The 13 distinct raw option strings of the built-in database convert to 13 distinct MurmurHash3 values, so the conversion introduces no collision.

Examples:

| Stack | Legacy native | v0.3–v0.4 | Current (v0.5) |
|---|---|---|---|
| Linux, IPv4 | `2_64_64240_2e3cee914fc1` | `2_64_64240_5ec4846073b9` | `2_64_64240_789c1d1f` |
| Linux, IPv6 | `2_64_64800_83b2f9a5576c` | `2_64_64800_5ec4846073b9` | `2_64_64800_789c1d1f` |
| Darwin (window scale 5) | `2_64_65535_15db81ff8b0d` | `2_64_65535_fa6f8edaadeb` | `2_64_65535_2b6d3038` |
| Windows 10 | `2_128_64240_6bb88f5575fd` | `2_128_64240_e035a9f8f3a0` | `2_128_64240_47466ece` |

When moving from the legacy layout to v0.3, the built-in database was converted by recovering the raw options string behind each legacy hash and re-hashing it:

- All 65 active entries (63 distinct fingerprints) were recovered, and they collapse into 46 entries.
- The main source of redundancy was MSS: 24 of the 63 distinct legacy entries differed from another one *only* in the MSS value (1460, 1440, 1410, 1398, 1392, 1382, 1340, 1284, 1268, 1182, …).

On the nDPI regression corpus (4,524 fingerprinted flows), v0.3 compared with the legacy layout:

- distinct fingerprints drop from 141 to 115;
- flows with an OS hint rise from 1,878 to 1,907;
- no flow changes from one OS to another.

These figures carry over to v0.5 unless two distinct raw option strings of the corpus collide under MurmurHash3. They have not yet been re-measured with a v0.5 implementation.

## 16. Conformance Requirements

A conformant **producer**:

1. **MUST** select packets exactly as in §6.1 and §6.2, and compute at most one TCPFP per flow.
2. **MUST** bucket TTL/Hop Limit as in §6.3.
3. **MUST** build `R` exactly as in §6.4 and §7, including the comma-separated decimal encoding, the NOP-adjacency rule, the EOL termination and the malformed-input behaviour of §8.
4. **MUST** hash the ASCII text of `R` with `MurmurHash3_x86_32`, seed 0, little-endian block reads, and emit the result as 8 zero-padded lowercase hex characters (§6.5).
5. **MUST** emit decimal fields without padding and use `_` as the only separator.
6. **MUST NOT** include the MSS value, the TFO state or any other informative value in the fingerprint string.
7. **SHOULD** export `tcp_mss` and `tcp_fastopen` (§11). If it does, it **MUST** compute them as in §6.4 notes 9 and 10, and **MUST NOT** export the TFO cookie, the Timestamp values, the MD5/AO MACs or MPTCP keys, tokens and nonces.
8. **MUST** reproduce all test vectors in Appendix A.

A conformant **consumer**:

1. **MUST** compare fingerprints by exact string equality unless it explicitly implements per-field matching.
2. **MUST NOT** treat an OS hint derived from TCPFP as authoritative.
3. **MUST NOT** match TCPFP values against fingerprints produced by earlier native layouts (§15) or by MuonFP.

---

## Appendix A — Test Vectors

All vectors were computed with the reference implementation in Appendix B, and every options hash was cross-checked against nDPI's C `MurmurHash()` with seed 0. `M` is `tcp_mss` and `Q` is `tcp_fastopen`; they are not part of TCPFP.

### A.1 Real-World Captures

Vectors R1–R12 come from the annotated captures `tests/pcap/fp_tcp_<name>` of the nDPI regression suite. Each one is the first `SYN` of a flow. For every capture, the v0.4 hex raw options string and fingerprint computed from the same SYN match the current `ndpiReader` output in `tests/cfgs/default/result/fp_tcp_<name>.out`, which validates the option parsing on real traffic. Those expected outputs must be regenerated once nDPI implements v0.5.

| # | Capture | `F` | TTL → `T'` | `W` | Options (wire) | `R` | TCPFP (v0.5) | `M` | `Q` |
|---|---|---|---|---|---|---|---|---|---|
| R1 | `fp_tcp_linux_ubuntu24.pcap` | 2 | 64 → 64 | 64240 | `020405b4 0402 080a… 01 030307` | `2,4,8,1,3:7` | `2_64_64240_789c1d1f` | 1460 | 0 |
| R2 | `fp_tcp_android13.pcapng` | 2 | 64 → 64 | 65535 | `020404bc 0402 080a… 01 03030a 2202 01 01` | `2,4,8,1,3:10` | `2_64_65535_58b6a464` | 1212 | 1 |
| R3 | `fp_tcp_android16.pcapng` | 2 | 64 → 64 | 65535 | `020405b4 0402 080a… 01 03030a` | `2,4,8,1,3:10` | `2_64_65535_58b6a464` | 1460 | 0 |
| R4 | `fp_tcp_freebsd15.pcap` | 2 | 64 → 64 | 65535 | `020405b4 01 030306 0402 080a…` | `2,1,3:6,4,8` | `2_64_65535_2b9b4c52` | 1460 | 0 |
| R5 | `fp_tcp_macos27.pcapng` | 194 | 64 → 64 | 65535 | `020405b4 01 030306 01 01 080a… 0402 00 00` | `2,1,3:6,1,1,8,4,0` | `194_64_65535_e76f0f14` | 1460 | 0 |
| R6 | `fp_tcp_iPadOS27.pcapng` | 194 | 64 → 64 | 65535 | as R5 | `2,1,3:6,1,1,8,4,0` | `194_64_65535_e76f0f14` | 1460 | 0 |
| R7 | `fp_tcp_iOS27_iphone.pcapng` | 2 | 64 → 64 | 65535 | as R5 | `2,1,3:6,1,1,8,4,0` | `2_64_65535_e76f0f14` | 1460 | 0 |
| R8 | `fp_tcp_iOS18_iPad.pcapng` | 2 | 64 → 64 | 65535 | as R5 | `2,1,3:6,1,1,8,4,0` | `2_64_65535_e76f0f14` | 1460 | 0 |
| R9 | `fp_tcp_iOS15_iPhone.pcapng` | 194 | 64 → 64 | 65535 | `020405b4 01 030305 01 01 080a… 0402 00 00` | `2,1,3:5,1,1,8,4,0` | `194_64_65535_2b6d3038` | 1460 | 0 |
| R10 | `fp_tcp_win10.pcapng` | 2 | 128 → 128 | 64240 | `020405b4 01 030308 01 01 0402` | `2,1,3:8,1,1,4` | `2_128_64240_47466ece` | 1460 | 0 |
| R11 | `fp_tcp_win11.pcapng`, IPv6 to itself (`::1`, link-local) | 2 | 128 → 128 | 65535 | `0204ffc3 01 030308 01 01 0402` | `2,1,3:8,1,1,4` | `2_128_65535_47466ece` | 65475 | 0 |
| R12 | `fp_tcp_win11.pcapng`, IPv4 (`192.168.1.31` → `192.168.1.29`) | 2 | 128 → 128 | 65535 | `020405b4 01 030308 01 01 0402` | `2,1,3:8,1,1,4` | `2_128_65535_47466ece` | 1460 | 0 |

Observations:
- **MSS and TFO do not split a stack.** R2 and R3 (Android 13 and 16) differ in MSS (1212 vs 1460), and R2 also carries a TFO cookie request. Their fingerprint is the same; the differences are visible only in `tcp_mss` and `tcp_fastopen`. Likewise, R11 and R12 are the same Windows 11 host over the IPv6 loopback (MSS 65475 = 65535 − 40 − 20) and over IPv4 Ethernet (MSS 1460), with the same fingerprint.
- **Android vs Linux.** Android keeps the Linux option layout but uses window scale 10 instead of 7, so R2/R3 and R1 have different options hashes.
- **Apple.** macOS 27, iPadOS 27, iOS 27 and iOS 18 share the options hash `e76f0f14` (window scale 6). iOS 15 uses window scale 5 (`2b6d3038`). Release 27 appears both with ECN setup (macOS, iPadOS: R5, R6) and without it (iOS: R7), so `F` alone does not separate Apple devices.
- **Windows.** Windows 10 and 11 share the options hash `47466ece` and differ in the window (64240 vs 65535).
- **FreeBSD** places the Timestamps option after SACK-Permitted with no NOP padding, unlike every other stack here.

### A.2 Synthetic SYNs

Vectors 1, 3–5 and 11–13 are in the regression pcap `tests/cfgs/default/pcap/tcp_fingerprint_crafted.pcap`. Timestamp values, TFO cookies, MPTCP keys and MD5 digests are arbitrary and do not affect the result.

| # | Stack / case | `F` | TTL → `T'` | `W` | Options | `R` | TCPFP | `M` | `Q` |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Linux, IPv4 | 2 | 64 → 64 | 64240 | `020405b4 0402 080a… 01 030307` | `2,4,8,1,3:7` | `2_64_64240_789c1d1f` | 1460 | 0 |
| 2 | Linux, IPv6 | 2 | 64 → 64 | 64800 | `020405a0 0402 080a… 01 030307` | `2,4,8,1,3:7` | `2_64_64800_789c1d1f` | 1440 | 0 |
| 3 | Linux + TFO cookie request | 2 | 64 → 64 | 64240 | vector 1 + `2202 01 01` | `2,4,8,1,3:7` | `2_64_64240_789c1d1f` | 1460 | 1 |
| 4 | Linux + TFO cookie | 2 | 64 → 64 | 64240 | vector 1 + `220a<8 octets> 01 01` | `2,4,8,1,3:7` | `2_64_64240_789c1d1f` | 1460 | 2 |
| 5 | Linux + MPTCP v0 MP_CAPABLE | 2 | 64 → 64 | 64240 | vector 1 + `1e0c 00 81 <8-octet key>` | `2,4,8,1,3:7,30:0:129` | `2_64_64240_1d00dd35` | 1460 | 0 |
| 6 | Darwin, window scale 5 (as R9) | 2 | 64 → 64 | 65535 | `020405b4 01 030305 01 01 080a… 0402 00 00` | `2,1,3:5,1,1,8,4,0` | `2_64_65535_2b6d3038` | 1460 | 0 |
| 7 | Vector 6, ECN-setup SYN, 7 hops | 194 | 57 → 64 | 65535 | as vector 6 | `2,1,3:5,1,1,8,4,0` | `194_64_65535_2b6d3038` | 1460 | 0 |
| 8 | BGP with TCP-MD5 | 2 | 255 → 255 | 16384 | `020405b4 1312<16-octet digest> 01 01` | `2,19,1,1` | `2_255_16384_85adcf01` | 1460 | 0 |
| 9 | MSS + experimental TFO cookie + padding | 2 | 64 → 64 | 64240 | `020405b4 fe06 f989 aabb 01 01` | `2` | `2_64_64240_0129e217` | 1460 | 2 |
| 10 | Stateless scanner (no options) | 2 | 250 → 255 | 1024 | — | `""` | `2_255_1024_00000000` | 0 | 0 |

Observations:
- Vectors 1, 3 and 4 share one fingerprint and differ only in `tcp_fastopen`. Vector 2 shares their options hash and differs in the window.
- Vector 5 keeps a distinct but stable fingerprint: MPTCP support is a stack signal.
- In vector 9 the experimental TFO option has `L = 6 > 4`, i.e. a 2-octet cookie after the ExID, so `Q = 2`.
- Vector 10 raises `NDPI_MALICIOUS_FINGERPRINT` ("Massive scanner detected (probably masscan)").

### A.3 Malformed SYNs (IPv4, TTL 64, window 64240, `F = 2`)

| # | Options | `R` | TCPFP | `M` | `Q` |
|---|---|---|---|---|---|
| 11 | `22 03 01 22 fd 00…00` (40 octets; `i + L` > 255) | `""` | `2_64_64240_00000000` | 0 | 2 |
| 12 | `020405b4 03 00 00 00` (`L == 0`) | `2,3` | `2_64_64240_c636218e` | 1460 | 0 |
| 13 | `020405b4 00 de ad be` (garbage after EOL) | `2,0` | `2_64_64240_44bcccc7` | 1460 | 0 |

In vector 11 both TFO options declare a non-empty cookie (`L = 3` and `L = 253`), so `Q = 2`.

## Appendix B — Reference Implementation (Python)

```python
def _murmur3_32(data, seed=0):
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

def _ttl_bucket(ttl):
    return 32 if ttl <= 32 else 64 if ttl <= 64 else 128 if ttl <= 128 \
           else 192 if ttl <= 192 else 255

def _value_len(kind, opts, i):
    """Value octets to emit (section 7), or -1 to drop the option."""
    n = len(opts)
    if kind in (2, 8, 19, 29):                        # MSS, TS, MD5, AO: kind only
        return 0
    if kind == 30:                                    # MPTCP: subtype/version (+flags)
        return (2 if (opts[i + 2] >> 4) == 0 else 1) if i + 2 < n else 0
    if kind == 34:                                    # TFO: drop
        return -1
    if kind in (253, 254):                            # RFC 6994: ExID only
        if i + 3 < n:
            return -1 if (opts[i + 2], opts[i + 3]) == (0xF9, 0x89) else 2
        return 0
    return 255

def _parse_options(opts):
    """Returns (R, tcp_mss, tcp_fastopen)."""
    toks, mss, tfo, i, n = [], 0, 0, 0, len(opts)
    nop_start, skip_nops = None, False
    while i < n:                                      # Python int: never wraps
        kind = opts[i]
        if kind == 1:                                 # NOP
            if skip_nops:                             # padding after dropped option
                i += 1
                continue
            if nop_start is None:
                nop_start = len(toks)
            toks.append("1")
            i += 1
            continue
        vl = _value_len(kind, opts, i) if kind > 1 else 0
        if vl < 0:                                    # dropped: remove preceding NOPs
            if nop_start is not None:
                del toks[nop_start:]
            skip_nops = True
        else:
            skip_nops = False
        nop_start = None
        if kind == 0:                                 # EOL: the rest is padding
            toks.append("0")
            break
        if vl >= 0:
            toks.append("%u" % kind)
        if i + 1 >= n:                                # truncated option
            break
        olen = opts[i + 1]
        if olen == 0:                                 # malformed: stop
            break
        if kind == 2 and olen == 4 and i + 4 <= n:    # MSS: last valid one wins
            mss = int.from_bytes(opts[i + 2:i + 4], "big")
        if vl < 0:                                    # TFO: 1 = request, 2 = cookie
            tfo = max(tfo, 2 if olen > (2 if kind == 34 else 4) else 1)
        if olen > 2 and vl > 0:
            toks[-1] += "".join(":%u" % b for b in opts[i + 2:min(i + olen, n)][:vl])
        i += olen
    return ",".join(toks), mss, tfo

def ndpi_native_tcp_fp(tcp_hdr: bytes, ttl: int):
    """tcp_hdr: full TCP header incl. options; ttl: IPv4 TTL or IPv6 Hop Limit.
       Returns (TCPFP, raw, tcp_mss, tcp_fastopen), or None if the segment
       does not qualify."""
    flags = int.from_bytes(tcp_hdr[12:14], "big") & 0x0FFF
    if not (flags & 0x002) or (flags & 0x010):        # SYN set, ACK clear
        return None
    doff = (tcp_hdr[12] >> 4) * 4
    if doff < 20 or len(tcp_hdr) < doff:
        return None
    win = int.from_bytes(tcp_hdr[14:16], "big")
    raw, mss, tfo = _parse_options(tcp_hdr[20:doff])

    oh = "%08x" % _murmur3_32(raw.encode("ascii"), 0)
    return "%u_%u_%u_%s" % (flags, _ttl_bucket(ttl), win, oh), raw, mss, tfo
```

## Appendix C — TCP Option Kind Reference (Informative)

| Kind | Name | Length | Emitted into `R` | Informative value |
|---|---|---|---|---|
| 0 | End of Option List (EOL) | 1 | Kind; parsing stops | — |
| 1 | No-Operation (NOP) | 1 | Kind, unless adjacent to a dropped option | — |
| 2 | Maximum Segment Size | 4 | Kind | `tcp_mss` |
| 3 | Window Scale | 3 | Kind + shift | — |
| 4 | SACK-Permitted | 2 | Kind | — |
| 5 | SACK | variable | Kind + block edges (not normally present in a SYN) | — |
| 8 | Timestamps | 10 | Kind | — |
| 19 | TCP MD5 Signature | 18 | Kind | — |
| 28 | User Timeout | 4 | Kind + 2 octets | — |
| 29 | TCP-AO | variable | Kind | — |
| 30 | Multipath TCP | variable | Kind + subtype/version (+ flags for MP_CAPABLE) | — |
| 34 | TCP Fast Open Cookie | variable | Dropped (with adjacent NOPs) | `tcp_fastopen` |
| 253, 254 | Experimental (RFC 6994) | variable | Kind + ExID; ExID `0xF989` (TFO) dropped | `tcp_fastopen` (ExID `0xF989` only) |

## Change Log

- **v0.5** (2026-10-11):
  - The options hash is now MurmurHash3_x86_32 with seed 0 (8 hex characters) instead of the first 6 octets of SHA-256 (12 hex characters). The layout stays `<tcp_flags>_<ttl_bucket>_<tcp_window>_<options_hash>`.
  - The MSS and the TCP Fast Open state are exported next to the fingerprint as the informative values `tcp_mss` and `tcp_fastopen` (§11). They are not part of the fingerprint (§3).
  - The raw options string `R` is now human-readable comma-separated decimal (`2,4,8,1,3:7`) instead of hex (`020408010307`). Its maximum length grows from 80 to 155 characters (§6.4).
  - Added the list of ephemeral options and values skipped by the hash, with what is exported and why (§7.1).
  - Added real-world test vectors R1–R12 from the `tests/pcap/fp_tcp_*` captures (Appendix A.1).
  - All test vectors recomputed.
- **v0.4** (2026-09-29): Added the comparison with FoxIO's JA4T (§12.1).
- **v0.3** (2026-09-29): The sanitized serialization, introduced in v0.2 as a separate format (`2`), becomes the native format (`0`). The previous native format is removed (§15 describes the differences). The Wireshark Lua port is updated accordingly.
- **v0.2** (2026-09-29): Added a sanitized variant that removes from the hash:
  - the MSS value;
  - TCP-MD5/TCP-AO MACs;
  - MPTCP keys, tokens and nonces;
  - TFO, together with its NOP padding;
  - everything after the first EOL.

  The variant also shipped a separate OS database.
- **v0.1** (2026-09-29): Initial draft describing the original native format.
