# nDPI TCP Fingerprint Format

**A Passive, Single-Packet TCP/IP Stack Fingerprint Derived from the Connection-Opening Segment**

**Draft Specification — Version 0.4**


---

## Status of This Memo

This document specifies the **nDPI TCP Fingerprint** (hereafter *TCPFP*), the default TCP fingerprint computed by the `nDPI` deep packet inspection library (`metadata.tcp_fingerprint_format = 0`, symbol `NDPI_NATIVE_TCP_FINGERPRINT`). It describes the format as implemented in `src/lib/ndpi_main.c`, so that third-party producers can generate byte-identical fingerprints and consumers can interpret them. Where the implementation behaves in a non-obvious way on malformed input, that behaviour is documented as normative, because interoperability depends on it.

This revision of the format removes ephemeral options and path-dependent values from the hash. Fingerprints produced by earlier nDPI versions are **not** compatible with it (§15).

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

where `<options_hash>` is a truncated SHA-256 over a hex serialization of the TCP options **in wire order**. The serialization keeps the option layout (which options are present, their order, the NOP placement) and the option values that are constant for a given stack. It removes every input that is not a property of the sending stack:

- the MSS value (path-dependent);
- the Timestamp value (per connection);
- TCP-MD5 and TCP-AO MACs (per segment);
- MPTCP keys, tokens and nonces (per connection);
- TCP Fast Open, completely, including its NOP padding (per destination);
- everything after the first End-of-Option-List (padding).

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
- **[R12]** FIPS 180-4, *Secure Hash Standard (SHS)*
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
| **Ephemeral option** | An option whose presence or encoding depends on per-connection or per-destination state rather than on the stack configuration. It is removed from the hash completely, kind octet included (§7). |
| **Raw options string** (`R`) | The lowercase ASCII-hex serialization of the option region defined in §6.4. It is the SHA-256 input. |
| **TTL bucket** | The observed IPv4 TTL / IPv6 Hop Limit rounded up to one of `{32, 64, 128, 192, 255}` (§6.3). |
| **Hex8(x)** | The two-character lowercase hexadecimal encoding of octet `x` (`printf("%02x")`). |
| **Dec(x)** | The unsigned decimal encoding of integer `x` with no leading zeros and no sign (`printf("%u")`). |

## 2. Scope

This specification covers:

- the conditions under which a packet is selected for fingerprinting;
- the exact byte-to-string transformation, including hash input and truncation;
- behaviour on malformed option encodings;
- how nDPI maps a fingerprint to an operating-system hint and which flow risks are raised during computation.

It does **not** cover the MuonFP format (`metadata.tcp_fingerprint_format = 1`) or FoxIO's JA4T, except for the comparison in §12, nor the nDPI TLS/JA4-derived fingerprints that embed TCPFP as a component.

## 3. Design Rationale

| Field | Why it discriminates | Why it is normalized the way it is |
|---|---|---|
| Flags | ECN-capable stacks send `SYN+ECE+CWR` (RFC 3168 §6.1.1); others send a bare `SYN`. Reserved/`AE` bits expose AccECN-capable or unusual stacks. | Emitted as the numeric 12-bit value, so every bit that the sender controls is retained and no bit is interpreted. |
| TTL | Stacks pick a well-known initial TTL (64 for Linux/macOS/BSD/Android, 128 for Windows, 255 for many network devices). | The observed value has been decremented by the path. Rounding up to the next bucket restores the likely initial value and removes the dependence on hop count. |
| Window | The initial receive window is a tunable, often stack- or version-specific constant (e.g. 64240, 65535, 29200, 8192). | Emitted verbatim. It is **not** multiplied by the window-scale factor, because window scaling does not apply to SYN segments (RFC 7323 §2.2). |
| Options | The option *order*, the `NOP` placement, and constant option values (e.g. the window-scale shift) are the strongest per-stack discriminator. | Hashed to a fixed 48-bit width so the fingerprint stays short and fixed-length regardless of option count. Per-connection, per-segment, per-destination and per-path values are removed (§7). |

## 4. Data Model

Given a qualifying segment, the producer extracts:

| Symbol | Source | Width | Notes |
|---|---|---|---|
| `F` | `ntohs(*(u16*)&tcp[12]) & 0x0FFF` | 12 bits | Data Offset nibble masked out. |
| `T` | IPv4 `ttl` or IPv6 `ip6_hlim` | 8 bits | Bucketed per §6.3 → `T'`. |
| `W` | `ntohs(tcp->window)` | 16 bits | Unscaled. |
| `O` | Option region, `doff*4 − 20` bytes | 0–40 octets | Serialized per §6.4 → `R`. |

## 5. String Format

### 5.1 Grammar (ABNF, RFC 5234)

```
tcpfp        = flags "_" ttl-bucket "_" window "_" options-hash
flags        = 1*4DIGIT          ; Dec(F), 0..4095
ttl-bucket   = "32" / "64" / "128" / "192" / "255"
window       = 1*5DIGIT          ; Dec(W), 0..65535
options-hash = 12LHEXDIG         ; first 6 octets of SHA-256(R), lowercase hex
LHEXDIG      = DIGIT / %x61-66   ; 0-9 a-f
```

### 5.2 Properties

- Character set: `[0-9a-f_]`.
- Length: minimum 21 characters (`0_32_0_` + 12), maximum 27 characters (`4095_255_65535_` + 12).
- Exactly three `_` separators; the fourth field is always exactly 12 characters, **including when `R` is empty** (§6.5).
- Fields are **not** zero-padded. `2_64_8192_...` and `002_064_08192_...` are different strings; the latter is non-conformant.

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
4. No fingerprint has already been recorded for the flow. TCPFP is computed **at most once per flow**, from the first qualifying segment in either direction. Retransmitted SYNs therefore do not overwrite the value.

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

`R` is built by a single left-to-right pass over the option region `O[0..n)`, `n = doff*4 − 20`. `V(k, O, i)` is the value policy of §7: it returns the number of value octets to emit, or `DROP` for an ephemeral option. The cursor `i` **MUST** be at least 16 bits wide (§8.5).

```
R = ""; i = 0; nop_start = NONE; skip_nops = false
while i < n:
    k = O[i]

    if k == 1:                                     # NOP
        if skip_nops: i += 1; continue             # (a) padding after a dropped option
        if nop_start == NONE: nop_start = |R|      # remember start of NOP run
        R += "01"; i += 1; continue

    v = V(k, O, i) if k != 0 else 0
    if v == DROP:
        if nop_start != NONE: truncate R to nop_start   # (b) padding before a dropped option
        skip_nops = true
    else:
        skip_nops = false
    nop_start = NONE

    if k == 0: R += "00"; break                    # (c) EOL: stop, rest is padding
    if v != DROP: R += Hex8(k)                     # (d) dropped options emit nothing
    if i + 1 >= n: break                           # (e) truncated option
    L = O[i+1]
    if L == 0: break                               # (f) malformed: stop
    if L > 2 and v > 0:
        for j in [i+2, min(i+L, n, i+2+v)):        # (g) at most v value octets
            R += Hex8(O[j])
    i += L                                         # (h) advance by declared length
```

Normative notes:

1. **Wire order is preserved.** Options are not sorted, deduplicated, or reordered.
2. **The length octet is never emitted.** Only the kind and the value octets selected by `V` are.
3. **Dropped options leave no trace.** Neither their kind nor their length is emitted. This is what makes the TFO cookie-request, cookie and absent states identical.
4. **NOP padding of dropped options.** A run of consecutive NOPs *immediately* preceding a dropped option is removed from `R`, and NOPs *immediately* following it are skipped. Stacks align TFO with NOPs (Linux emits `…,wscale,tfo,nop,nop`), so without this rule a TFO SYN would still differ from a plain SYN. NOPs that are not adjacent to a dropped option are kept, because NOP placement is a stack discriminator (e.g. Windows `mss,nop,ws,nop,nop,sackOK` vs FreeBSD `mss,nop,ws,sackOK,ts`).
5. **EOL terminates.** RFC 9293 defines everything after `EOL` as padding. The first `EOL` contributes `"00"` and parsing stops, so the number of trailing `EOL` octets (which follows from the preceding layout anyway) and any garbage padding do not affect the hash.
6. **Kinds without values.** The kinds of MSS, Timestamps, TCP-MD5 and TCP-AO are emitted, so their position in the option order still counts, but their values are not (§7).
7. **Value octets are clamped to the option region.** If `i + L > n`, only the octets up to `n` are emitted, and the loop then terminates because `i + L >= n`.
8. **Output bound.** `R` is held in a 128-byte buffer (127 characters + NUL). An append that would reach the buffer end is discarded, and the loop stops. With at most 40 option octets, at most 80 hex characters can be produced, so this bound is never reached.

### 6.5 Hash

```
H   = SHA-256( ASCII(R) )           # input is the hex TEXT, |R| octets, no NUL
oh  = Hex8(H[0]) || Hex8(H[1]) || ... || Hex8(H[5])   # 48 bits, 12 chars
```

The hash input is the **ASCII hex string**, not the raw option bytes. For example, `R = "020408010307"` is hashed as the 12 octets `0x30 0x32 0x30 0x34 …`.

When `R` is empty, `oh = e3b0c44298fc` (the prefix of SHA-256 of the empty string).

### 6.6 Assembly

```
TCPFP = Dec(F) || "_" || Dec(T') || "_" || Dec(W) || "_" || oh
```

### 6.7 Worked Example (Linux)

SYN, IPv4 TTL 64, window 64240, options (20 octets):

```
02 04 05 b4                    MSS = 1460
04 02                          SACK-Permitted
08 0a 9f 3c 11 02 00 00 00 00  Timestamp (TSval, TSecr=0)
01                             NOP
03 03 07                       Window Scale, shift = 7
```

| Step | Option | `V` | Emitted |
|---|---|---|---|
| 1 | `02 04 05b4` | 0 | `02` |
| 2 | `04 02` | 255 (no value) | `04` |
| 3 | `08 0a …` | 0 | `08` |
| 4 | `01` | — | `01` |
| 5 | `03 03 07` | 255 | `03` + `07` |

```
R   = "020408010307"
H   = SHA-256("020408010307") = 5ec4846073b9…
TCPFP = 2_64_64240_5ec4846073b9
```

This value matches the `ndpi_os_linux` entries in `src/lib/ndpi_os_fingerprint.c.inc`. The same stack over IPv6 (MSS 1440, window 64800) produces `2_64_64800_5ec4846073b9`: the window differs, but the options hash is identical.

## 7. Option Value Policy

`V(k, O, i)` (`ndpi_tcp_fp_option_value_len()` in the reference implementation):

| Kind `k` | `V` | Rationale |
|---|---|---|
| 0 (EOL), 1 (NOP) | — | Handled by the serializer (§6.4) |
| 2 (MSS) | 0 | Path-dependent: MTU, IPv4 vs IPv6, VPNs, MSS clamping |
| 8 (Timestamps) | 0 | Per-connection clock (`TSval`) and echo (`TSecr`) |
| 19 (TCP-MD5) | 0 | Per-segment digest |
| 29 (TCP-AO) | 0 | Per-segment MAC |
| 30 (MPTCP) | `2` if `O[i+2] >> 4 == 0` (MP_CAPABLE), else `1`; `0` if `i+2 >= n` | Keep subtype, version and the MP_CAPABLE flags (e.g. the HMAC algorithm); drop keys, tokens, nonces and address IDs |
| 34 (TCP Fast Open) | `DROP` | Per-server cookie; presence depends on the cookie cache and on the application |
| 253, 254 (RFC 6994) | `DROP` if `O[i+2..i+3] == F9 89` (experimental TFO), else `2`; `0` if `i+3 >= n` | Keep the ExID, drop the experiment data |
| any other | all (255) | Assumed to be a stack constant (e.g. the Window Scale shift, the User Timeout) |

MPTCP value layouts relevant to `V`:

| Subtype in SYN | Value octets | Kept | Dropped |
|---|---|---|---|
| MP_CAPABLE v0 (RFC 6824), `L = 12` | `subtype\|ver`, `flags`, 8-octet key | first 2 | key |
| MP_CAPABLE v1 (RFC 8684), `L = 4` | `subtype\|ver`, `flags` | all | — |
| MP_JOIN, `L = 12` | `subtype\|B`, address ID, token, nonce | first 1 | address ID, token, nonce |

The MSS value is still parsed internally, because the scanner heuristics of §10 and the MuonFP format use it. It is only excluded from `R`.

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

An empty option region gives `R = ""`, `oh = e3b0c44298fc`, and raises the flow risk of §10. `R` can also be empty for a non-empty option region (e.g. only TFO). That produces the same `oh` but does **not** raise the "Massive scanner" risk, which is based on the option region length.

## 9. Matching Semantics and OS Inference

- TCPFP values are compared by **exact, case-sensitive string equality**. The format has no partial or per-field matching semantics. Consumers that want to match on a subset of fields (e.g. ignore the window) **MUST** split on `_` and compare fields individually.
- After computing TCPFP, nDPI looks it up in a hash table (`ndpi_get_os_from_tcp_fingerprint()`) and stores the result in `flow->metadata.l4.tcp.os_hint` as an `ndpi_os` value:

  | `ndpi_os` | Value |
  |---|---|
  | `ndpi_os_unknown` | 0 |
  | `ndpi_os_windows` | 1 |
  | `ndpi_os_macos` | 2 |
  | `ndpi_os_ios_ipad_os` | 3 |
  | `ndpi_os_android` | 4 |
  | `ndpi_os_linux` | 5 |
  | `ndpi_os_freebsd` | 6 |

- At initialization, `ndpi_load_tcp_fingerprints()` seeds the table with the built-in list `tcp_fps[]` (`src/lib/ndpi_os_fingerprint.c.inc`) when the native format is configured. No built-in list is loaded for MuonFP. Each built-in entry is annotated with its raw options string `R`. The table can be extended at run time with `ndpi_add_tcp_fingerprint()` or `ndpi_load_tcp_fingerprint_file()`. The file format is one entry per line:

  ```
  # comment
  <TCPFP>,<numeric ndpi_os>
  2_64_14600_b88686e220ac,5
  ```

  Duplicate fingerprints are rejected (first insertion wins), and OS values `>= ndpi_os_MAX_OS` are ignored.
- The mapping is many-to-one, and a fingerprint may legitimately match multiple OS families (e.g. `2_64_65535_5ec4846073b9` is Android, while the same options hash with window 64240 is Linux; `96500ba614e1` is shared by macOS and iOS/iPadOS). The OS hint is a **hint**, not an identification.

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
| `metadata.tcp_fingerprint` | `enable` | Master switch. When disabled, no TCP fingerprint is computed. |
| `metadata.tcp_fingerprint_format` | `0` | `0` = TCPFP (this document), `1` = MuonFP. |
| `metadata.tcp_fingerprint_raw` | `disable` | Also export `R` (the pre-hash raw options string) when `|R| > 0`. |
| `metadata.ndpi_fingerprint_ignore_tcp_fp` | `disable` | When disabled, TCPFP is used as the L4 component of the composite nDPI client fingerprint. |

Exported fields:

- C API: `flow->metadata.l4.tcp.fingerprint`, `flow->metadata.l4.tcp.fingerprint_raw`, `flow->metadata.l4.tcp.os_hint`.
- JSON/TLV serializer: `"tcp_fingerprint"` and `"tcp_fingerprint_raw"`.
- `ndpiReader`: `[TCP Fingerprint: <TCPFP>/<OS>]`, e.g. `[TCP Fingerprint: 2_64_64240_5ec4846073b9/Linux]`.
- Wireshark (`wireshark/ndpi.lua`): field `ntop.tcp_fingerprint`.

Exporting `R` is **RECOMMENDED** when building or auditing fingerprint databases, because it makes hash collisions directly visible and allows the database to be recomputed if the format changes.

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

| Vector | JA4T | TCPFP |
|---|---|---|
| 1 Linux, IPv4 | `64240_2-4-8-1-3_1460_7` | `2_64_64240_5ec4846073b9` |
| 2 Linux, IPv6 | `64800_2-4-8-1-3_1440_7` | `2_64_64800_5ec4846073b9` |
| 3 Linux + TFO cookie request | `64240_2-4-8-1-3-34-1-1_1460_7` | `2_64_64240_5ec4846073b9` |
| 5 Linux + MPTCP | `64240_2-4-8-1-3-30_1460_7` | `2_64_64240_d9f8b1298998` |
| 6 macOS | `65535_2-1-3-1-1-8-4-0-0_1460_5` | `2_64_65535_fa6f8edaadeb` |
| 7 macOS, ECN SYN, 7 hops | `65535_2-1-3-1-1-8-4-0-0_1460_5` | `194_64_65535_fa6f8edaadeb` |

The two fingerprints start from the same observation: window, option layout and a few option values identify a TCP/IP stack. They make different trade-offs:

| Aspect | JA4T | TCPFP |
|---|---|---|
| Packet | Client SYN (JA4TS: server SYN-ACK) | Client SYN only |
| Representation | Clear text, variable length | `flags_ttl_win` in clear + 48-bit hash of the options, fixed layout |
| TCP flags (ECN negotiation) | Not included | Included (`F`) |
| Initial TTL | Not included | Included, bucketed (§6.3) |
| Window | Included | Included |
| Option kinds and order | Included, all kinds | Included; ephemeral kinds (TFO, experimental TFO) and their NOP padding removed; stops at the first EOL |
| MSS value | Included | **Excluded** (§7) |
| Window-scale shift | Included | Included (inside the hash) |
| Other option values (MPTCP version and flags, RFC 6994 ExID, unknown options) | Not included | Included (inside the hash) |
| Partial matching | Natural: fields and option lists can be compared or wildcarded directly | Only on `flags`, `ttl` and `window`; option-level matching needs the raw string `R` (§11) |
| Active variant | JA4TScan (retransmission timing) | None; TCPFP is passive only |

**The main design difference is MSS.** JA4T keeps the MSS on purpose. An MSS below what the link MTU would allow (e.g. 1460 minus tunnel overhead) reveals VPNs, tunnels and proxies on the path, and FoxIO presents this as a JA4T use case. TCPFP deliberately removes the MSS so that one stack yields one fingerprint regardless of path: vectors 1 and 2 share the TCPFP options hash, while their JA4T strings differ. As a result, TCPFP is the better key for stack/OS identification and database lookups, and JA4T is the better signal for path analysis. The two are complementary, not competing.

**TCPFP sees more of the stack in two respects:**
- **Flags and TTL.** Vectors 6 and 7 have the same JA4T, but TCPFP separates them (`2` vs `194`). ECN negotiation and the initial TTL (64 vs 128 vs 255) are strong OS discriminators that JA4T leaves out.
- **Option values beyond MSS and WS.** TCPFP hashes the MPTCP version and flags, the RFC 6994 ExIDs and the values of unknown options. JA4T records these options only by their kind.

**JA4T sees more in one respect:** the presence of TFO. Vector 3 shows TFO in JA4T but not in TCPFP. That makes the JA4T of a client depend on whether it has a TFO cookie for the server, or uses TFO at all. It is the same session-state drift TLSFP removes for TLS, and TCPFP removes it for TCP (§13). JA4T also lists every trailing EOL (`…-0-0`), which follows from the option layout and adds no information.

**Readability vs compactness.** JA4T can be read and matched by eye; TCPFP cannot without `R`. On the other hand, TCPFP has a fixed, bounded layout that suits hash-table lookups (`ndpi_get_os_from_tcp_fingerprint()`) and flow export.

**Licensing.** At the time of writing, FoxIO publishes JA4 (TLS client) under the BSD 3-Clause license and the other JA4+ methods, including JA4T, under the FoxIO License 1.1, which restricts some commercial uses. Check FoxIO's current terms before embedding JA4T. TCPFP is specified under CC BY 4.0 (this document) and implemented in nDPI under the LGPLv3.

### 12.2 MuonFP

MuonFP (`metadata.tcp_fingerprint_format = 1`) carries essentially the same information as JA4T: window, option kinds, MSS and window scale, in clear text with `:` as the separator (e.g. `64240:2-4-8-1-3:1460:7`). nDPI users who need a JA4T-style fingerprint can therefore use format 1, which differs from JA4T mainly in field separators and in how an absent MSS or window scale is encoded. It is computed by the same parser pass as TCPFP:

| Aspect | TCPFP (format 0) | MuonFP (format 1) |
|---|---|---|
| Layout | `flags_ttl_win_hash12` | `win:kinds:mss:wscale` |
| Flags / TTL | Included | Not included |
| Option kinds | In order, hashed; ephemeral kinds removed; stops at EOL | In order, in clear; all kinds |
| Option values | Only stack constants (WS shift, MPTCP version, unknown options) | MSS and WS shift, in clear |
| MSS | Not in hash | In clear |
| Length | Fixed-width last field | Variable |
| Human-readable | No | Yes |

The two formats share segment selection (`SYN` without `ACK`), the zero-length-option rule (§8.2) and the 16-bit cursor (§8.5).

## 13. Stability Considerations

| Source of drift | Handled | Notes |
|---|---|---|
| MSS clamping, IPv4 vs IPv6 MSS | Yes | MSS value not hashed |
| TCP Fast Open (request / cookie / absent) | Yes | TFO and its NOP padding removed |
| MPTCP keys, tokens, nonces | Yes | Version and flags kept |
| TCP-MD5 / TCP-AO | Yes | MAC not hashed |
| Trailing EOL count / garbage padding | Yes | Parsing stops at the first EOL |
| Window tied to MSS (Linux uses the largest multiple of MSS ≤ 65535: 64240 = 44×1460, 64800 = 45×1440) | Partially | The options hash is identical, but the window field differs |
| TTL near a bucket edge | No | Rare in practice |
| Middlebox ECN bleaching (`ECE/CWR` cleared) | No | `F` flips between `194` and `2` |
| Presence of MPTCP (application-dependent on iOS) | No | Kept on purpose as a stack signal |

Because the window is usually still stack-specific, consumers that need to match across IPv4 and IPv6 **MAY** match on the flags, TTL and options-hash fields only.

## 14. Security and Privacy Considerations

- **Spoofability.** Every TCPFP input is sender-controlled, so a crafted SYN can impersonate any fingerprint. TCPFP **MUST NOT** be used as an authentication signal.
- **Truncated hash.** The 48-bit hash truncation is sized for classification, not collision resistance. An attacker can find a second preimage of a chosen `R` with approximately `2^48` work. Because `R` is itself constrained to at most 40 option octets, collisions are in any case not a concern for benign traffic.
- **Evasion.** MSS, TFO and MAC perturbation do not change TCPFP, but unknown option values are still hashed, so a tool can change its TCPFP by adding or altering one. A tool can also pad a SYN with TFO options, which are removed, without changing its fingerprint. Detection logic **SHOULD** combine TCPFP with the structural risks of §10 and, where available, with the raw string `R`.
- **Parser safety.** The parser reads only within the option region and writes only within the fixed output buffer. With a 16-bit cursor (§8.5), crafted `L == 0` or oversized `L` values cannot cause out-of-bounds access or non-termination.
- **Privacy.** TCPFP identifies a TCP/IP **stack configuration**, not an individual. The values that could link connections from the same host are excluded from both the hash and `R`: Timestamps (uptime/clock-skew estimation), TFO cookies (per client-server pair) and MPTCP keys.

## 15. Changes from the Previous Native Format

nDPI versions before this revision computed a native fingerprint with the same string layout but a different option serialization. **Old and new fingerprints are not comparable**, and databases built with earlier versions (including custom files loaded with `ndpi_load_tcp_fingerprint_file()`) **MUST** be regenerated.

| Aspect | Previous native format | Current native format |
|---|---|---|
| Segment selection | `SYN`, `ECE` or `CWR` set, `ACK` clear | `SYN` set, `ACK` clear |
| MSS, TCP-MD5, TCP-AO, MPTCP, experimental options | Kind + full value | Per §7 |
| TCP Fast Open | Kind + cookie | Removed with its NOP padding |
| EOL | Parsing continued after it | Parsing stops |
| `L == 0` | Kind re-emitted until the 128-byte buffer filled | Stop |
| Cursor | 8-bit (could wrap) | 16-bit |

Examples:

| Stack | Previous | Current |
|---|---|---|
| Linux, IPv4 | `2_64_64240_2e3cee914fc1` | `2_64_64240_5ec4846073b9` |
| Linux, IPv6 | `2_64_64800_83b2f9a5576c` | `2_64_64800_5ec4846073b9` |
| macOS | `2_64_65535_15db81ff8b0d` | `2_64_65535_fa6f8edaadeb` |
| Windows 10/11 | `2_128_64240_6bb88f5575fd` | `2_128_64240_e035a9f8f3a0` |

The built-in database was converted by recovering the raw options string behind each previous hash and re-hashing it:

- All 65 active entries (63 distinct fingerprints) were recovered, and they collapse into 46 entries.
- The main source of redundancy was MSS: 24 of the 63 distinct previous entries differed from another one *only* in the MSS value (1460, 1440, 1410, 1398, 1392, 1382, 1340, 1284, 1268, 1182, …).

On the nDPI regression corpus (4,524 fingerprinted flows):

- distinct fingerprints drop from 141 to 115;
- flows with an OS hint rise from 1,878 to 1,907;
- no flow changes from one OS to another.

## 16. Conformance Requirements

A conformant **producer**:

1. **MUST** select packets exactly as in §6.1 and §6.2, and compute at most one TCPFP per flow.
2. **MUST** bucket TTL/Hop Limit as in §6.3.
3. **MUST** build `R` exactly as in §6.4 and §7, including the NOP-adjacency rule, the EOL termination and the malformed-input behaviour of §8.
4. **MUST** hash the ASCII text of `R` with SHA-256 and emit the first six digest octets as 12 lowercase hex characters.
5. **MUST** emit decimal fields without padding and use `_` as the only separator.
6. **MUST** reproduce all test vectors in Appendix A.

A conformant **consumer**:

1. **MUST** compare fingerprints by exact string equality unless it explicitly implements per-field matching.
2. **MUST NOT** treat an OS hint derived from TCPFP as authoritative.
3. **MUST NOT** match TCPFP values against fingerprints produced by the previous native format (§15) or by MuonFP.

---

## Appendix A — Test Vectors

All vectors were computed with the reference implementation in Appendix B and cross-checked against `ndpiReader` and the Lua port in `wireshark/ndpi.lua`. Vectors 1, 3–5 and 11–13 are part of the regression suite (`tests/cfgs/default/pcap/tcp_fingerprint_crafted.pcap`). Timestamp values, TFO cookies, MPTCP keys and MD5 digests are arbitrary and do not affect the result.

### A.1 Well-formed SYNs

| # | Stack / case | `F` | TTL → `T'` | `W` | Options | `R` | TCPFP |
|---|---|---|---|---|---|---|---|
| 1 | Linux, IPv4 | 2 | 64 → 64 | 64240 | `020405b4 0402 080a… 01 030307` | `020408010307` | `2_64_64240_5ec4846073b9` |
| 2 | Linux, IPv6 (MSS 1440) | 2 | 64 → 64 | 64800 | `020405a0 0402 080a… 01 030307` | `020408010307` | `2_64_64800_5ec4846073b9` |
| 3 | Linux + TFO cookie request | 2 | 64 → 64 | 64240 | vector 1 + `2202 01 01` | `020408010307` | `2_64_64240_5ec4846073b9` |
| 4 | Linux + TFO cookie | 2 | 64 → 64 | 64240 | vector 1 + `220a<8 octets> 01 01` | `020408010307` | `2_64_64240_5ec4846073b9` |
| 5 | Linux + MPTCP v0 MP_CAPABLE | 2 | 64 → 64 | 64240 | vector 1 + `1e0c 00 81 <8-octet key>` | `0204080103071e0081` | `2_64_64240_d9f8b1298998` |
| 6 | macOS / Darwin | 2 | 64 → 64 | 65535 | `020405b4 01 030305 01 01 080a… 0402 00 00` | `020103050101080400` | `2_64_65535_fa6f8edaadeb` |
| 7 | Vector 6, ECN-setup SYN, 7 hops | 194 | 57 → 64 | 65535 | as vector 6 | `020103050101080400` | `194_64_65535_fa6f8edaadeb` |
| 8 | BGP with TCP-MD5 | 2 | 255 → 255 | 16384 | `020405b4 1312<16-octet digest> 01 01` | `02130101` | `2_255_16384_df9f6ba44436` |
| 9 | MSS + experimental TFO + padding | 2 | 64 → 64 | 64240 | `020405b4 fe06 f989 aabb 01 01` | `02` | `2_64_64240_a953f09a1b6b` |
| 10 | Stateless scanner (no options) | 2 | 250 → 255 | 1024 | — | `""` | `2_255_1024_e3b0c44298fc` |

Observations:
- Vectors 1, 3 and 4 share one fingerprint, and vector 2 shares their options hash.
- Vector 5 keeps a distinct but stable fingerprint: MPTCP support is a stack signal.
- Vector 10 raises `NDPI_MALICIOUS_FINGERPRINT` ("Massive scanner detected (probably masscan)").

### A.2 Malformed SYNs (IPv4, TTL 64, window 64240, `F = 2`)

| # | Options | `R` | TCPFP |
|---|---|---|---|
| 11 | `22 03 01 22 fd 00…00` (40 octets; `i + L` > 255) | `""` | `2_64_64240_e3b0c44298fc` |
| 12 | `020405b4 03 00 00 00` (`L == 0`) | `0203` | `2_64_64240_c2576dd8541a` |
| 13 | `020405b4 00 de ad be` (garbage after EOL) | `0200` | `2_64_64240_1fdc13485c8a` |

## Appendix B — Reference Implementation (Python)

```python
import hashlib

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

def _raw_options(opts):
    raw, i, n = "", 0, len(opts)
    nop_start, skip_nops = None, False
    while i < n:                                      # Python int: never wraps
        kind = opts[i]
        if kind == 1:                                 # NOP
            if skip_nops:                             # padding after dropped option
                i += 1
                continue
            if nop_start is None:
                nop_start = len(raw)
            raw += "01"
            i += 1
            continue
        vl = _value_len(kind, opts, i) if kind > 1 else 0
        if vl < 0:                                    # dropped: remove preceding NOPs
            if nop_start is not None:
                raw = raw[:nop_start]
            skip_nops = True
        else:
            skip_nops = False
        nop_start = None
        if kind == 0:                                 # EOL: the rest is padding
            raw += "00"
            break
        if vl >= 0:
            raw += "%02x" % kind
        if i + 1 >= n:                                # truncated option
            break
        olen = opts[i + 1]
        if olen == 0:                                 # malformed: stop
            break
        if olen > 2 and vl > 0:
            raw += "".join("%02x" % b for b in opts[i + 2:min(i + olen, n)][:vl])
        i += olen
    return raw

def ndpi_native_tcp_fp(tcp_hdr: bytes, ttl: int):
    """tcp_hdr: full TCP header incl. options; ttl: IPv4 TTL or IPv6 Hop Limit.
       Returns (TCPFP, raw) or None if the segment does not qualify."""
    flags = int.from_bytes(tcp_hdr[12:14], "big") & 0x0FFF
    if not (flags & 0x002) or (flags & 0x010):        # SYN set, ACK clear
        return None
    doff = (tcp_hdr[12] >> 4) * 4
    if doff < 20 or len(tcp_hdr) < doff:
        return None
    win = int.from_bytes(tcp_hdr[14:16], "big")
    raw = _raw_options(tcp_hdr[20:doff])

    digest = hashlib.sha256(raw.encode("ascii")).hexdigest()[:12]
    return "%u_%u_%u_%s" % (flags, _ttl_bucket(ttl), win, digest), raw
```

## Appendix C — TCP Option Kind Reference (Informative)

| Kind | Name | Length | Emitted into `R` |
|---|---|---|---|
| 0 | End of Option List (EOL) | 1 | Kind; parsing stops |
| 1 | No-Operation (NOP) | 1 | Kind, unless adjacent to a dropped option |
| 2 | Maximum Segment Size | 4 | Kind |
| 3 | Window Scale | 3 | Kind + shift |
| 4 | SACK-Permitted | 2 | Kind |
| 5 | SACK | variable | Kind + block edges (not normally present in a SYN) |
| 8 | Timestamps | 10 | Kind |
| 19 | TCP MD5 Signature | 18 | Kind |
| 28 | User Timeout | 4 | Kind + 2 octets |
| 29 | TCP-AO | variable | Kind |
| 30 | Multipath TCP | variable | Kind + subtype/version (+ flags for MP_CAPABLE) |
| 34 | TCP Fast Open Cookie | variable | Dropped (with adjacent NOPs) |
| 253, 254 | Experimental (RFC 6994) | variable | Kind + ExID; ExID `0xF989` (TFO) dropped |

## Change Log

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
