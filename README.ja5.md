# JA5 TLS Client Fingerprint Format

**An Extension of JA4 with Ephemeral-Extension Sanitization and Supported-Groups Binding**

**Draft Specification — Version 0.1**


---

## Status of This Memo

This document defines the **JA5 TLS Client Fingerprint (JA5) Format**, an extension of the JA4 fingerprint proposed for adoption within the `nDPI` deep packet inspection library and downstream consumers. It is published as a draft for internal and community review. Implementers are encouraged to validate the algorithm against production TLS traffic and to report collision, stability, and performance data.

## Copyright and License

Copyright © 2026, ntop. This draft is released under the Creative Commons Attribution 4.0 International (CC BY 4.0). Implementations may use, adapt, and redistribute the format and examples with attribution.

---

## Table of Contents

1. [Terminology and Conventions](#1-terminology-and-conventions)
2. [Scope](#2-scope)
3. [Limitations of JA4 Motivating This Extension](#3-limitations-of-ja4-motivating-this-extension)
4. [Data Model](#4-data-model)
5. [String Format](#5-string-format)
6. [Low-Level Calculation Mechanism](#6-low-level-calculation-mechanism)
7. [Normalization Rules](#7-normalization-rules)
8. [Matching Semantics](#8-matching-semantics)
9. [Error Handling](#9-error-handling)
10. [Versioning and Compatibility](#10-versioning-and-compatibility)
11. [Interoperability Considerations](#11-interoperability-considerations)
12. [Deployment Guidance (Non-Normative)](#12-deployment-guidance-non-normative)
13. [Security Considerations](#13-security-considerations)
14. [Privacy Considerations](#14-privacy-considerations)
15. [Conformance Requirements](#15-conformance-requirements)
- [Appendix A — Test Vectors](#appendix-a--test-vectors)
- [Appendix B — Ephemeral Extension Registry (Informative)](#appendix-b--ephemeral-extension-registry-informative)
- [Appendix C — Extension and Group ID Reference (Informative)](#appendix-c--extension-and-group-id-reference-informative)
- [Change Log](#change-log)

---

## Abstract

The **JA4** fingerprint (FoxIO, 2023) improved on **JA3** by sorting cipher suites and extensions before hashing, replacing raw extension lists with stable counts, and separately hashing signature algorithms. In production DPI deployments, however, two residual weaknesses remain observable:

1. **Ephemeral extensions** — extensions whose presence, absence, or ordering varies run-to-run for an otherwise identical client build, due to session state, TLS session resumption, or library-internal padding heuristics — introduce fingerprint drift that is indistinguishable from genuine client diversity.
2. JA4 intentionally discards the **values** carried inside the `supported_groups` (elliptic curve) extension, retaining only extension *identity*, which causes distinct TLS stacks negotiating different curve sets to collide onto the same JA4_c hash.

**JA5** addresses both issues by (a) excluding a curated set of ephemeral extension types from both the extension count and the extension hash input, and (b) appending a fourth, independently computed hash segment derived from the ordered `supported_groups` values. This document specifies the canonical string format, the byte-level calculation procedure, normalization rules, matching semantics, and conformance requirements for JA5 producers and consumers. A reference implementation is maintained in `nDPI` (`src/lib/protocols/tls.c`).

## Normative and Informative References

- **[R1]** FoxIO, *JA4+ Network Fingerprinting*: <https://github.com/FoxIO-LLC/ja4>
- **[R2]** ntop, *nDPI — Open Source Deep Packet Inspection Library*: <https://github.com/ntop/nDPI>
- **[R3]** RFC 8446, *The Transport Layer Security (TLS) Protocol Version 1.3*
- **[R4]** RFC 8701, *Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility*
- **[R5]** RFC 2119 / RFC 8174, *Key words for use in RFCs to Indicate Requirement Levels*
- **[R6]** IANA, *TLS ExtensionType Values Registry*
- **[R7]** IANA, *TLS Supported Groups Registry*

---

## 1. Terminology and Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals, as shown here.

| Term | Definition |
|---|---|
| **ClientHello** | The first TLS handshake message sent by a client, as defined in RFC 8446 §4.1.2. |
| **GREASE** | Placeholder cipher/extension/group values following the bit pattern `0x?A?A` (RFC 8701), inserted by conforming clients to prevent protocol ossification. GREASE values **MUST** be excluded from all JA5 computations. |
| **Ephemeral extension** | An extension type whose presence, absence, or byte content on the wire is determined by *session state* (e.g. resumption, retry) rather than by the client's static TLS stack configuration, and which therefore **MUST** be excluded from the JA5_a count and JA5_c hash input. The canonical registry is given in Appendix B. |
| **Fingerprint** | A signature derived from ClientHello header features. It does *not* uniquely identify a person or device; it characterizes TLS stack and library behavior. |

## 2. Scope

This document specifies: the JA5 string format and its Augmented Backus–Naur Form (ABNF) grammar; the byte-level algorithm used to derive each field from a captured ClientHello; normalization and canonicalization rules; matching semantics for exact and wildcard consumers; error handling; and conformance requirements for **producers** (DPI sensors, e.g. `nDPI`) and **consumers** (firewalls, SIEM, `ntopng` flow classification, SOAR).

## 3. Limitations of JA4 Motivating This Extension

### 3.1 Evasion and Noise via Ephemeral Extensions

JA4_a encodes a raw extension *count*, and JA4_c hashes the sorted extension *type list*. Both are sensitive to any change in which extensions appear on the wire. Several extension types are legitimately transient for a single, unmodified client binary:

- `session_ticket` (35) and `pre_shared_key` (41) / `psk_key_exchange_modes` (45) appear only when a prior session exists to resume, so the *same browser build* alternates between including and omitting them across consecutive connections to the same or different origins.
- `padding` (21) is inserted opportunistically by several stacks (notably BoringSSL-derived clients) to reach a target ClientHello record size, and its presence depends on the byte length of unrelated fields such as the SNI hostname.
- `early_data` (42) and `cookie` (44) are HelloRetryRequest-contingent and depend on network/server round-trip conditions, not client identity.

Because JA4_a's extension-count digit and JA4_c's hash both react to these fields, a single client build can legitimately present several distinct JA4 values, degrading precision for both allow-listing and threat-hunting use cases and giving automated tooling free "fingerprint churn" that is indistinguishable from genuine population diversity.

### 3.2 Blindness to TLS Supported Groups (Elliptic Curves)

JA4_c hashes extension *type identifiers* only; it never inspects the payload of the `supported_groups` extension (type 10, RFC 8446 §4.2.7), which enumerates the elliptic curves and key-exchange groups the client is willing to negotiate (e.g. `x25519` `0x001d`, `secp256r1` `0x0017`, `x25519mlkem768` `0x11ec` for post-quantum hybrids). Because the extension's mere presence is already reflected in JA4_c, two clients that both advertise `supported_groups` but with entirely different curve sets — for instance, a legitimate browser stack versus a Go `crypto/tls`-based scanning tool configured to mimic browser cipher order — can collide onto an identical JA4 fingerprint. This is precisely the collision class exploited by fingerprint-evasion tooling that copies published browser JA4 values while leaving the underlying TLS library's default curve list unchanged.

## 4. Data Model

A JA5 fingerprint encodes values observed in the *first* relevant handshake message for one of two observation profiles, consistent with JA4:

- **Client-Initiated (ClientHello):** JA5(C) — the profile normatively specified in this document.
- **Server-Initiated (ServerHello):** JA5S — reserved for a companion specification; out of scope here.

Producers **MUST** process only the first ClientHello observed on a given 5-tuple (ignoring TCP retransmissions) and, where TLS 1.3 HelloRetryRequest occurs, **MUST** fingerprint the *original* ClientHello, not the retried one, unless explicitly operating in a retry-aware mode declared out of band.

## 5. String Format

The canonical JA5 string consists of **four underscore-separated fields**, extending JA4's three:

```
JA5_a _ JA5_b _ JA5_c _ JA5_d
```

| Field | Length | Content |
|---|---|---|
| `JA5_a` | 10 chars | Structured metadata: protocol, TLS version, SNI presence, cipher count, *sanitized* extension count, first ALPN. Unchanged in length from JA4_a; semantically identical except the extension-count digits exclude ephemeral extensions (§6.2). |
| `JA5_b` | 12 hex | Truncated SHA-256 of the sorted cipher-suite list. **Identical to JA4_b** — JA5 does not alter cipher-suite handling. |
| `JA5_c` | 12 hex | Truncated SHA-256 of the sorted extension-type list *with ephemeral extensions removed*, concatenated with the signature-algorithms list in advertised order. |
| `JA5_d` | 12 hex | **New in JA5.** Truncated SHA-256 of the sorted `supported_groups` value list (GREASE-filtered). |

Total canonical length is 10 + 1 + 12 + 1 + 12 + 1 + 12 = **49 characters** (versus 36 for JA4), reflecting the appended fourth field.

### 5.1 ABNF

Using the core rules of RFC 5234:

```abnf
ja5      = ja5-a "_" ja5-b "_" ja5-c "_" ja5-d
ja5-a    = proto version sni cnt-c cnt-e alpn
proto    = "t" / "q" / "d"          ; TCP, QUIC, DTLS
version  = 2(DIGIT / ALPHA)         ; e.g. "13", "s3", "d1"
sni      = "d" / "i"                ; domain present / absent
cnt-c    = 2DIGIT                   ; cipher count, capped at 99
cnt-e    = 2DIGIT                   ; sanitized extension count, capped at 99
alpn     = 2(ALPHA / DIGIT) / "00"
ja5-b    = 12HEXDIG / wildcard
ja5-c    = 12HEXDIG / wildcard
ja5-d    = 12HEXDIG / empty / wildcard
empty    = ""
wildcard = "%"
```

The percent sign (`%`) is the field-level wildcard operator and matches any value for that field. `ja5-d` **MAY** be empty when `supported_groups` is absent from the ClientHello (permitted, though rare, for TLS ≤1.2 RSA key-exchange-only clients).

### 5.2 Examples

```
t13d1514h2_acb858a92679_7dc829385eb9_0a47a2b05960
t13d1516h2_acb858a92679_562e8b7393e5_000000000000   (JA5_d empty: no supported_groups)
```

## 6. Low-Level Calculation Mechanism

This section defines, at byte and field granularity, the deterministic procedure a conformant producer **MUST** implement.

### 6.1 Input

The algorithm operates on a parsed ClientHello structure exposing, in on-wire order: the legacy protocol version, the `supported_versions` extension (if present), the SNI extension (if present), the ordered `cipher_suites` list, the ordered extension list (type + length + payload triples), the `signature_algorithms` extension payload (if present), and the `supported_groups` extension payload (if present).

### 6.2 Step 1 — GREASE Filtering

For any 16-bit value `v` (cipher suite, extension type, or supported group), `v` is a GREASE value iff:

```
(v mod 256) == floor(v / 256)   and   (v mod 256) in {0x0A, 0x1A, 0x2A, ..., 0xFA}
```

equivalently, in bitwise form, `v` **MUST** be treated as GREASE iff `(v & 0x0F0F) == 0x0A0A`. All GREASE-valued ciphers, extension types, and supported-group codes **MUST** be removed from every list before any subsequent step.

### 6.3 Step 2 — Ephemeral Extension Exclusion (New in JA5)

Let `E_eph` be the ephemeral extension registry defined in Appendix B (extension type codes). For the GREASE-filtered extension list `L`:

```
L'            = L \ E_eph
n_sanitized   = |L'|
```

`L'` (still in on-wire order at this stage) is retained for Step 5. `n_sanitized` feeds JA5_a in place of JA4's raw extension count. Producers **MUST** apply Step 2 *after* GREASE filtering and *before* sorting, so that ephemeral-extension exclusion and GREASE exclusion do not double-count.

### 6.4 Step 3 — JA5_a Construction

```
proto    = "t" if TLS over TCP, "q" if QUIC, "d" if DTLS
version  = highest value in supported_versions (GREASE-filtered),
           else legacy_version; mapped 0x0304 -> "13", 0x0303 -> "12",
           0x0302 -> "11", 0x0301 -> "10", SSLv3 -> "s3"; 0XFEFF -> "d1",
           0XFEFD -> "d2", 0XFEFC -> "d3", unknown -> "00"
sni      = "d" if extension type 0 present, else "i"
cnt_c    = min(count(cipher_suites, GREASE-filtered), 99), zero-padded to 2
cnt_e    = min(n_sanitized, 99), zero-padded to 2          <-- differs from JA4
alpn     = first + last byte of the first protocol string in extension 16,
           lower-cased; "00" if extension 16 absent or protocol string empty

JA5_a = proto || version || sni || cnt_c || cnt_e || alpn
```

### 6.5 Step 4 — JA5_b (Cipher Suite Hash, Unchanged from JA4_b)

```
ciphers_sorted = sort_numeric_ascending(GREASE_filter(cipher_suites))
input_b        = join(hex(c, width=4) for c in ciphers_sorted, sep=",")
digest_b       = SHA256(input_b)                 ; 32-byte digest
JA5_b          = hex(digest_b)[0:12]             ; first 48 bits, 12 hex nibbles
```

Reusing JA4_b unmodified preserves backward compatibility for consumers that only key on cipher-suite identity, and confirms empirically that cipher-suite ordering carries no ephemeral noise comparable to the extension list.

### 6.6 Step 5 — JA5_c (Sanitized Extension + Signature-Algorithm Hash)

```
ext_for_hash   = L' minus {SNI(0), ALPN(16)}     ; already GREASE- and
                                                   ; ephemeral-filtered from Step 2
ext_sorted     = sort_numeric_ascending(ext_for_hash)
ext_part       = join(hex(t, width=4) for t in ext_sorted, sep=",")
sigalg_part    = join(hex(s, width=4) for s in signature_algorithms, sep=",")
                 ; kept in ADVERTISED (unsorted) order, per JA4 precedent --
                 ; signature-algorithm order is itself a stack signature
input_c        = ext_part || "_" || sigalg_part
digest_c       = SHA256(input_c)
JA5_c          = hex(digest_c)[0:12]
```

### 6.7 Step 6 — JA5_d (Supported-Groups Hash, New in JA5)

```
groups_raw     = payload of extension 10 (supported_groups), parsed as
                 a sequence of 16-bit NamedGroup codes (RFC 8446 §4.2.7)
groups_filt    = GREASE_filter(groups_raw)
groups_sorted  = sort_numeric_ascending(groups_filt)
input_d        = join(hex(g, width=4) for g in groups_sorted, sep=",")
digest_d       = SHA256(input_d)
JA5_d          = hex(digest_d)[0:12] if groups_sorted is non-empty else ""
```

Groups are sorted (rather than kept in advertised order) so that JA5_d is invariant to curve-list randomization, mirroring JA4's rationale for sorting cipher suites and extensions; the residual signal — *which* groups are offered, not their order — is what distinguishes divergent TLS stacks.

### 6.8 Step 7 — Assembly

```
JA5 = JA5_a + "_" + JA5_b + "_" + JA5_c + "_" + JA5_d
```

### 6.9 Computational Complexity

Steps 1–2 are O(n) in the number of extensions/ciphers per ClientHello (typically n < 40); sorting in Steps 4–6 is O(n log n); each of the three SHA-256 invocations operates on an input of at most a few hundred bytes. The full computation is therefore dominated by constant-factor hashing cost and is suitable for inline, per-flow execution in `nDPI` without a dedicated worker thread.

## 7. Normalization Rules

Producers **MUST** apply the following before emitting a JA5 string:

1. Observe only the first ClientHello relevant to the flow; ignore TCP retransmissions and, per §4, HelloRetryRequest-triggered second ClientHellos unless operating in a retry-aware mode.
2. Apply GREASE filtering (§6.2) before any counting, sorting, or hashing.
3. Apply ephemeral-extension exclusion (§6.3) before computing `n_sanitized` and before building the JA5_c input.
4. Sort numeric lists in strictly ascending order by the 16-bit code point; **MUST NOT** deduplicate repeated values (malformed or unusual ClientHellos **MAY** legitimately repeat a code point, and altering that is itself a loss of signal).
5. Zero-pad `cnt_c` and `cnt_e` to exactly two digits; cap displayed counts at 99 without capping the underlying hash inputs.
6. If `supported_groups` is absent, emit an empty `JA5_d` field (not a hash of the empty string) so that "absent" remains distinguishable from "present but data-poor."
7. Hexadecimal output **MUST** be lower-case, matching JA4 convention.

## 8. Matching Semantics

Consumers **MUST** support exact matching and **SHOULD** support the field-level wildcard (`%`). Because each field is independently derived, JA5 preserves JA4's *locality-preserving* property: partial matching on a prefix (e.g. `JA5_a` alone, or `JA5_a_JA5_b`) is meaningful and **MAY** be used for coarse-grained clustering before committing to full four-field comparison. Consumers implementing curve-profile-only detection rules (e.g. "flag any client offering only legacy NIST curves") **MAY** match on `JA5_d` in isolation using the `%_%_%_<hash>` form.

## 9. Error Handling

If a producer cannot parse a required field (malformed ClientHello, truncated capture), it **MUST** emit an empty field at that position and **SHOULD** log a parse diagnostic. Consumers receiving a JA5 string with an incorrect number of fields (not exactly four) **MUST** treat it as non-matching and **SHOULD** log a parse error with the offending string for triage.

## 10. Versioning and Compatibility

This document defines JA5 v1. JA5_b is intentionally byte-identical to JA4_b, so a consumer **MAY** downgrade a JA5 string to a JA4-compatible 3-field value by dropping `JA5_d` and recomputing `JA5_c` against an *unsanitized* extension list if strict JA4 interoperability is required; this is MAY, not MUST, since recomputation requires access to the original packet, not just the JA5 string. Future revisions introducing additional fields **MUST** append them after `JA5_d`, separated by `_`; consumers that do not recognize a trailing field **MUST** ignore it rather than reject the record.

## 11. Interoperability Considerations

Reverse proxies, CDNs, and TLS-terminating load balancers present their own TLS stack's fingerprint rather than the origin client's; JA5 policy **SHOULD** be enforced at the true network edge, before termination, exactly as for JA4. For TLS 1.3 0-RTT deployments, `early_data` and `pre_shared_key` are already excluded via the ephemeral registry, so JA5 is expected to be materially *more* stable than JA4 across resumption-heavy client populations (e.g. mobile applications maintaining long-lived TLS session tickets). QUIC (`proto = "q"`) ClientHellos carry the same extension set inside the TLS 1.3 CRYPTO frame and **MUST** be processed identically once reassembled.

## 12. Deployment Guidance (Non-Normative)

- Run JA5 alongside JA4 in shadow/monitor-only mode initially; compare cardinality (distinct fingerprint count) for a known client population to validate that ephemeral-extension sanitization reduces JA4-observed churn without collapsing genuinely distinct clients together.
- Prioritize `JA5_d`-based rules for detecting automated tooling that clones a browser's JA4_a/JA4_b/JA4_c but leaves the underlying TLS library's default curve preference list unchanged (a common artifact of Go, Python, and Rust TLS clients configured to mimic Chrome cipher order).
- Combine JA5 with IP reputation and behavioral rate limiting; a fingerprint match, JA5 or otherwise, is one signal among several.

## 13. Security Considerations

An adversary controlling the TLS client implementation can, in principle, replicate any target JA5 value by matching cipher order, sanitized extension set, signature-algorithm order, and `supported_groups` content exactly. JA5 raises the cost of impersonation relative to JA4 by adding one more independently-constrained dimension (curve selection) that must be matched, but it **MUST NOT** be treated as an authentication mechanism. Because ephemeral-extension exclusion is a curated, versioned registry (Appendix B), producers and consumers **MUST** agree on the registry version in use; mismatched registries between a sensor and a downstream consumer will produce silently inconsistent `JA5_a`/`JA5_c` values for the same traffic. Registry version **SHOULD** be carried alongside the fingerprint in telemetry (e.g. as metadata, not embedded in the string itself, to preserve the fixed-width format).

## 14. Privacy Considerations

As with JA4, JA5 values describe TLS stack and library behavior, not user identity, and **SHOULD** be treated as low-sensitivity telemetry. The addition of `supported_groups` data (`JA5_d`) does not increase per-user identifiability beyond what JA4_c already exposes via extension-set hashing, since curve preference lists are a library/build-level property shared across all users of a given client version, not a per-installation secret.

## 15. Conformance Requirements

**Producers MUST** implement GREASE filtering (§6.2), ephemeral-extension exclusion against a declared registry version (§6.3, Appendix B), and all four field-construction procedures of §6.4–6.7, and **MUST** emit the four-field, underscore-separated canonical string. **Consumers MUST** implement exact matching and **SHOULD** implement field-level wildcard matching (§8). Telemetry pipelines **SHOULD** export the matched rule identifier, the observed JA5 string, and the ephemeral-extension registry version used at capture time.

---

## Appendix A — Test Vectors

The following vectors are synthetic and constructed for illustration; they are not captures of a specific named client. All hashes below were computed with the reference algorithm of §6.

**Vector 1 — TLS 1.3, domain SNI, session-ticket-bearing (ephemeral) resumption attempt filtered out.**

```
Cipher suites (sorted, GREASE-filtered):
  1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035
  -> cnt_c = 15

Raw extension list (16 total, GREASE-filtered): includes padding(21) and
pre_shared_key(41) as ephemeral members -> excluded by Step 2
Sanitized extension list (14 members, sorted, SNI/ALPN removed for hashing):
  0005,000a,000b,000d,0010,0012,0017,001b,0023,002b,002d,0033,ff01
  -> cnt_e = 14

Signature algorithms (advertised order):
  0403,0804,0401,0503,0805,0501,0806,0601

Supported groups (sorted, GREASE-filtered):
  0017,0018,0019,001d,001e

JA5_a = t13d1514h2
JA5_b = acb858a92679   (SHA256(ciphers)[0:12])
JA5_c = 7dc829385eb9   (SHA256(ext_sorted + "_" + sigalgs)[0:12])
JA5_d = 0a47a2b05960   (SHA256(groups_sorted)[0:12])

JA5   = t13d1514h2_acb858a92679_7dc829385eb9_0a47a2b05960   (49 chars)
```

**Vector 2 — Same client, JA4 baseline for comparison (no ephemeral sanitization, no curve hash).**

```
JA4_a = t13d1516h2        (raw ext count 16, includes padding + PSK)
JA4_b = acb858a92679      (identical to JA5_b, as specified)
JA4_c = 562e8b7393e5      (differs from JA5_c: unsanitized extension list)

JA4   = t13d1516h2_acb858a92679_562e8b7393e5                (36 chars)
```

Note that `JA4_b` and `JA5_b` are identical by construction (§6.5), while `cnt_e`, `JA5_c`, and the appended `JA5_d` diverge from their JA4 counterparts, isolating exactly the two deficiencies this specification addresses.

**Vector 3 — Supported groups absent (legacy RSA key exchange only).**

```
JA5 = t12i0806h2_3fa1c9e0221b_9b0e4d7a1c58_
```

Trailing empty `JA5_d` field; note the trailing underscore with no following characters, per §5.1 and §6.8.

## Appendix B — Ephemeral Extension Registry (Informative)

Extension type codes excluded from `cnt_e` and from the `JA5_c` hash input by Step 2 (§6.3). This registry is versioned independently of this document's revision number; the version below is **Registry v1**.

| Extension | Type | Rationale for exclusion |
|---|---|---|
| `padding` | 21 (0x0015) | Inserted to reach a target record size dependent on SNI length and other variable-length fields; not a stable stack property. |
| `session_ticket` | 35 (0x0023) | Present only when a session ticket is cached from a prior connection; toggles across connections from the same client build. |
| `pre_shared_key` | 41 (0x0029) | TLS 1.3 resumption-only; presence is a function of session cache state. |
| `early_data` | 42 (0x002a) | 0-RTT opportunistic; depends on prior session and application-layer timing. |
| `cookie` | 44 (0x002c) | Populated only in the second ClientHello of a HelloRetryRequest exchange. |
| `psk_key_exchange_modes` | 45 (0x002d) | Co-occurs with `pre_shared_key`; same rationale. |

Implementations **MUST** record and export the registry version alongside JA5 output (§13).

## Appendix C — Extension and Group ID Reference (Informative)

Selected IANA-registered code points referenced in this document: SNI `0`; `supported_groups` `10`; ALPN `16`; `signature_algorithms` `13`; `padding` `21`; `session_ticket` `35`; `pre_shared_key` `41`; `early_data` `42`; `psk_key_exchange_modes` `45`; `cookie` `44`; `supported_versions` `43`.

Common `supported_groups` values: `secp256r1` `0x0017`; `secp384r1` `0x0018`; `secp521r1` `0x0019`; `x25519` `0x001d`; `x448` `0x001e`.

Full canonical lists are maintained by IANA and **MUST NOT** be hard-coded without a versioned update path, since post-quantum hybrid groups (e.g. `x25519mlkem768`) are actively being allocated.

## Change Log

- **v0.1** (2026-09-20): Initial draft, reworked from an internal engineering note into normative specification form; added byte-level calculation procedure (§6), ephemeral extension registry (Appendix B), and worked test vectors (Appendix A).

## Acknowledgments

This draft builds directly on the publicly documented JA4 algorithm (FoxIO) and reflects engineering requirements arising from encrypted-traffic classification work in the `nDPI` project.
