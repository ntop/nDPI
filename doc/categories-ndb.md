# nDPI `.ndb` Category Backend — Manual

## Overview

The `.ndb`  backend provides a high-performance, memory-mapped (`mmap`) category lookup engine for:

- Hostnames (FQDN)
- IPv4 networks (CIDR)
- IPv6 networks (CIDR)

It replaces large text-based category lists with a compact binary format, improving:

- Startup time
- Memory usage
- Lookup performance
- Reload behavior

---

## Backend Modes

The category backend operates in three modes (see `ndpi_category_backend_mode_t` in `ndpi_api.h`):

| User-facing name | API constant |
|------------------|--------------|
| LEGACY | `NDPI_CATEGORY_BACKEND_LEGACY` |
| HYBRID | `NDPI_CATEGORY_BACKEND_HYBRID` |
| NDB_ONLY | `NDPI_CATEGORY_BACKEND_NDB_ONLY` |

### LEGACY

- Uses the classic in-memory backends: **Patricia** for custom IP/network categories and **Aho-Corasick** (`ndpi_domain_classify_hostname()`) for hostname lists (see `ndpi_api.h` comments on `ndpi_category_backend_mode_t`)
- `.ndb` is not consulted; `ndpi_load_category_ndb_file()` rejects `NDPI_CATEGORY_BACKEND_LEGACY`. After `ndpi_unload_category_ndb()`, the module returns to this mode with no mmap database attached.

### HYBRID

- `.ndb` is consulted first
- Falls back to legacy structures if no match

### NDB_ONLY

- Only `.ndb` is used
- No fallback

---

## Runtime Behavior

### Lookup Order

**Hostname** — handled in `ndpi_match_custom_category()`.

**IP (IPv4 / IPv6)** — handled in `ndpi_get_custom_category_match()`.

### Behavior by mode

| Mode | Order |
|------|--------|
| HYBRID | `.ndb` → legacy fallback |
| NDB_ONLY | `.ndb` only |

### Thread safety

**Unix (POSIX), with global context support (`USE_GLOBAL_CONTEXT`)**

- Uses `pthread_rwlock_t`
- Read: shared lock
- Reload: exclusive lock

**Unix (POSIX), without global context support (`--disable-global-context-support`)**

- Lock calls are no-ops; there is no `pthread` dependency for this backend in that configuration.
- In this configuration, the `.ndb` backend should be considered single-threaded unless external synchronization is provided by the caller.
- Post-build check (static lib): `nm -u libndpi.a` lists *unresolved* symbols; plain `nm` lists defined and undefined symbols. Expect **no unresolved nor referenced `pthread_*` symbols** in `ndpi_category_ndb.o` nor in `libndpi.a` for the `.ndb` path when built without global context support (other optional library pieces may still pull pthread elsewhere).

**Windows**

- Uses `SRWLOCK` with the same semantics:
  - `AcquireSRWLockShared` for readers
  - `AcquireSRWLockExclusive` for reload

**Note:** while locking primitives are implemented on Windows (`SRWLOCK`), the `.ndb` backend relies on `mmap`-based loading and is primarily validated on Unix/POSIX environments. Full Windows support may depend on toolchain and runtime configuration.

**Guarantee (when internal rwlock is enabled)**

- Lookups are always protected
- Reload is atomic (pointer swap)
- Old `mmap` is released after unlock

---

## Reload behavior

Reload uses a safe swap model (see `ndpi_load_category_ndb_file()` in `ndpi_category_ndb.c`):

1. Load new `.ndb` (`mmap` + `ndb_validate`) **before** taking the module lock (so readers are not blocked during I/O)
2. Acquire write lock (`pthread_rwlock` / `SRWLOCK` exclusive)
3. Swap pointer and backend mode
4. Release lock
5. `munmap` the previous database (`ndb_unmap`)

This guarantees:

- No use-after-unmap
- No partial reads

---

## DNS validation (single source of truth)

Disk strings and normalized hostnames must satisfy `ndpi_category_hostname_labels_valid_ascii()` (`ndpi_category_host_norm.c` / `ndpi_category_host_norm.h`). The generator applies **`ndpi_category_normalize_host_for_ndb()`** first (lowercase, strip scheme/path, port stripping, `*.` wildcard prefix, then the label rules via `ndpi_category_hostname_labels_valid_ascii()`).

### Rules

- Total length: 1–253
- Labels: 1–63 characters
- Allowed characters: `[a-z0-9-]` (ASCII lowercase digits and hyphen)
- Labels cannot start or end with `-`
- No leading or trailing `.`

This validation is used in:

- The generator (`ndpi_gen_categories_bin` → `ndpi_category_normalize_host_for_ndb()`)
- The loader (`ndb_validate()` in `ndpi_category_ndb.c`)
- Runtime lookup (`ndpi_category_ndb_lookup_hostname()` → same normalization path)

---

## `.ndb` format

The on-disk layout is defined in `ndpi_categories_bin.h`. At a high level the file contains:

- Header (`ndb_header_disk_t`)
- Category table
- Domain hash buckets and domain entries
- String pool
- IPv4 entries
- IPv6 entries

### IPv4 entry (`ndb_ipv4_entry_disk_t`)

| Field | Role |
|-------|------|
| `network_be` | IPv4 network address, **network** byte order |
| `prefix_len` | Prefix length (0–32) |
| `flags`, `reserved0` | Reserved / flags (packed record) |
| `category_id` | Category identifier |

### IPv6 entry (`ndb_ipv6_entry_disk_t`)

| Field | Role |
|-------|------|
| `addr[16]` | IPv6 network address |
| `prefix_len` | Prefix length (0–128) |
| `flags`, `reserved0` | Reserved / flags (packed record) |
| `category_id` | Category identifier |

### Validation (`ndb_validate`)

On load, the file is validated.

**General**

- File bounds are checked
- Overflow-safe arithmetic is used

**IPv4 / IPv6**

- Offsets must lie inside the file
- `offset + count * sizeof(entry)` is checked safely
- `prefix_len`: IPv4 in 0–32, IPv6 in 0–128
- `category_id` must be valid

**Optional**

- Ordering may be validated (future optimization)

---

## Lookup algorithm

### IPv4 / IPv6

Uses linear LPM (longest prefix match): for each entry, if the address matches the network/prefix, keep the entry with the largest `prefix_len`.

Properties:

- Correct even without sorting
- Simple and robust
- Does not depend on generator ordering

### Future optimization

- Binary search
- Indexed lookup

---

## Generator (`ndpi_gen_categories_bin`)

### Input files

Categories must follow one of these filename patterns (see `is_domain_list_file()` / `is_ipv4_list_file()` / `is_ipv6_list_file()` in `ndpi_gen_categories_bin.c`):

```text
<id>_<name>.list
<id>_<name>.ipv4.list
<id>_<name>.ipv6.list
```

Examples:

- `10_web.list`
- `20_vpn.list`
- `10_corp.ipv4.list` / `10_corp.ipv6.list` (IP-only lists)

### Rules

- `id` must satisfy: `0 < id < NDPI_PROTOCOL_NUM_CATEGORIES`
- The generator fails early on invalid filename or invalid ID

---

## IP canonicalization and deduplication

### IPv4

- Input is masked with `ipv4_apply_mask()`

### IPv6

- The network is masked to the prefix (`ipv6_apply_mask()` in `ndpi_gen_categories_bin.c`) when building canonical keys and on-disk rows

### Deduplication

- Based on canonical key: **network + prefix**
- Equivalent entries collapse into one

Example:

```text
10.1.2.3/16
10.1.0.0/16
```

→ same network → single entry

---

## Conflict handling

All of this is **generator-time** (`ndpi_gen_categories_bin`, `--conflict-policy`); runtime only does LPM over the emitted rows.

- **Duplicate key, same category:** collapsed (deduplication).
- **Duplicate key, different categories:** default **`error`** (exit); optional policies `warn-ignore`, `first-wins`, `last-wins` resolve which category wins at build time.
- **Distinct overlapping prefixes:** longest-prefix match at runtime (see [Lookup algorithm](#lookup-algorithm)).

---

## Integration in runtime

| Concern | Entry point |
|---------|--------------|
| Hostname | `ndpi_match_custom_category()` |
| IP | `ndpi_get_custom_category_match()` |
| Backend mode | Shared across both paths (`ndpi_str->category_backend_mode`) |

---

## Testing

### Unit (minimum)

The `category_ndb_smoke_unit()` test in `tests/unit/unit.c` (non-Windows) covers:

- Hostname hit (`ndpi_match_custom_category`)
- IPv4 LPM and a `/32` row (`ndpi_get_custom_category_match`)
- Hostname miss under `NDB_ONLY`
- Loading **`HYBRID`** and exercising an **IPv6 miss** (no `.ndb` IPv6 rows and no Patricia entries in the test module — not a full “`.ndb` miss → list hit” integration)

Example scenario:

- `10.0.0.0/8` → WEB  
- `10.1.0.0/16` → VPN  

Then:

- `10.1.2.3` → VPN (longer prefix)
- `10.9.9.9` → WEB

### Fuzz (optional)

- Extended coverage
- Includes IP path (`fuzz/fuzz_match_custom_category.c`)

---

## Build notes

### Generator

Built as a separate tool: `ndpi_gen_categories_bin`.

Requires `ndpi_category_host_norm.h` (shared hostname normalization / validation).

### Known issues

- `libndpi.so` may fail linking in some custom environments (glibc / toolchain quirks)
- `libndpi.a` is sufficient for most use cases

---

## Usage

### Generate `.ndb`

```sh
ndpi_gen_categories_bin \
  -i /path/categories \
  -o /path/base.ndb
# optional: -V "build label" (stored in the on-disk header)
```

### Run `ndpiReader`

```sh
ndpiReader --categories-bin /path/base.ndb
```

### Enable reload

```sh
ndpiReader --categories-bin /path/base.ndb \
  --category-ndb-reload-interval <seconds>
```

---

## Summary

This implementation provides:

- Safe hot-reload
- Unified validation
- Full support for hostname, IPv4, and IPv6
- Deterministic behavior across modes
- Clean separation between generator and runtime

---

## Next steps (future work)

- Indexed lookup for IP (performance)
- RCU-based lock-free reads
- Extended validation (ordering contract)
- Metrics (hits, misses, latency)
