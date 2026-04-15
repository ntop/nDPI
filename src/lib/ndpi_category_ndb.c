/*
 * ndpi_category_ndb.c — mmap .ndb category backend (hostname + IPv4/IPv6)
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(WIN32) && !defined(_MSC_VER)
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "ndpi_api.h"
#include "ndpi_private.h"
#include "ndpi_categories_bin.h"
#include "ndpi_category_host_norm.h"

struct ndpi_category_ndb {
#if defined(WIN32) || defined(_MSC_VER)
  HANDLE file_handle;
  HANDLE mapping_handle;
#else
  int fd;
#endif
  size_t map_size;
  void *map_base;
  const ndb_header_disk_t *hdr;
  const ndb_category_disk_t *categories;
  const ndb_bucket_disk_t *buckets;
  const ndb_entry_disk_t *entries;
  const char *strpool;
  const ndb_ipv4_entry_disk_t *ipv4_entries;
  const ndb_ipv6_entry_disk_t *ipv6_entries;
};

static uint64_t fnv1a64(const char *s, size_t len) {
  uint64_t h = 1469598103934665603ULL;
  for(size_t i = 0; i < len; ++i) {
    h ^= (unsigned char)s[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static int is_power_of_two_u64(uint64_t n) { return n != 0 && (n & (n - 1)) == 0; }

/* True if [off, off+count*elem) is not fully contained in [0,file_size) or if multiply overflows. */
static int ndb_u64_range_invalid(uint64_t off, uint64_t count, uint64_t elem, uint64_t file_size) {
  if(elem == 0)
    return 1;
  if(count == 0)
    return off > file_size;
  if(count > UINT64_MAX / elem)
    return 1;
  {
    uint64_t nbytes = count * elem;
    if(off > file_size || nbytes > file_size - off)
      return 1;
  }
  return 0;
}

static int ndb_ipv4_prefix_matches(uint32_t addr_be, uint32_t net_be, uint8_t pl) {
  uint32_t a, n, mask_host;

  if(pl > 32)
    return 0;
  a = ntohl(addr_be);
  n = ntohl(net_be);
  if(pl == 0)
    return 1;
  if(pl == 32)
    return a == n;
  mask_host = (uint32_t)(0xFFFFFFFFu << (32u - (uint32_t)pl));
  return (a & mask_host) == (n & mask_host);
}

static int ndb_ipv6_prefix_matches(const uint8_t *addr, const uint8_t *net, uint8_t pl) {
  unsigned i, full_bytes, rem_bits;

  if(pl > 128)
    return 0;
  full_bytes = (unsigned)pl / 8;
  for(i = 0; i < full_bytes; i++) {
    if(addr[i] != net[i])
      return 0;
  }
  rem_bits = (unsigned)pl % 8;
  if(rem_bits) {
    uint8_t m = (uint8_t)(0xFFu << (8 - rem_bits));
    if((addr[full_bytes] & m) != (net[full_bytes] & m))
      return 0;
  }
  return 1;
}

static int ndb_validate(const ndb_header_disk_t *hdr, size_t file_size) {
  uint64_t i;

  if(memcmp(hdr->magic, NDB_MAGIC, 4) != 0)
    return -1;
  if(hdr->format_version != NDB_FORMAT_VERSION)
    return -2;
  if(hdr->file_size != (uint64_t)file_size)
    return -3;
  if(hdr->domain_bucket_count == 0 || !is_power_of_two_u64(hdr->domain_bucket_count))
    return -4;

  if(hdr->categories_off > file_size || hdr->domain_buckets_off > file_size ||
      hdr->domain_entries_off > file_size || hdr->string_pool_off > file_size ||
      hdr->ipv4_entries_off > file_size || hdr->ipv6_entries_off > file_size)
    return -5;

  if(ndb_u64_range_invalid(hdr->categories_off, hdr->category_count, sizeof(ndb_category_disk_t), file_size))
    return -7;

  if(ndb_u64_range_invalid(hdr->domain_buckets_off, hdr->domain_bucket_count, sizeof(ndb_bucket_disk_t),
         file_size))
    return -8;

  if(ndb_u64_range_invalid(hdr->domain_entries_off, hdr->domain_entry_count, sizeof(ndb_entry_disk_t), file_size))
    return -10;

  if(hdr->string_pool_off > file_size || hdr->string_pool_size > file_size - hdr->string_pool_off)
    return -11;

  if(ndb_u64_range_invalid(hdr->ipv4_entries_off, hdr->ipv4_entry_count, sizeof(ndb_ipv4_entry_disk_t), file_size))
    return -14;

  if(ndb_u64_range_invalid(hdr->ipv6_entries_off, hdr->ipv6_entry_count, sizeof(ndb_ipv6_entry_disk_t), file_size))
    return -17;

  const ndb_category_disk_t *cats =
    (const ndb_category_disk_t *)((const char *)hdr + hdr->categories_off);
  const ndb_bucket_disk_t *bucks =
    (const ndb_bucket_disk_t *)((const char *)hdr + hdr->domain_buckets_off);
  const ndb_entry_disk_t *ents =
    (const ndb_entry_disk_t *)((const char *)hdr + hdr->domain_entries_off);
  const char *pool = (const char *)hdr + hdr->string_pool_off;
  const ndb_ipv4_entry_disk_t *ipv4e =
    (const ndb_ipv4_entry_disk_t *)((const char *)hdr + hdr->ipv4_entries_off);
  const ndb_ipv6_entry_disk_t *ipv6e =
    (const ndb_ipv6_entry_disk_t *)((const char *)hdr + hdr->ipv6_entries_off);

  for(i = 0; i < hdr->category_count; i++) {
    uint32_t cid = cats[i].id;
    if(cid == 0 || cid >= NDPI_PROTOCOL_NUM_CATEGORIES)
      return -20;
    if((uint64_t)cats[i].name_off >= hdr->string_pool_size)
      return -21;
  }

  uint64_t sum = 0;
  for(i = 0; i < hdr->domain_bucket_count; i++) {
    uint64_t f = bucks[i].first;
    uint64_t c = bucks[i].count;
    sum += c;
    if(f + c > hdr->domain_entry_count)
      return -30;
  }
  if(sum != hdr->domain_entry_count)
    return -31;

  for(i = 0; i < hdr->domain_entry_count; i++) {
    uint32_t cid = ents[i].category_id;
    if(cid == 0 || cid >= NDPI_PROTOCOL_NUM_CATEGORIES)
      return -40;
    if((uint64_t)ents[i].domain_off + (uint64_t)ents[i].domain_len > hdr->string_pool_size)
      return -41;
    if(ents[i].domain_len == 0)
      return -42;
    const char *ds = pool + ents[i].domain_off;
    if(strlen(ds) != ents[i].domain_len)
      return -43;
    if(!ndpi_category_hostname_labels_valid_ascii(ds))
      return -44;
  }

  for(i = 0; i < hdr->ipv4_entry_count; i++) {
    uint32_t cid = ipv4e[i].category_id;
    if(cid == 0 || cid >= NDPI_PROTOCOL_NUM_CATEGORIES)
      return -50;
    if(ipv4e[i].prefix_len > 32)
      return -51;
  }

  for(i = 0; i < hdr->ipv6_entry_count; i++) {
    uint32_t cid = ipv6e[i].category_id;
    if(cid == 0 || cid >= NDPI_PROTOCOL_NUM_CATEGORIES)
      return -60;
    if(ipv6e[i].prefix_len > 128)
      return -61;
  }

  return 0;
}

static void ndb_unmap(struct ndpi_category_ndb *db) {
  if(!db)
    return;
#if defined(WIN32) || defined(_MSC_VER)
  if(db->map_base)
    UnmapViewOfFile(db->map_base);
  if(db->mapping_handle && db->mapping_handle != INVALID_HANDLE_VALUE)
    CloseHandle(db->mapping_handle);
  if(db->file_handle && db->file_handle != INVALID_HANDLE_VALUE)
    CloseHandle(db->file_handle);
#else
  if(db->map_base && db->map_base != MAP_FAILED)
    munmap(db->map_base, db->map_size);
  if(db->fd >= 0)
    close(db->fd);
#endif
  ndpi_free(db);
}

#if defined(WIN32) || defined(_MSC_VER)
static struct ndpi_category_ndb *ndb_mmap_path(const char *path, int *err_out) {
  struct ndpi_category_ndb *db;
  HANDLE fh = INVALID_HANDLE_VALUE;
  HANDLE mh = INVALID_HANDLE_VALUE;
  void *map = NULL;
  LARGE_INTEGER sz;

  fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if(fh == INVALID_HANDLE_VALUE) {
    if(err_out) *err_out = -(int)GetLastError();
    return NULL;
  }

  if(!GetFileSizeEx(fh, &sz)) {
    if(err_out) *err_out = -(int)GetLastError();
    CloseHandle(fh);
    return NULL;
  }

  if(sz.QuadPart < (LONGLONG)sizeof(ndb_header_disk_t)) {
    if(err_out) *err_out = -EINVAL;
    CloseHandle(fh);
    return NULL;
  }

  mh = CreateFileMappingA(fh, NULL, PAGE_READONLY, (DWORD)(sz.QuadPart >> 32),
      (DWORD)(sz.QuadPart & 0xFFFFFFFFu), NULL);
  if(mh == NULL) {
    if(err_out) *err_out = -(int)GetLastError();
    CloseHandle(fh);
    return NULL;
  }

  map = MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0);
  if(map == NULL) {
    if(err_out) *err_out = -(int)GetLastError();
    CloseHandle(mh);
    CloseHandle(fh);
    return NULL;
  }

  const ndb_header_disk_t *hdr = (const ndb_header_disk_t *)map;
  int vr = ndb_validate(hdr, (size_t)sz.QuadPart);
  if(vr != 0) {
    if(err_out) *err_out = vr;
    UnmapViewOfFile(map);
    CloseHandle(mh);
    CloseHandle(fh);
    return NULL;
  }

  db = (struct ndpi_category_ndb *)ndpi_malloc(sizeof(*db));
  if(!db) {
    if(err_out) *err_out = -ENOMEM;
    UnmapViewOfFile(map);
    CloseHandle(mh);
    CloseHandle(fh);
    return NULL;
  }

  db->file_handle = fh;
  db->mapping_handle = mh;
  db->map_size = (size_t)sz.QuadPart;
  db->map_base = map;
  db->hdr = hdr;
  db->categories = (const ndb_category_disk_t *)((const char *)map + hdr->categories_off);
  db->buckets = (const ndb_bucket_disk_t *)((const char *)map + hdr->domain_buckets_off);
  db->entries = (const ndb_entry_disk_t *)((const char *)map + hdr->domain_entries_off);
  db->strpool = (const char *)map + hdr->string_pool_off;
  db->ipv4_entries = (const ndb_ipv4_entry_disk_t *)((const char *)map + hdr->ipv4_entries_off);
  db->ipv6_entries = (const ndb_ipv6_entry_disk_t *)((const char *)map + hdr->ipv6_entries_off);

  if(err_out) *err_out = 0;
  return db;
}
#else
static struct ndpi_category_ndb *ndb_mmap_path(const char *path, int *err_out) {
  struct ndpi_category_ndb *db;
  struct stat st;
  void *map = MAP_FAILED;
  int fd = -1;

  fd = open(path, O_RDONLY);
  if(fd < 0) {
    if(err_out) *err_out = -errno;
    return NULL;
  }

  if(fstat(fd, &st) != 0) {
    if(err_out) *err_out = -errno;
    close(fd);
    return NULL;
  }

  if(st.st_size < (off_t)sizeof(ndb_header_disk_t)) {
    if(err_out) *err_out = -EINVAL;
    close(fd);
    return NULL;
  }

  map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if(map == MAP_FAILED) {
    if(err_out) *err_out = -errno;
    close(fd);
    return NULL;
  }

  const ndb_header_disk_t *hdr = (const ndb_header_disk_t *)map;
  int vr = ndb_validate(hdr, (size_t)st.st_size);
  if(vr != 0) {
    if(err_out) *err_out = vr;
    munmap(map, (size_t)st.st_size);
    close(fd);
    return NULL;
  }

  db = (struct ndpi_category_ndb *)ndpi_malloc(sizeof(*db));
  if(!db) {
    if(err_out) *err_out = -ENOMEM;
    munmap(map, (size_t)st.st_size);
    close(fd);
    return NULL;
  }

  db->fd = fd;
  db->map_size = (size_t)st.st_size;
  db->map_base = map;
  db->hdr = hdr;
  db->categories = (const ndb_category_disk_t *)((const char *)map + hdr->categories_off);
  db->buckets = (const ndb_bucket_disk_t *)((const char *)map + hdr->domain_buckets_off);
  db->entries = (const ndb_entry_disk_t *)((const char *)map + hdr->domain_entries_off);
  db->strpool = (const char *)map + hdr->string_pool_off;
  db->ipv4_entries = (const ndb_ipv4_entry_disk_t *)((const char *)map + hdr->ipv4_entries_off);
  db->ipv6_entries = (const ndb_ipv6_entry_disk_t *)((const char *)map + hdr->ipv6_entries_off);

  if(err_out) *err_out = 0;
  return db;
}
#endif

static int ndb_lookup_exact(const struct ndpi_category_ndb *db, const char *host, uint32_t *category_id) {
  size_t len = strlen(host);
  uint64_t h = fnv1a64(host, len);
  size_t bucket = (size_t)(h & (db->hdr->domain_bucket_count - 1));

  uint32_t first = db->buckets[bucket].first;
  uint32_t count = db->buckets[bucket].count;

  for(uint32_t j = 0; j < count; j++) {
    const ndb_entry_disk_t *e = &db->entries[first + j];
    if(e->hash != h)
      continue;
    if(e->domain_len != len)
      continue;

    const char *s = db->strpool + e->domain_off;
    if(memcmp(s, host, len) == 0) {
      *category_id = e->category_id;
      return 0;
    }
  }
  return -1;
}

int ndpi_category_ndb_lookup_hostname(struct ndpi_category_ndb *db, const char *name, u_int name_len,
    uint32_t *category_id) {
  char buf[512];
  char *candidate;
  int first = 1;

  if(!db || !name || !category_id || name_len == 0)
    return -1;

  if(name_len >= sizeof(buf))
    name_len = sizeof(buf) - 1;
  memcpy(buf, name, name_len);
  buf[name_len] = '\0';

  if(ndpi_category_normalize_host_for_ndb(buf, buf, sizeof(buf)) != 0)
    return -1;

  candidate = buf;
  while(candidate && *candidate) {
    if(first || strchr(candidate, '.') != NULL) {
      if(ndb_lookup_exact(db, candidate, category_id) == 0)
        return 0;
    }
    first = 0;
    char *dot = strchr(candidate, '.');
    if(!dot)
      break;
    candidate = dot + 1;
  }
  return -1;
}

int ndpi_category_ndb_lookup_ipv4(struct ndpi_category_ndb *db, uint32_t addr_be, uint32_t *category_id) {
  uint64_t i;
  uint8_t best_pl = 0;
  int found = 0;
  uint32_t best_cat = 0;

  if(!db || !category_id)
    return -1;

  /*
   * Linear scan for longest-prefix match. The generator emits sorted IPv4 rows; future optimization:
   * binary search window + LPM when profiling shows this path is hot on large IP tables.
   */
  for(i = 0; i < db->hdr->ipv4_entry_count; i++) {
    const ndb_ipv4_entry_disk_t *e = &db->ipv4_entries[i];
    if(!ndb_ipv4_prefix_matches(addr_be, e->network_be, e->prefix_len))
      continue;
    if(!found || e->prefix_len > best_pl) {
      best_pl = e->prefix_len;
      best_cat = e->category_id;
      found = 1;
    }
  }

  if(!found)
    return -1;
  *category_id = best_cat;
  return 0;
}

int ndpi_category_ndb_lookup_ipv6(struct ndpi_category_ndb *db, const uint8_t addr[16], uint32_t *category_id) {
  uint64_t i;
  uint8_t best_pl = 0;
  int found = 0;
  uint32_t best_cat = 0;

  if(!db || !addr || !category_id)
    return -1;

  /* Same strategy as IPv4; sorted on-disk rows from the generator — see IPv4 comment. */
  for(i = 0; i < db->hdr->ipv6_entry_count; i++) {
    const ndb_ipv6_entry_disk_t *e = &db->ipv6_entries[i];
    if(!ndb_ipv6_prefix_matches(addr, e->addr, e->prefix_len))
      continue;
    if(!found || e->prefix_len > best_pl) {
      best_pl = e->prefix_len;
      best_cat = e->category_id;
      found = 1;
    }
  }

  if(!found)
    return -1;
  *category_id = best_cat;
  return 0;
}

void ndpi_category_ndb_rwlock_init(struct ndpi_detection_module_struct *ndpi_str) {
  if(!ndpi_str)
    return;
#if defined(WIN32) || defined(_MSC_VER)
  /* SRWLOCK (Vista+): shared for lookups, exclusive for load/unload; same contract as pthread_rwlock. */
  InitializeSRWLock(&ndpi_str->category_ndb_lock);
  ndpi_str->category_ndb_lock_inited = 1;
#elif defined(USE_GLOBAL_CONTEXT)
  if(pthread_rwlock_init(&ndpi_str->category_ndb_lock, NULL) == 0)
    ndpi_str->category_ndb_lock_inited = 1;
  else
    ndpi_str->category_ndb_lock_inited = 0;
#else
  (void)ndpi_str;
#endif
}

void ndpi_category_ndb_rwlock_destroy(struct ndpi_detection_module_struct *ndpi_str) {
  if(!ndpi_str)
    return;
#if defined(WIN32) || defined(_MSC_VER)
  ndpi_str->category_ndb_lock_inited = 0;
#elif defined(USE_GLOBAL_CONTEXT)
  if(ndpi_str->category_ndb_lock_inited) {
    pthread_rwlock_destroy(&ndpi_str->category_ndb_lock);
    ndpi_str->category_ndb_lock_inited = 0;
  }
#else
  (void)ndpi_str;
#endif
}

void ndpi_category_ndb_lock_rd(struct ndpi_detection_module_struct *ndpi_str) {
  if(!ndpi_str)
    return;
#if defined(WIN32) || defined(_MSC_VER)
  if(!ndpi_str->category_ndb_lock_inited)
    return;
  AcquireSRWLockShared(&ndpi_str->category_ndb_lock);
#elif defined(USE_GLOBAL_CONTEXT)
  if(!ndpi_str->category_ndb_lock_inited)
    return;
  pthread_rwlock_rdlock(&ndpi_str->category_ndb_lock);
#else
  (void)ndpi_str;
#endif
}

void ndpi_category_ndb_unlock_rd(struct ndpi_detection_module_struct *ndpi_str) {
  if(!ndpi_str)
    return;
#if defined(WIN32) || defined(_MSC_VER)
  if(!ndpi_str->category_ndb_lock_inited)
    return;
  ReleaseSRWLockShared(&ndpi_str->category_ndb_lock);
#elif defined(USE_GLOBAL_CONTEXT)
  if(!ndpi_str->category_ndb_lock_inited)
    return;
  pthread_rwlock_unlock(&ndpi_str->category_ndb_lock);
#else
  (void)ndpi_str;
#endif
}

void ndpi_category_ndb_lock_wr(struct ndpi_detection_module_struct *ndpi_str) {
  if(!ndpi_str)
    return;
#if defined(WIN32) || defined(_MSC_VER)
  if(!ndpi_str->category_ndb_lock_inited)
    return;
  AcquireSRWLockExclusive(&ndpi_str->category_ndb_lock);
#elif defined(USE_GLOBAL_CONTEXT)
  if(!ndpi_str->category_ndb_lock_inited)
    return;
  pthread_rwlock_wrlock(&ndpi_str->category_ndb_lock);
#else
  (void)ndpi_str;
#endif
}

void ndpi_category_ndb_unlock_wr(struct ndpi_detection_module_struct *ndpi_str) {
  if(!ndpi_str)
    return;
#if defined(WIN32) || defined(_MSC_VER)
  if(!ndpi_str->category_ndb_lock_inited)
    return;
  ReleaseSRWLockExclusive(&ndpi_str->category_ndb_lock);
#elif defined(USE_GLOBAL_CONTEXT)
  if(!ndpi_str->category_ndb_lock_inited)
    return;
  pthread_rwlock_unlock(&ndpi_str->category_ndb_lock);
#else
  (void)ndpi_str;
#endif
}

int ndpi_load_category_ndb_file(struct ndpi_detection_module_struct *ndpi_str, const char *path,
    ndpi_category_backend_mode_t mode) {
  struct ndpi_category_ndb *newdb, *olddb;
  int err = 0;

  if(!ndpi_str)
    return -2;
  if(!path || path[0] == '\0')
    return -2;
  if(mode == NDPI_CATEGORY_BACKEND_LEGACY)
    return -2;
  if(mode != NDPI_CATEGORY_BACKEND_NDB_ONLY && mode != NDPI_CATEGORY_BACKEND_HYBRID)
    return -2;

  newdb = ndb_mmap_path(path, &err);
  if(!newdb)
    return err ? err : -1;

  ndpi_category_ndb_lock_wr(ndpi_str);

  olddb = (struct ndpi_category_ndb *)ndpi_str->category_ndb;
  ndpi_str->category_ndb = (void *)newdb;
  ndpi_str->category_backend_mode = (u_int8_t)mode;

  ndpi_category_ndb_unlock_wr(ndpi_str);

  if(olddb)
    ndb_unmap(olddb);

  return 0;
}

void ndpi_unload_category_ndb(struct ndpi_detection_module_struct *ndpi_str) {
  struct ndpi_category_ndb *olddb;

  if(!ndpi_str)
    return;

  ndpi_category_ndb_lock_wr(ndpi_str);

  olddb = (struct ndpi_category_ndb *)ndpi_str->category_ndb;
  ndpi_str->category_ndb = NULL;
  /* Always LEGACY once the mmap backend is detached (no NDB_* mode without a live db). */
  ndpi_str->category_backend_mode = NDPI_CATEGORY_BACKEND_LEGACY;

  ndpi_category_ndb_unlock_wr(ndpi_str);

  if(olddb)
    ndb_unmap(olddb);
}
