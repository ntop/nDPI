/*
 * ndpi_categories_bin.h — on-disk .ndb format (single source of truth)
 */
#ifndef NDPI_CATEGORIES_BIN_H
#define NDPI_CATEGORIES_BIN_H

#include <stdint.h>
#include <stddef.h>

#define NDB_MAGIC "NDB1"
#define NDB_FORMAT_VERSION 1

typedef struct {
  uint32_t id;
  uint32_t name_off;
} ndb_category_disk_t;

typedef struct {
  uint64_t hash;
  uint32_t domain_off;
  uint16_t domain_len;
  uint16_t flags;
  uint32_t category_id;
} ndb_entry_disk_t;

typedef struct {
  uint32_t first;
  uint32_t count;
} ndb_bucket_disk_t;

/* Packed on-disk records: #pragma pack works with MSVC, GCC, and Clang. */
#pragma pack(push, 1)
typedef struct {
  uint32_t network_be; /* IPv4 network address, network byte order */
  uint8_t prefix_len;  /* 0..32 */
  uint8_t flags;
  uint16_t reserved0;
  uint32_t category_id;
} ndb_ipv4_entry_disk_t;

typedef struct {
  uint8_t addr[16]; /* IPv6 network address */
  uint8_t prefix_len; /* 0..128 */
  uint8_t flags;
  uint16_t reserved0;
  uint32_t category_id;
} ndb_ipv6_entry_disk_t;

typedef struct {
  char magic[4];
  uint32_t format_version;
  uint32_t flags;
  uint32_t reserved0;

  uint64_t build_unix_time;
  char base_version[64];

  uint64_t category_count;

  uint64_t domain_entry_count;
  uint64_t domain_bucket_count;
  uint64_t string_pool_size;

  uint64_t ipv4_entry_count;
  uint64_t ipv6_entry_count;

  uint64_t categories_off;
  uint64_t domain_buckets_off;
  uint64_t domain_entries_off;
  uint64_t string_pool_off;
  uint64_t ipv4_entries_off;
  uint64_t ipv6_entries_off;

  uint64_t file_size;
  uint64_t reserved1;
} ndb_header_disk_t;
#pragma pack(pop)

#endif /* NDPI_CATEGORIES_BIN_H */
