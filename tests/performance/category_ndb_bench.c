/*
 * category_ndb_bench.c — category lookup benchmark (.ndb vs legacy), hot path only.
 *
 * Default: micro profile (1 host, 3 IPv4 rules, 2 buckets) + temp .ndb, same cases as legacy mirror.
 * Positional: ./category_ndb_bench [iters] [rounds] when argv contains no "--" (backward compatible).
 * Flags: see --help (--mode, --profile, --backend, --ndb-file, --out-file, --only-*, RSS, block percentiles).
 *
 * Pipeline: generate (unless --ndb-file / --skip-build) -> load .ndb -> optional legacy mirror ->
 *           optional --only-load exit -> timed lookups. .ndb IPv4 path is O(N) over ipv4_entry_count.
 */

#if defined(_WIN32) || defined(WIN32)
#include <stdio.h>
int main(void) {
  puts("category_ndb_bench: not run on Windows (uses POSIX temp file / mmap bench)");
  return 0;
}
#else

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef __APPLE__
#include <mach/mach.h>
#endif

#include "ndpi_api.h"
#include "ndpi_categories_bin.h"
#include "ndpi_config.h"
#include "ndpi_define.h"

#ifdef USE_GLOBAL_CONTEXT
#define GC_LABEL "USE_GLOBAL_CONTEXT=1"
#else
#define GC_LABEL "USE_GLOBAL_CONTEXT=0"
#endif

#define LEGACY_MAX_HOSTS_DEFAULT 500000u
#define LEGACY_MAX_IPV4_RULES_DEFAULT 200000u
#define QUERY_POOL_CAP 4096u
/* Max synthetic IPv4 rows (exact + prefix). Stress profile uses 200k+200k; keep headroom. */
#define IPV4_RULE_CAP (512u * 1024u)
#define DEFAULT_BLOCKS_PER_ROUND 64

enum bench_backend { BACKEND_NDB = 1, BACKEND_LEGACY = 2, BACKEND_BOTH = 3 };
enum bench_mode { MODE_FIXED = 0, MODE_MIXED_BY_CASE = 1, MODE_MIXED_GLOBAL = 2 };

typedef struct {
  size_t iters;
  int rounds;
  size_t warm;
  unsigned seed;
  enum bench_backend backend;
  int backend_explicit; /* 1 if user passed --backend */
  enum bench_mode mode;
  int profile_set; /* 1 if --profile */
  int iters_explicit; /* 1 if --iters or positional iters */
  char profile[32]; /* micro|scale|stress|scale_lookup_light|stress_lookup_light */
  char ndb_file[4096];
  char out_file[4096];
  int skip_build;
  int only_generate;
  int only_load;
  int only_lookup;
  int force_legacy;
  int lpm_realistic; /* 0=clean, 1=realistic overlapping (subset) */
  size_t hosts;
  size_t ipv4_exact;
  size_t ipv4_prefix;
  size_t domain_buckets;
  int blocks_per_round;
  /* runtime warnings */
  int warn_ipv4_linear;
  int warn_unfair_compare;
  int warn_legacy_fallback;
  char unfair_reason[256];
} bench_opts_t;

/* Must match fnv1a64 in src/lib/ndpi_category_ndb.c */
static uint64_t bench_fnv1a64(const char *s, size_t len) {
  uint64_t h = 1469598103934665603ULL;
  size_t i;
  for(i = 0; i < len; ++i) {
    h ^= (unsigned char)s[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static int is_power_of_two_u64(uint64_t n) {
  return n != 0 && (n & (n - 1)) == 0;
}

static int rss_bytes_self(size_t *out_bytes) {
#ifdef __APPLE__
  struct task_basic_info tbi;
  mach_msg_type_number_t cnt = TASK_BASIC_INFO_COUNT;
  kern_return_t kr = task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&tbi, &cnt);
  if(kr != KERN_SUCCESS)
    return -1;
  *out_bytes = (size_t)tbi.resident_size;
  return 0;
#else
  FILE *f;
  char line[256];
  unsigned long kb = 0;

  f = fopen("/proc/self/status", "r");
  if(!f)
    return -1;
  while(fgets(line, sizeof(line), f)) {
    if(strncmp(line, "VmRSS:", 6) == 0) {
      if(sscanf(line + 6, "%lu", &kb) == 1) {
        *out_bytes = (size_t)kb * 1024ul;
        fclose(f);
        return 0;
      }
    }
  }
  fclose(f);
  return -1;
#endif
}

static void print_usage(const char *prog) {
  printf(
      "Usage: %s [options]\n"
      "       %s [iterations] [rounds]   (legacy, if argv has no '--')\n"
      "\n"
      "Options:\n"
      "  --help                 This help\n"
      "  --iters N              Lookups per timed round (default 2000000).\n"
      "                         --profile scale|stress: default 100000 when neither --iters nor legacy\n"
      "                         positional [iterations] is given (both count as explicit --iters).\n"
      "  --rounds N             Timed rounds for median (default 5, min 3)\n"
      "  --warm N               Warm-up iterations per round (default derived)\n"
      "  --backend ndb|legacy|both   (default both)\n"
      "  --mode fixed|mixed_by_case|mixed_global   (default fixed; mixed_by_case varies per lookup case)\n"
      "                         mixed_global: same per-case string pools as mixed_by_case, not a true\n"
      "                         cross-API mix; noisier, not a CI baseline.\n"
      "  --profile micro|scale|stress|scale_lookup_light|stress_lookup_light\n"
      "                         scale|stress: same synthetic DB shape (hosts/IPv4/buckets), fewer default\n"
      "                         timed lookups unless --iters or positional [iterations] is provided.\n"
      "                         *_lookup_light: same DB shape as scale|stress, lighter preset lookups\n"
      "                         (iters 50000, rounds 3; does not use the scale/stress default-iters rule).\n"
      "  --ndb-file PATH        Load this .ndb (no synthetic build; precedence over generator)\n"
      "                         External `.ndb` files are best suited for load-only measurements (`--only-load`).\n"
      "                         For lookup benchmarks, results are only meaningful if the file matches the\n"
      "                         synthetic generator conventions used by this benchmark (fixed strings/pools).\n"
      "  --out-file PATH        Persist synthetic .ndb here; without it, temp file + unlink at exit\n"
      "  --skip-build           No synthetic generation (requires --ndb-file)\n"
      "  --only-generate        Write synthetic .ndb to --out-file and exit (requires --out-file)\n"
      "  --only-load            Print load metrics and exit (no lookup timing)\n"
      "  --only-lookup          After load, only report lookup timings\n"
      "  --hosts N              Synthetic hostname rows\n"
      "  --ipv4-exact N         Synthetic /32 rows\n"
      "  --ipv4-prefix N        Synthetic prefix rows\n"
      "  --domain-buckets N     Hash buckets (power of two, >=2)\n"
      "  --seed U               RNG seed (reserved / reproducibility hooks)\n"
      "  --lpm clean|realistic  IPv4 table style for synthetic generator\n"
      "  --force-legacy         Override default %u-host / %u-IPv4-rule cap; build the legacy mirror\n"
      "                         anyway (may OOM).\n"
      "  --blocks-per-round K   Block samples per round for percentiles (default %d)\n"
      "\n"
      "Default iters: with --profile scale|stress, timed lookups default to 100000 unless you pass\n"
      "  --iters or positional [iterations] (both count as explicit; see --iters above).\n"
      "\n"
      "Recommended (from repo root after build; adjust if out-of-tree):\n"
      "  ./tests/performance/category_ndb_bench --profile micro --backend both --mode fixed\n"
      "  ./tests/performance/category_ndb_bench --profile micro --backend both --mode mixed_by_case\n"
      "  ./tests/performance/category_ndb_bench --profile scale --backend both --only-load\n"
      "  ./tests/performance/category_ndb_bench --profile scale --backend both --mode mixed_by_case\n"
      "  ./tests/performance/category_ndb_bench --profile stress --backend ndb --only-load\n"
      "\n"
      "Pipeline: generate (unless --ndb-file or --skip-build) -> load_ndb -> optional legacy build ->\n"
      "          optional --only-load exit -> lookup benchmarks.\n"
      "\n"
      "Note: .ndb IPv4 lookup is O(N) over ipv4_entry_count; large N stresses current implementation.\n",
      prog, prog, (unsigned)LEGACY_MAX_HOSTS_DEFAULT, (unsigned)LEGACY_MAX_IPV4_RULES_DEFAULT, DEFAULT_BLOCKS_PER_ROUND);
}

static void opts_defaults(bench_opts_t *o) {
  memset(o, 0, sizeof(*o));
  o->iters = 2000000;
  o->rounds = 5;
  o->warm = 0; /* computed later */
  o->seed = 1;
  o->backend = BACKEND_BOTH;
  o->backend_explicit = 0;
  o->mode = MODE_FIXED;
  strcpy(o->profile, "micro");
  o->domain_buckets = 2;
  o->hosts = 1;
  o->ipv4_exact = 1; /* will align with micro 3 ipv4 total */
  o->ipv4_prefix = 2;
  o->blocks_per_round = DEFAULT_BLOCKS_PER_ROUND;
  o->iters_explicit = 0;
}

static void profile_apply(bench_opts_t *o) {
  if(strcmp(o->profile, "micro") == 0) {
    o->hosts = 1;
    o->ipv4_exact = 1;
    o->ipv4_prefix = 2;
    o->domain_buckets = 2;
  } else if(strcmp(o->profile, "scale") == 0) {
    o->hosts = 200000;
    o->ipv4_exact = 50000;
    o->ipv4_prefix = 50000;
    o->domain_buckets = 1u << 18;
  } else if(strcmp(o->profile, "stress") == 0) {
    o->hosts = 2000000;
    o->ipv4_exact = 200000;
    o->ipv4_prefix = 200000;
    o->domain_buckets = 1u << 20;
    if(o->backend == BACKEND_BOTH && !o->backend_explicit)
      o->backend = BACKEND_NDB; /* stress defaults to ndb-only unless --backend was passed */
  } else if(strcmp(o->profile, "scale_lookup_light") == 0) {
    o->hosts = 200000;
    o->ipv4_exact = 50000;
    o->ipv4_prefix = 50000;
    o->domain_buckets = 1u << 18;
    o->iters = 50000;
    o->rounds = 3;
    o->iters_explicit = 1;
  } else if(strcmp(o->profile, "stress_lookup_light") == 0) {
    o->hosts = 2000000;
    o->ipv4_exact = 200000;
    o->ipv4_prefix = 200000;
    o->domain_buckets = 1u << 20;
    if(o->backend == BACKEND_BOTH && !o->backend_explicit)
      o->backend = BACKEND_NDB;
    o->iters = 50000;
    o->rounds = 3;
    o->iters_explicit = 1;
  }
}

static int parse_u64(const char *s, uint64_t *out) {
  char *end = NULL;
  unsigned long long v;
  errno = 0;
  v = strtoull(s, &end, 10);
  if(errno || end == s || (end && *end))
    return -1;
  *out = (uint64_t)v;
  return 0;
}

static int parse_args(int argc, char **argv, bench_opts_t *o) {
  int i;
  int any_flag = 0;

  for(i = 1; i < argc; i++) {
    if(argv[i][0] == '-' && argv[i][1] == '-')
      any_flag = 1;
  }
  if(!any_flag && argc >= 2) {
    uint64_t v;
    if(parse_u64(argv[1], &v) == 0) {
      o->iters = (size_t)v;
      o->iters_explicit = 1; /* so end-of-parse scale/stress default-iters cap does not override */
      if(o->iters < 1000)
        o->iters = 1000;
    }
    if(argc >= 3 && parse_u64(argv[2], &v) == 0) {
      o->rounds = (int)v;
      if(o->rounds < 3)
        o->rounds = 3;
    }
    return 0;
  }

  for(i = 1; i < argc; i++) {
    const char *a = argv[i];
#define NEED_ARG()                                                                               \
  do {                                                                                           \
    if(i + 1 >= argc) {                                                                          \
      fprintf(stderr, "missing value after %s\n", a);                                            \
      return -1;                                                                                 \
    }                                                                                            \
  } while(0)
    if(strcmp(a, "--help") == 0) {
      print_usage(argv[0]);
      exit(0);
    } else if(strcmp(a, "--iters") == 0) {
      uint64_t v;
      NEED_ARG();
      if(parse_u64(argv[++i], &v) || v < 1000) {
        fprintf(stderr, "bad --iters\n");
        return -1;
      }
      o->iters = (size_t)v;
      o->iters_explicit = 1;
    } else if(strcmp(a, "--rounds") == 0) {
      uint64_t v;
      NEED_ARG();
      if(parse_u64(argv[++i], &v) || v < 3) {
        fprintf(stderr, "bad --rounds\n");
        return -1;
      }
      o->rounds = (int)v;
    } else if(strcmp(a, "--warm") == 0) {
      uint64_t v;
      NEED_ARG();
      if(parse_u64(argv[++i], &v)) {
        fprintf(stderr, "bad --warm\n");
        return -1;
      }
      o->warm = (size_t)v;
    } else if(strcmp(a, "--seed") == 0) {
      uint64_t v;
      NEED_ARG();
      if(parse_u64(argv[++i], &v)) {
        fprintf(stderr, "bad --seed\n");
        return -1;
      }
      o->seed = (unsigned)v;
    } else if(strcmp(a, "--backend") == 0) {
      NEED_ARG();
      a = argv[++i];
      o->backend_explicit = 1;
      if(strcmp(a, "ndb") == 0)
        o->backend = BACKEND_NDB;
      else if(strcmp(a, "legacy") == 0)
        o->backend = BACKEND_LEGACY;
      else if(strcmp(a, "both") == 0)
        o->backend = BACKEND_BOTH;
      else {
        fprintf(stderr, "bad --backend\n");
        return -1;
      }
    } else if(strcmp(a, "--mode") == 0) {
      NEED_ARG();
      a = argv[++i];
      if(strcmp(a, "fixed") == 0)
        o->mode = MODE_FIXED;
      else if(strcmp(a, "mixed_by_case") == 0)
        o->mode = MODE_MIXED_BY_CASE;
      else if(strcmp(a, "mixed_global") == 0)
        o->mode = MODE_MIXED_GLOBAL;
      else {
        fprintf(stderr, "bad --mode\n");
        return -1;
      }
    } else if(strcmp(a, "--profile") == 0) {
      NEED_ARG();
      a = argv[++i];
      if(strcmp(a, "micro") != 0 && strcmp(a, "scale") != 0 && strcmp(a, "stress") != 0 &&
          strcmp(a, "scale_lookup_light") != 0 && strcmp(a, "stress_lookup_light") != 0) {
        fprintf(stderr, "bad --profile\n");
        return -1;
      }
      strncpy(o->profile, a, sizeof(o->profile) - 1);
      o->profile[sizeof(o->profile) - 1] = '\0';
      o->profile_set = 1;
      profile_apply(o);
    } else if(strcmp(a, "--ndb-file") == 0) {
      NEED_ARG();
      strncpy(o->ndb_file, argv[++i], sizeof(o->ndb_file) - 1);
      o->ndb_file[sizeof(o->ndb_file) - 1] = '\0';
    } else if(strcmp(a, "--out-file") == 0) {
      NEED_ARG();
      strncpy(o->out_file, argv[++i], sizeof(o->out_file) - 1);
      o->out_file[sizeof(o->out_file) - 1] = '\0';
    } else if(strcmp(a, "--skip-build") == 0) {
      o->skip_build = 1;
    } else if(strcmp(a, "--only-generate") == 0) {
      o->only_generate = 1;
    } else if(strcmp(a, "--only-load") == 0) {
      o->only_load = 1;
    } else if(strcmp(a, "--only-lookup") == 0) {
      o->only_lookup = 1;
    } else if(strcmp(a, "--force-legacy") == 0) {
      o->force_legacy = 1;
    } else if(strcmp(a, "--lpm") == 0) {
      NEED_ARG();
      a = argv[++i];
      if(strcmp(a, "realistic") == 0)
        o->lpm_realistic = 1;
      else if(strcmp(a, "clean") == 0)
        o->lpm_realistic = 0;
      else {
        fprintf(stderr, "bad --lpm\n");
        return -1;
      }
    } else if(strcmp(a, "--hosts") == 0) {
      uint64_t v;
      NEED_ARG();
      if(parse_u64(argv[++i], &v)) {
        fprintf(stderr, "bad --hosts\n");
        return -1;
      }
      o->hosts = (size_t)v;
    } else if(strcmp(a, "--ipv4-exact") == 0) {
      uint64_t v;
      NEED_ARG();
      if(parse_u64(argv[++i], &v)) {
        fprintf(stderr, "bad --ipv4-exact\n");
        return -1;
      }
      o->ipv4_exact = (size_t)v;
    } else if(strcmp(a, "--ipv4-prefix") == 0) {
      uint64_t v;
      NEED_ARG();
      if(parse_u64(argv[++i], &v)) {
        fprintf(stderr, "bad --ipv4-prefix\n");
        return -1;
      }
      o->ipv4_prefix = (size_t)v;
    } else if(strcmp(a, "--domain-buckets") == 0) {
      uint64_t v;
      NEED_ARG();
      if(parse_u64(argv[++i], &v) || v < 2) {
        fprintf(stderr, "bad --domain-buckets\n");
        return -1;
      }
      o->domain_buckets = (size_t)v;
    } else if(strcmp(a, "--blocks-per-round") == 0) {
      uint64_t v;
      NEED_ARG();
      if(parse_u64(argv[++i], &v) || v < 2) {
        fprintf(stderr, "bad --blocks-per-round\n");
        return -1;
      }
      o->blocks_per_round = (int)v;
    } else {
      fprintf(stderr, "unknown option: %s\n", a);
      return -1;
    }
#undef NEED_ARG
  }

  if(o->skip_build && o->ndb_file[0] == '\0') {
    fprintf(stderr, "error: --skip-build requires --ndb-file\n");
    return -1;
  }
  if(o->only_generate && o->out_file[0] == '\0') {
    fprintf(stderr, "error: --only-generate requires --out-file\n");
    return -1;
  }
  if(o->only_generate && (o->ndb_file[0] || o->skip_build)) {
    fprintf(stderr, "error: --only-generate conflicts with --ndb-file / --skip-build\n");
    return -1;
  }
  if(o->ndb_file[0] && o->backend == BACKEND_LEGACY) {
    fprintf(stderr, "error: --ndb-file requires --backend ndb or both\n");
    return -1;
  }
  if((o->only_load || o->only_lookup) && o->skip_build && o->ndb_file[0] == '\0') {
    fprintf(stderr, "error: --only-load / --only-lookup with --skip-build requires --ndb-file\n");
    return -1;
  }
  if(!is_power_of_two_u64((uint64_t)o->domain_buckets)) {
    fprintf(stderr, "error: --domain-buckets must be a power of two >= 2\n");
    return -1;
  }
  if(o->hosts == 0 && o->ipv4_exact == 0 && o->ipv4_prefix == 0 && o->ndb_file[0] == '\0' && !o->only_generate) {
    /* micro profile still sets hosts>=1; this catches empty synthetic with no external file */
    fprintf(stderr, "error: need --ndb-file or non-zero synthetic counts\n");
    return -1;
  }
  /* Large DB profiles: keep full synthetic tables but avoid multi-hour lookup loops by default.
   * For lighter preset lookup runs (same DB shape), see scale_lookup_light / stress_lookup_light. */
  if(o->profile_set && !o->iters_explicit) {
    if(strcmp(o->profile, "scale") == 0 || strcmp(o->profile, "stress") == 0)
      o->iters = 100000;
  }
  return 0;
}

/* ---- micro .ndb (historical minimal file) ---- */
static int write_micro_ndb(const char *path) {
  FILE *fp;
  ndb_header_disk_t hdr;
  ndb_category_disk_t cat;
  ndb_bucket_disk_t bucks[2];
  ndb_entry_disk_t ent;
  const char *dom = "example.com";
  size_t dom_len = strlen(dom);
  const char pool[] = "x\0example.com\0";
  const size_t pool_len = sizeof(pool) - 1;
  ndb_ipv4_entry_disk_t v4[3];
  uint64_t off;
  uint32_t addr_8888 = htonl(0x08080808);
  uint32_t addr_10_8 = htonl(0x0a000000);
  uint32_t addr_10_1_16 = htonl(0x0a010000);

  fp = fopen(path, "wb");
  if(!fp)
    return -1;

  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.magic, NDB_MAGIC, 4);
  hdr.format_version = NDB_FORMAT_VERSION;
  hdr.category_count = 1;
  hdr.domain_entry_count = 1;
  hdr.domain_bucket_count = 2;
  hdr.string_pool_size = pool_len;
  hdr.ipv4_entry_count = 3;
  hdr.ipv6_entry_count = 0;

  off = sizeof(hdr);
  hdr.categories_off = off;
  off += sizeof(cat);
  hdr.domain_buckets_off = off;
  off += sizeof(bucks);
  hdr.domain_entries_off = off;
  off += sizeof(ent);
  hdr.string_pool_off = off;
  off += pool_len;
  hdr.ipv4_entries_off = off;
  off += sizeof(v4);
  hdr.ipv6_entries_off = off;
  hdr.file_size = off;

  cat.id = NDPI_PROTOCOL_CATEGORY_WEB;
  cat.name_off = 0;

  bucks[0].first = 0;
  bucks[0].count = 1;
  bucks[1].first = 0;
  bucks[1].count = 0;

  ent.hash = bench_fnv1a64(dom, dom_len);
  ent.domain_off = 2;
  ent.domain_len = (uint16_t)dom_len;
  ent.flags = 0;
  ent.category_id = NDPI_PROTOCOL_CATEGORY_WEB;

  v4[0].network_be = addr_10_8;
  v4[0].prefix_len = 8;
  v4[0].flags = 0;
  v4[0].reserved0 = 0;
  v4[0].category_id = NDPI_PROTOCOL_CATEGORY_WEB;

  v4[1].network_be = addr_10_1_16;
  v4[1].prefix_len = 16;
  v4[1].flags = 0;
  v4[1].reserved0 = 0;
  v4[1].category_id = NDPI_PROTOCOL_CATEGORY_VPN;

  v4[2].network_be = addr_8888;
  v4[2].prefix_len = 32;
  v4[2].flags = 0;
  v4[2].reserved0 = 0;
  v4[2].category_id = NDPI_PROTOCOL_CATEGORY_VPN;

  if(fwrite(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr) || fwrite(&cat, 1, sizeof(cat), fp) != sizeof(cat) ||
      fwrite(bucks, 1, sizeof(bucks), fp) != sizeof(bucks) || fwrite(&ent, 1, sizeof(ent), fp) != sizeof(ent) ||
      fwrite(pool, 1, pool_len, fp) != pool_len || fwrite(v4, 1, sizeof(v4), fp) != sizeof(v4)) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  return 0;
}

/* ---- synthetic .ndb ---- */
static int write_synthetic_ndb(const char *path, const bench_opts_t *opt, size_t *out_pool_used) {
  FILE *fp = NULL;
  ndb_header_disk_t hdr;
  ndb_category_disk_t cat;
  ndb_bucket_disk_t *bucks = NULL;
  ndb_entry_disk_t *ents = NULL;
  uint32_t *bc = NULL;
  uint32_t *bwr = NULL;
  char *pool = NULL;
  ndb_ipv4_entry_disk_t *v4 = NULL;
  uint64_t off;
  size_t nb = opt->domain_buckets;
  size_t N = opt->hosts;
  size_t nex = opt->ipv4_exact;
  size_t npr = opt->ipv4_prefix;
  size_t ipv4_total;
  size_t pool_cap;
  size_t pool_used = 0;
  size_t bi, idx;
  int rc = -1;

  *out_pool_used = 0;
  ipv4_total = nex + npr;
  if(ipv4_total > IPV4_RULE_CAP) {
    fprintf(stderr, "ipv4 rules too large (cap %u)\n", (unsigned)IPV4_RULE_CAP);
    return -1;
  }
  if(nb > (1ull << 31)) {
    fprintf(stderr, "domain_buckets too large\n");
    return -1;
  }

  fp = fopen(path, "wb");
  if(!fp)
    return -1;

  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.magic, NDB_MAGIC, 4);
  hdr.format_version = NDB_FORMAT_VERSION;
  hdr.category_count = 1;
  hdr.domain_entry_count = (uint64_t)N;
  hdr.domain_bucket_count = (uint64_t)nb;
  hdr.ipv4_entry_count = (uint64_t)ipv4_total;
  hdr.ipv6_entry_count = 0;

  bucks = (ndb_bucket_disk_t *)calloc(nb, sizeof(ndb_bucket_disk_t));
  if(N > 0 && !bucks)
    goto fail;

  bc = (uint32_t *)calloc(nb, sizeof(uint32_t));
  if(N > 0 && !bc)
    goto fail;

  /* pass 1: bucket counts */
  if(N > 0) {
    char hbuf[256];
    size_t i;
    for(i = 1; i <= N; i++) {
      uint64_t h;
      size_t b;
      int nch = snprintf(hbuf, sizeof(hbuf), "d%07zu.example.test", i);
      if(nch <= 0 || (size_t)nch >= sizeof(hbuf))
        goto fail;
      h = bench_fnv1a64(hbuf, (size_t)nch);
      b = (size_t)(h & (uint64_t)(nb - 1));
      if(bc[b] == UINT32_MAX)
        goto fail;
      bc[b]++;
    }
  }

  bwr = (uint32_t *)calloc(nb, sizeof(uint32_t));
  ents = (ndb_entry_disk_t *)calloc(N > 0 ? N : 1, sizeof(ndb_entry_disk_t));
  if((N > 0 && !ents) || (N > 0 && !bwr))
    goto fail;

  if(N > 0) {
    uint32_t run = 0;
    for(bi = 0; bi < nb; bi++) {
      bucks[bi].first = run;
      bucks[bi].count = bc[bi];
      run += bc[bi];
      bwr[bi] = bucks[bi].first;
    }
  } else {
    for(bi = 0; bi < nb; bi++) {
      bucks[bi].first = 0;
      bucks[bi].count = 0;
    }
  }

  pool_cap = N * 48 + 16;
  if(N > 0) {
    pool = (char *)malloc(pool_cap);
    if(!pool)
      goto fail;
    pool[0] = '\0';
    pool_used = 1; /* cat name empty at off 0 */
  } else {
    pool = (char *)malloc(1);
    if(!pool)
      goto fail;
    pool[0] = '\0';
    pool_used = 1;
  }

  /* pass 2: entries + pool */
  if(N > 0) {
    char hbuf[256];
    size_t i;
    for(i = 1; i <= N; i++) {
      uint64_t hv;
      size_t b;
      uint32_t pos;
      size_t len;
      int nch = snprintf(hbuf, sizeof(hbuf), "d%07zu.example.test", i);
      if(nch <= 0 || (size_t)nch >= sizeof(hbuf))
        goto fail;
      len = (size_t)nch;
      hv = bench_fnv1a64(hbuf, len);
      b = (size_t)(hv & (uint64_t)(nb - 1));
      pos = bwr[b]++;
      if(pool_used + len + 1 > pool_cap) {
        size_t ncap = pool_cap * 2 + len + 64;
        char *np = (char *)realloc(pool, ncap);
        if(!np)
          goto fail;
        pool = np;
        pool_cap = ncap;
      }
      ents[pos].hash = hv;
      ents[pos].domain_off = (uint32_t)pool_used;
      ents[pos].domain_len = (uint16_t)len;
      ents[pos].flags = 0;
      ents[pos].category_id =
          ((i & 1) ? NDPI_PROTOCOL_CATEGORY_VPN : NDPI_PROTOCOL_CATEGORY_WEB);
      memcpy(pool + pool_used, hbuf, len);
      pool_used += len;
      pool[pool_used++] = '\0';
    }
  }

  cat.id = NDPI_PROTOCOL_CATEGORY_WEB;
  cat.name_off = 0;
  hdr.string_pool_size = (uint64_t)pool_used;

  v4 = (ndb_ipv4_entry_disk_t *)calloc(ipv4_total > 0 ? ipv4_total : 1, sizeof(ndb_ipv4_entry_disk_t));
  if(ipv4_total > 0 && !v4)
    goto fail;

  /* IPv4: exact rows then prefix rows */
  idx = 0;
  for(; idx < nex; idx++) {
    uint32_t a = htonl(0x0b000000u | (uint32_t)(idx & 0x00ffffffu));
    v4[idx].network_be = a;
    v4[idx].prefix_len = 32;
    v4[idx].flags = 0;
    v4[idx].reserved0 = 0;
    v4[idx].category_id = NDPI_PROTOCOL_CATEGORY_VPN;
  }
  for(; idx < ipv4_total; idx++) {
    size_t j = idx - nex;
    uint32_t oct = (uint32_t)((j % 200) + 1);
    uint32_t a = htonl(0x0a000000u | (oct << 16));
    v4[idx].network_be = a;
    v4[idx].prefix_len = 16;
    v4[idx].flags = 0;
    v4[idx].reserved0 = 0;
    v4[idx].category_id = NDPI_PROTOCOL_CATEGORY_WEB;
  }

  if(opt->lpm_realistic && ipv4_total >= 4) {
    /* overlap stack for first anchor (documentation / stress) */
    size_t base = 0;
    v4[base + 0].network_be = htonl(0x0a141e28u); /* 10.20.30.40 */
    v4[base + 0].prefix_len = 8;
    v4[base + 0].category_id = NDPI_PROTOCOL_CATEGORY_WEB;
    v4[base + 1].network_be = htonl(0x0a141e28u);
    v4[base + 1].prefix_len = 16;
    v4[base + 1].category_id = NDPI_PROTOCOL_CATEGORY_VPN;
    v4[base + 2].network_be = htonl(0x0a141e28u);
    v4[base + 2].prefix_len = 24;
    v4[base + 2].category_id = NDPI_PROTOCOL_CATEGORY_WEB;
    v4[base + 3].network_be = htonl(0x0a141e28u);
    v4[base + 3].prefix_len = 32;
    v4[base + 3].category_id = NDPI_PROTOCOL_CATEGORY_VPN;
  }

  off = sizeof(hdr);
  hdr.categories_off = off;
  off += sizeof(cat);
  hdr.domain_buckets_off = off;
  off += (uint64_t)nb * sizeof(ndb_bucket_disk_t);
  hdr.domain_entries_off = off;
  off += (uint64_t)N * sizeof(ndb_entry_disk_t);
  hdr.string_pool_off = off;
  off += (uint64_t)pool_used;
  hdr.ipv4_entries_off = off;
  off += (uint64_t)ipv4_total * sizeof(ndb_ipv4_entry_disk_t);
  hdr.ipv6_entries_off = off;
  hdr.file_size = off;

  if(fwrite(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr) || fwrite(&cat, 1, sizeof(cat), fp) != sizeof(cat))
    goto fail;
  if(nb > 0 && fwrite(bucks, sizeof(ndb_bucket_disk_t), nb, fp) != nb)
    goto fail;
  if(N > 0 && fwrite(ents, sizeof(ndb_entry_disk_t), N, fp) != N)
    goto fail;
  if(fwrite(pool, 1, pool_used, fp) != pool_used)
    goto fail;
  if(ipv4_total > 0 && fwrite(v4, sizeof(ndb_ipv4_entry_disk_t), ipv4_total, fp) != ipv4_total)
    goto fail;

  *out_pool_used = pool_used;
  rc = 0;
fail:
  free(v4);
  free(pool);
  free(ents);
  free(bwr);
  free(bc);
  free(bucks);
  if(fp)
    fclose(fp);
  if(rc && path)
    unlink(path);
  return rc;
}

static int cmp_double_asc(const void *a, const void *b) {
  double x = *(const double *)a;
  double y = *(const double *)b;
  if(x < y)
    return -1;
  if(x > y)
    return 1;
  return 0;
}

typedef void (*bench_body_fn)(struct ndpi_detection_module_struct *m, void *ctx);

typedef struct {
  enum bench_mode mode;
  char fixed_hit[256];
  char fixed_miss[256];
  char fixed_ip_hit[32];
  char fixed_ip_lpm[32];
  char fixed_ip_miss[32];
  /* pools for mixed */
  char **pool_host_hit;
  char **pool_host_miss;
  char **pool_ip_hit;
  char **pool_ip_lpm;
  char **pool_ip_miss;
  size_t n_hit, n_miss, n_ip_hit, n_ip_lpm, n_ip_miss;
  size_t ix_hit, ix_miss, ix_ip_hit, ix_ip_lpm, ix_ip_miss;
  size_t glob_ix;
} bench_ctx_t;

static void body_host_hit(struct ndpi_detection_module_struct *m, void *ctx) {
  bench_ctx_t *c = (bench_ctx_t *)ctx;
  const char *s;
  size_t len;
  ndpi_protocol_category_t cat;
  ndpi_protocol_breed_t breed;
  if(c->mode == MODE_FIXED) {
    s = c->fixed_hit;
    len = strlen(s);
  } else if(c->mode == MODE_MIXED_GLOBAL) {
    /* Same pools as mixed_by_case per body; true global interleave would mix APIs in one loop (future). */
    if(!c->n_hit)
      return;
    s = c->pool_host_hit[c->ix_hit++ % c->n_hit];
    len = strlen(s);
  } else {
    if(!c->n_hit)
      return;
    s = c->pool_host_hit[c->ix_hit++ % c->n_hit];
    len = strlen(s);
  }
  (void)ndpi_match_custom_category(m, (char *)s, len, &cat, &breed);
}

static void body_host_miss(struct ndpi_detection_module_struct *m, void *ctx) {
  bench_ctx_t *c = (bench_ctx_t *)ctx;
  const char *s;
  size_t len;
  ndpi_protocol_category_t cat;
  ndpi_protocol_breed_t breed;
  if(c->mode == MODE_FIXED) {
    s = c->fixed_miss;
    len = strlen(s);
  } else if(c->mode == MODE_MIXED_GLOBAL) {
    if(!c->n_miss)
      return;
    s = c->pool_host_miss[c->ix_miss++ % c->n_miss];
    len = strlen(s);
  } else {
    if(!c->n_miss)
      return;
    s = c->pool_host_miss[c->ix_miss++ % c->n_miss];
    len = strlen(s);
  }
  (void)ndpi_match_custom_category(m, (char *)s, len, &cat, &breed);
}

static void body_ip_hit(struct ndpi_detection_module_struct *m, void *ctx) {
  bench_ctx_t *c = (bench_ctx_t *)ctx;
  const char *s;
  size_t len;
  ndpi_protocol_category_t cat;
  ndpi_protocol_breed_t breed;
  if(c->mode == MODE_FIXED) {
    s = c->fixed_ip_hit;
    len = strlen(s);
  } else if(c->mode == MODE_MIXED_GLOBAL) {
    if(!c->n_ip_hit)
      return;
    s = c->pool_ip_hit[c->ix_ip_hit++ % c->n_ip_hit];
    len = strlen(s);
  } else {
    if(!c->n_ip_hit)
      return;
    s = c->pool_ip_hit[c->ix_ip_hit++ % c->n_ip_hit];
    len = strlen(s);
  }
  (void)ndpi_get_custom_category_match(m, (char *)s, len, &cat, &breed);
}

static void body_ip_lpm(struct ndpi_detection_module_struct *m, void *ctx) {
  bench_ctx_t *c = (bench_ctx_t *)ctx;
  const char *s;
  size_t len;
  ndpi_protocol_category_t cat;
  ndpi_protocol_breed_t breed;
  if(c->mode == MODE_FIXED) {
    s = c->fixed_ip_lpm;
    len = strlen(s);
  } else if(c->mode == MODE_MIXED_GLOBAL) {
    if(!c->n_ip_lpm)
      return;
    s = c->pool_ip_lpm[c->ix_ip_lpm++ % c->n_ip_lpm];
    len = strlen(s);
  } else {
    if(!c->n_ip_lpm)
      return;
    s = c->pool_ip_lpm[c->ix_ip_lpm++ % c->n_ip_lpm];
    len = strlen(s);
  }
  (void)ndpi_get_custom_category_match(m, (char *)s, len, &cat, &breed);
}

static void body_ip_miss(struct ndpi_detection_module_struct *m, void *ctx) {
  bench_ctx_t *c = (bench_ctx_t *)ctx;
  const char *s;
  size_t len;
  ndpi_protocol_category_t cat;
  ndpi_protocol_breed_t breed;
  if(c->mode == MODE_FIXED) {
    s = c->fixed_ip_miss;
    len = strlen(s);
  } else if(c->mode == MODE_MIXED_GLOBAL) {
    if(!c->n_ip_miss)
      return;
    s = c->pool_ip_miss[c->ix_ip_miss++ % c->n_ip_miss];
    len = strlen(s);
  } else {
    if(!c->n_ip_miss)
      return;
    s = c->pool_ip_miss[c->ix_ip_miss++ % c->n_ip_miss];
    len = strlen(s);
  }
  (void)ndpi_get_custom_category_match(m, (char *)s, len, &cat, &breed);
}

static double timespec_diff_sec(const struct timespec *a, const struct timespec *b) {
  return (double)(b->tv_sec - a->tv_sec) + (double)(b->tv_nsec - a->tv_nsec) / 1e9;
}

/* Median ns/op + block percentiles; prints block_size_ops / blocks_per_round via out-params */
static int median_ns_per_op_blocks(bench_body_fn body, void *ctx, struct ndpi_detection_module_struct *mod, size_t warm,
    size_t iters, int rounds, int blocks_per_round, double *out_median, double *out_p50, double *out_p95, double *out_p99,
    size_t *out_block_ops) {
  double *round_medians;
  double *block_samples;
  int r, b;
  size_t ops_per_block;
  size_t total_block_samples;
  size_t si;

  if(iters == 0 || rounds < 1 || blocks_per_round < 2)
    return -1;
  ops_per_block = iters / (size_t)blocks_per_round;
  if(ops_per_block == 0)
    return -1;
  *out_block_ops = ops_per_block;

  round_medians = (double *)malloc((size_t)rounds * sizeof(double));
  total_block_samples = (size_t)rounds * (size_t)blocks_per_round;
  block_samples = (double *)malloc(total_block_samples * sizeof(double));
  if(!round_medians || !block_samples) {
    free(round_medians);
    free(block_samples);
    return -1;
  }

  si = 0;
  for(r = 0; r < rounds + 1; r++) {
    size_t i, base;
    double sec_round = 0;

    for(i = 0; i < warm; i++)
      body(mod, ctx);

    for(b = 0; b < blocks_per_round; b++) {
      struct timespec t0, t1;
      size_t k;
      double sec, ns_per_op;
      clock_gettime(CLOCK_MONOTONIC, &t0);
      for(k = 0; k < ops_per_block; k++)
        body(mod, ctx);
      clock_gettime(CLOCK_MONOTONIC, &t1);
      sec = timespec_diff_sec(&t0, &t1);
      ns_per_op = (sec / (double)ops_per_block) * 1e9;
      if(r > 0)
        block_samples[si++] = ns_per_op;
      sec_round += sec;
    }
    /* remainder ops to reach iters */
    base = (size_t)blocks_per_round * ops_per_block;
    for(i = base; i < iters; i++)
      body(mod, ctx);

    if(r > 0) {
      double ns_round_op = (sec_round / (double)iters) * 1e9;
      round_medians[r - 1] = ns_round_op;
    }
  }

  qsort(round_medians, (size_t)rounds, sizeof(double), cmp_double_asc);
  *out_median = round_medians[rounds / 2];

  qsort(block_samples, total_block_samples, sizeof(double), cmp_double_asc);
  *out_p50 = block_samples[(size_t)((total_block_samples - 1) * 50 / 100)];
  *out_p95 = block_samples[(size_t)((total_block_samples - 1) * 95 / 100)];
  *out_p99 = block_samples[(size_t)((total_block_samples - 1) * 99 / 100)];

  free(block_samples);
  free(round_medians);
  return 0;
}

static void fill_fixed_strings(bench_ctx_t *c, const bench_opts_t *o) {
  /* External .ndb: assume same synthetic naming as this bench's generator (d0000001…, 11.0.0.0, …). */
  if(o->ndb_file[0]) {
    snprintf(c->fixed_hit, sizeof(c->fixed_hit), "d%07zu.example.test", (size_t)1);
    strcpy(c->fixed_miss, "nomatch.example.invalid");
    strcpy(c->fixed_ip_hit, "11.0.0.0");
    strcpy(c->fixed_ip_lpm, "10.1.1.2");
    strcpy(c->fixed_ip_miss, "192.0.2.1");
    return;
  }
  if(o->hosts >= 1 && strcmp(o->profile, "micro") != 0) {
    snprintf(c->fixed_hit, sizeof(c->fixed_hit), "d%07zu.example.test", (size_t)1);
  } else {
    strcpy(c->fixed_hit, "example.com");
  }
  strcpy(c->fixed_miss, "nomatch.example.invalid");
  strcpy(c->fixed_ip_hit, "8.8.8.8");
  strcpy(c->fixed_ip_lpm, "10.1.2.3");
  strcpy(c->fixed_ip_miss, "192.0.2.1");
  if(strcmp(o->profile, "micro") == 0) {
    strcpy(c->fixed_hit, "example.com");
    strcpy(c->fixed_ip_hit, "8.8.8.8");
    strcpy(c->fixed_ip_lpm, "10.1.2.3");
  }
}

static void free_pools(bench_ctx_t *c) {
  size_t i;
  if(c->pool_host_hit) {
    for(i = 0; i < c->n_hit; i++)
      free(c->pool_host_hit[i]);
    free(c->pool_host_hit);
  }
  if(c->pool_host_miss) {
    for(i = 0; i < c->n_miss; i++)
      free(c->pool_host_miss[i]);
    free(c->pool_host_miss);
  }
  if(c->pool_ip_hit) {
    for(i = 0; i < c->n_ip_hit; i++)
      free(c->pool_ip_hit[i]);
    free(c->pool_ip_hit);
  }
  if(c->pool_ip_lpm) {
    for(i = 0; i < c->n_ip_lpm; i++)
      free(c->pool_ip_lpm[i]);
    free(c->pool_ip_lpm);
  }
  if(c->pool_ip_miss) {
    for(i = 0; i < c->n_ip_miss; i++)
      free(c->pool_ip_miss[i]);
    free(c->pool_ip_miss);
  }
  memset(c, 0, sizeof(*c));
}

static int build_pools(bench_ctx_t *c, const bench_opts_t *o) {
  size_t cap = QUERY_POOL_CAP;
  size_t step, i;
  char buf[256];
  struct in_addr ia;

  c->mode = o->mode;
  fill_fixed_strings(c, o);

  if(o->mode == MODE_FIXED)
    return 0;

  if(o->hosts == 0) {
    c->n_hit = c->n_miss = 0;
  } else {
    c->n_hit = c->n_miss = (o->hosts < cap ? o->hosts : cap);
    c->pool_host_hit = (char **)calloc(c->n_hit, sizeof(char *));
    c->pool_host_miss = (char **)calloc(c->n_miss, sizeof(char *));
    if(!c->pool_host_hit || !c->pool_host_miss)
      return -1;
    step = o->hosts / (c->n_hit ? c->n_hit : 1);
    if(step == 0)
      step = 1;
    for(i = 0; i < c->n_hit; i++) {
      size_t id = 1 + i * step;
      if(id > o->hosts)
        id = o->hosts;
      snprintf(buf, sizeof(buf), "d%07zu.example.test", id);
      c->pool_host_hit[i] = strdup(buf);
      if(!c->pool_host_hit[i])
        return -1;
    }
    for(i = 0; i < c->n_miss; i++) {
      snprintf(buf, sizeof(buf), "zzzmiss%04zu.invalid.test", i);
      c->pool_host_miss[i] = strdup(buf);
      if(!c->pool_host_miss[i])
        return -1;
    }
  }

  if(o->ipv4_exact == 0)
    c->n_ip_hit = 0;
  else {
    c->n_ip_hit = (o->ipv4_exact < cap ? o->ipv4_exact : cap);
    c->pool_ip_hit = (char **)calloc(c->n_ip_hit, sizeof(char *));
    if(!c->pool_ip_hit)
      return -1;
    step = o->ipv4_exact / (c->n_ip_hit ? c->n_ip_hit : 1);
    if(step == 0)
      step = 1;
    for(i = 0; i < c->n_ip_hit; i++) {
      uint32_t a = htonl(0x0b000000u | (uint32_t)((i * step) & 0x00ffffffu));
      ia.s_addr = a;
      if(!inet_ntop(AF_INET, &ia, buf, sizeof(buf)))
        return -1;
      c->pool_ip_hit[i] = strdup(buf);
      if(!c->pool_ip_hit[i])
        return -1;
    }
  }

  if(o->ipv4_prefix == 0)
    c->n_ip_lpm = 0;
  else {
    c->n_ip_lpm = (o->ipv4_prefix < cap ? o->ipv4_prefix : cap);
    c->pool_ip_lpm = (char **)calloc(c->n_ip_lpm, sizeof(char *));
    if(!c->pool_ip_lpm)
      return -1;
    for(i = 0; i < c->n_ip_lpm; i++) {
      uint32_t oct = (uint32_t)((i % 200) + 1);
      snprintf(buf, sizeof(buf), "10.%u.1.2", oct);
      c->pool_ip_lpm[i] = strdup(buf);
      if(!c->pool_ip_lpm[i])
        return -1;
    }
  }

  c->n_ip_miss = (cap < 256 ? cap : 256);
  c->pool_ip_miss = (char **)calloc(c->n_ip_miss, sizeof(char *));
  if(!c->pool_ip_miss)
    return -1;
  for(i = 0; i < c->n_ip_miss; i++) {
    snprintf(buf, sizeof(buf), "192.0.2.%zu", (i % 200) + 1);
    c->pool_ip_miss[i] = strdup(buf);
    if(!c->pool_ip_miss[i])
      return -1;
  }
  return 0;
}

static struct ndpi_detection_module_struct *bench_ndb_load(const char *ndb_path, double *load_ms) {
  struct ndpi_detection_module_struct *m = ndpi_init_detection_module(NULL);
  struct timespec t0, t1;
  if(!m || ndpi_finalize_initialization(m) != 0) {
    if(m)
      ndpi_exit_detection_module(m);
    return NULL;
  }
  clock_gettime(CLOCK_MONOTONIC, &t0);
  if(ndpi_load_category_ndb_file(m, ndb_path, NDPI_CATEGORY_BACKEND_NDB_ONLY) != 0) {
    ndpi_exit_detection_module(m);
    return NULL;
  }
  clock_gettime(CLOCK_MONOTONIC, &t1);
  if(load_ms)
    *load_ms = timespec_diff_sec(&t0, &t1) * 1000.0;
  return m;
}

static int legacy_load_mirrored(struct ndpi_detection_module_struct *m, const bench_opts_t *o, double *load_ms) {
  struct timespec t0, t1;
  size_t i;
  char buf[256];
  struct in_addr ia;

  clock_gettime(CLOCK_MONOTONIC, &t0);
  /* Historical micro .ndb: same four rules as write_micro_ndb (not dNNNNNNN hostnames). */
  if(strcmp(o->profile, "micro") == 0 && o->ndb_file[0] == '\0') {
    if(ndpi_load_hostname_category(m, "example.com", NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE) != 0)
      return -1;
    if(ndpi_load_ip_category(m, "8.8.8.8/32", NDPI_PROTOCOL_CATEGORY_VPN, NULL) != 0)
      return -1;
    if(ndpi_load_ip_category(m, "10.0.0.0/8", NDPI_PROTOCOL_CATEGORY_WEB, NULL) != 0)
      return -1;
    if(ndpi_load_ip_category(m, "10.1.0.0/16", NDPI_PROTOCOL_CATEGORY_VPN, NULL) != 0)
      return -1;
  } else {
    for(i = 1; i <= o->hosts; i++) {
      snprintf(buf, sizeof(buf), "d%07zu.example.test", i);
      if(ndpi_load_hostname_category(m, buf,
             ((i & 1) ? NDPI_PROTOCOL_CATEGORY_VPN : NDPI_PROTOCOL_CATEGORY_WEB), NDPI_PROTOCOL_ACCEPTABLE) != 0)
        return -1;
    }
    for(i = 0; i < o->ipv4_exact; i++) {
      uint32_t a = htonl(0x0b000000u | (uint32_t)(i & 0x00ffffffu));
      ia.s_addr = a;
      if(!inet_ntop(AF_INET, &ia, buf, sizeof(buf)))
        return -1;
      {
        char line[64];
        snprintf(line, sizeof(line), "%s/32", buf);
        if(ndpi_load_ip_category(m, line, NDPI_PROTOCOL_CATEGORY_VPN, NULL) != 0)
          return -1;
      }
    }
    for(i = 0; i < o->ipv4_prefix; i++) {
      uint32_t oct = (uint32_t)((i % 200) + 1);
      snprintf(buf, sizeof(buf), "10.%u.0.0/16", oct);
      if(ndpi_load_ip_category(m, buf, NDPI_PROTOCOL_CATEGORY_WEB, NULL) != 0)
        return -1;
    }
  }
  if(ndpi_finalize_initialization(m) != 0)
    return -1;
  clock_gettime(CLOCK_MONOTONIC, &t1);
  if(load_ms)
    *load_ms = timespec_diff_sec(&t0, &t1) * 1000.0;
  return 0;
}

static const char *mode_str(enum bench_mode m) {
  switch(m) {
    case MODE_FIXED:
      return "fixed";
    case MODE_MIXED_BY_CASE:
      return "mixed_by_case";
    case MODE_MIXED_GLOBAL:
      return "mixed_global";
  }
  return "?";
}

static const char *backend_str(enum bench_backend b) {
  switch(b) {
    case BACKEND_NDB:
      return "ndb";
    case BACKEND_LEGACY:
      return "legacy";
    case BACKEND_BOTH:
      return "both";
  }
  return "?";
}

static void print_scenario_header(bench_opts_t *o, const char *ndb_path, uint64_t file_bytes, double load_ndb_ms,
    double load_legacy_ms, size_t rss_before, size_t rss_after_ndb, size_t rss_after_legacy, int legacy_ran) {
  double fmb = (double)file_bytes / (1024.0 * 1024.0);
  printf("=== scenario ===\n");
  printf("os_platform=%s  build=%s\n",
#ifdef __APPLE__
         "Darwin",
#else
         "Linux",
#endif
         GC_LABEL);
  printf("backend=%s  profile=%s  mode=%s  seed=%u\n", backend_str(o->backend), o->profile, mode_str(o->mode), o->seed);
  if(o->mode == MODE_MIXED_GLOBAL)
    printf("NOTE: mixed_global currently reuses per-case pools and is not yet a true cross-API mixed loop.\n");
  printf("hosts=%zu  ipv4_exact=%zu  ipv4_prefix=%zu  domain_buckets=%zu  lpm=%s\n", o->hosts, o->ipv4_exact,
      o->ipv4_prefix, o->domain_buckets, o->lpm_realistic ? "realistic" : "clean");
  if(o->ndb_file[0] && strcmp(ndb_path, o->ndb_file) == 0)
    printf("NOTE: host/ipv4 counts are CLI metadata only; external .ndb is not introspected.\n");
  printf("ndb_path=%s\n", ndb_path);
  printf("ndb_file_size_bytes=%llu  ndb_file_size_mb=%.3f\n", (unsigned long long)file_bytes, fmb);
  if(o->hosts + o->ipv4_exact + o->ipv4_prefix > 0 && file_bytes > 0) {
    double bh = o->hosts ? (double)file_bytes / (double)o->hosts : 0.0;
    double br = (o->ipv4_exact + o->ipv4_prefix) ? (double)file_bytes / (double)(o->ipv4_exact + o->ipv4_prefix) : 0.0;
    printf("bytes_per_host=%.3f  bytes_per_ipv4_rule=%.3f (file_size ratio; informational)\n", bh, br);
  }
  printf("load_ndb_ms=%.3f\n", load_ndb_ms);
  if(legacy_ran)
    printf("load_legacy_ms=%.3f\n", load_legacy_ms);
  printf("rss_before_bytes=%zu  rss_after_ndb_bytes=%zu", rss_before, rss_after_ndb);
  if(legacy_ran)
    printf("  rss_after_legacy_bytes=%zu", rss_after_legacy);
  printf("\n");
  if(o->warn_ipv4_linear)
    printf("WARNING: large ipv4_entry_count: .ndb IPv4 lookup is O(N) linear scan — interpret timings accordingly.\n");
  if(o->warn_unfair_compare && o->unfair_reason[0])
    printf("WARNING: comparison may be unfair: %s\n", o->unfair_reason);
  if(o->warn_legacy_fallback)
    printf("WARNING: legacy build failed or skipped; fell back to ndb-only with warning.\n");
  printf("================\n\n");
}

static void run_case(const char *tag, const char *case_name, struct ndpi_detection_module_struct *m, bench_body_fn body,
    bench_ctx_t *ctx, const bench_opts_t *o, size_t block_ops, int blocks_per_round) {
  double med, p50, p95, p99;
  size_t bo;
  double sec_total;
  double ops_per_sec;
  if(median_ns_per_op_blocks(body, ctx, m, o->warm, o->iters, o->rounds, blocks_per_round, &med, &p50, &p95, &p99, &bo) !=
      0) {
    printf("%-12s %-28s error\n", tag, case_name);
    return;
  }
  (void)bo;
  sec_total = (double)o->iters * (med / 1e9); /* approx using median ns/op */
  ops_per_sec = sec_total > 0 ? (double)o->iters / sec_total : 0;
  printf("%-12s %-28s med_ns/op=%.2f  block_ops=%zu  blocks_per_round=%d  block_p50=%.2f p95=%.2f p99=%.2f  "
         "~ops_per_sec=%.0f\n",
      tag, case_name, med, block_ops, blocks_per_round, p50, p95, p99, ops_per_sec);
}

int main(int argc, char **argv) {
  bench_opts_t opt;
  char tmpl[] = "/tmp/ndpi_bench_ndbXXXXXX";
  int fd = -1;
  char ndb_work[4096];
  uint64_t file_bytes = 0;
  struct stat st;
  double load_ndb_ms = 0, load_legacy_ms = 0;
  size_t rss_b = 0, rss_ndb = 0, rss_leg = 0, rss_after_gen = 0;
  int rss_ok;
  int legacy_ran = 0;
  int use_temp_file = 1;
  struct ndpi_detection_module_struct *ndb_m = NULL, *leg_m = NULL;
  bench_ctx_t ctx;
  int blocks_pr;
  size_t pool_used = 0;
  size_t lookup_ops_total;

  opts_defaults(&opt);
  if(parse_args(argc, argv, &opt) != 0)
    return 1;
  /* profile_apply runs from parse_args only when --profile is set; defaults already in opts_defaults */

  if(opt.warm == 0) {
    opt.warm = opt.iters / 50;
    if(opt.warm < 5000)
      opt.warm = 5000;
  }
  blocks_pr = opt.blocks_per_round;
  if((size_t)blocks_pr > opt.iters / 2)
    blocks_pr = (int)(opt.iters / 2);
  if(blocks_pr < 2)
    blocks_pr = 2;

  rss_ok = rss_bytes_self(&rss_b) == 0;

  memset(&ctx, 0, sizeof(ctx));
  ctx.mode = opt.mode;
  fill_fixed_strings(&ctx, &opt);
  if(opt.mode != MODE_FIXED) {
    if(build_pools(&ctx, &opt) != 0) {
      fprintf(stderr, "pool build failed\n");
      return 1;
    }
  }

  ndb_work[0] = '\0';

  if(opt.backend == BACKEND_LEGACY) {
    use_temp_file = 0;
    file_bytes = 0;
    goto after_generate;
  }

  if(opt.only_generate) {
    int wr;
    int is_default_micro = (strcmp(opt.profile, "micro") == 0 && opt.hosts == 1 && opt.ipv4_exact == 1 && opt.ipv4_prefix == 2 &&
                            opt.domain_buckets == 2);
    if(is_default_micro)
      wr = write_micro_ndb(opt.out_file);
    else
      wr = write_synthetic_ndb(opt.out_file, &opt, &pool_used);
    if(wr != 0) {
      fprintf(stderr, "generation failed\n");
      free_pools(&ctx);
      return 1;
    }
    printf("generated: %s\n", opt.out_file);
    free_pools(&ctx);
    return 0;
  }

  /* ---- resolve path + generate (precedence: --ndb-file) ---- */
  if(opt.ndb_file[0]) {
    strncpy(ndb_work, opt.ndb_file, sizeof(ndb_work) - 1);
    ndb_work[sizeof(ndb_work) - 1] = '\0';
    use_temp_file = 0;
  } else if(opt.skip_build) {
    fprintf(stderr, "error: --skip-build requires --ndb-file\n");
    free_pools(&ctx);
    return 1;
  } else {
    if(opt.out_file[0]) {
      strncpy(ndb_work, opt.out_file, sizeof(ndb_work) - 1);
      ndb_work[sizeof(ndb_work) - 1] = '\0';
      use_temp_file = 0;
    } else {
      fd = mkstemp(tmpl);
      if(fd < 0) {
        perror("mkstemp");
        free_pools(&ctx);
        return 1;
      }
      close(fd);
      strncpy(ndb_work, tmpl, sizeof(ndb_work) - 1);
      ndb_work[sizeof(ndb_work) - 1] = '\0';
      use_temp_file = 1;
    }
    {
      int is_default_micro = (strcmp(opt.profile, "micro") == 0 && opt.hosts == 1 && opt.ipv4_exact == 1 && opt.ipv4_prefix == 2 &&
                              opt.domain_buckets == 2);
      if(is_default_micro) {
        if(write_micro_ndb(ndb_work) != 0) {
          fprintf(stderr, "write_micro_ndb failed\n");
          if(use_temp_file)
            unlink(ndb_work);
          free_pools(&ctx);
          return 1;
        }
      } else {
        if(write_synthetic_ndb(ndb_work, &opt, &pool_used) != 0) {
          fprintf(stderr, "write_synthetic_ndb failed\n");
          if(use_temp_file)
            unlink(ndb_work);
          free_pools(&ctx);
          return 1;
        }
      }
    }
  }

  if(stat(ndb_work, &st) != 0) {
    perror("stat ndb");
    free_pools(&ctx);
    return 1;
  }
  file_bytes = (uint64_t)st.st_size;
  (void)rss_bytes_self(&rss_after_gen);

after_generate:

  if(opt.ipv4_exact + opt.ipv4_prefix > 100000u)
    opt.warn_ipv4_linear = 1;

  if(opt.ndb_file[0] && (opt.backend == BACKEND_BOTH || opt.backend == BACKEND_LEGACY)) {
    opt.warn_unfair_compare = 1;
    snprintf(opt.unfair_reason, sizeof(opt.unfair_reason), "legacy not mirrored for external --ndb-file");
    opt.backend = BACKEND_NDB;
  }

  /* ---- load .ndb (skipped for legacy-only) ---- */
  if(opt.backend != BACKEND_LEGACY) {
    ndb_m = bench_ndb_load(ndb_work, &load_ndb_ms);
    if(!ndb_m) {
      fprintf(stderr, "ndpi_load_category_ndb_file failed\n");
      if(use_temp_file)
        unlink(ndb_work);
      free_pools(&ctx);
      return 1;
    }
    (void)rss_bytes_self(&rss_ndb);
  } else {
    load_ndb_ms = 0.0;
    rss_ndb = rss_b;
  }

  /* ---- legacy mirror ---- */
  {
    int skip_legacy = 0;
    size_t ipv4_rules = opt.ipv4_exact + opt.ipv4_prefix;
    if(opt.backend == BACKEND_LEGACY || opt.backend == BACKEND_BOTH) {
      if(!opt.force_legacy) {
        int over_hosts = opt.hosts > (size_t)LEGACY_MAX_HOSTS_DEFAULT;
        int over_v4 = ipv4_rules > (size_t)LEGACY_MAX_IPV4_RULES_DEFAULT;
        if(over_hosts || over_v4) {
          skip_legacy = 1;
          if(opt.backend == BACKEND_LEGACY) {
            if(over_hosts && over_v4) {
              fprintf(stderr,
                  "error: --backend legacy: default safety limits exceeded (max %u hosts, max %u total IPv4 "
                  "rules). Use --force-legacy, or --backend ndb|both, or lower --hosts / --ipv4-* counts.\n",
                  (unsigned)LEGACY_MAX_HOSTS_DEFAULT, (unsigned)LEGACY_MAX_IPV4_RULES_DEFAULT);
            } else if(over_hosts) {
              fprintf(stderr,
                  "error: --backend legacy: default safety limit exceeded (max %u hosts). Use --force-legacy, "
                  "or --backend ndb|both, or lower --hosts.\n",
                  (unsigned)LEGACY_MAX_HOSTS_DEFAULT);
            } else {
              fprintf(stderr,
                  "error: --backend legacy: default safety limit exceeded (max %u total IPv4 rules=exact+"
                  "prefix). Use --force-legacy, or --backend ndb|both, or lower --ipv4-*.\n",
                  (unsigned)LEGACY_MAX_IPV4_RULES_DEFAULT);
            }
            if(ndb_m) {
              ndpi_unload_category_ndb(ndb_m);
              ndpi_exit_detection_module(ndb_m);
            }
            if(use_temp_file && ndb_work[0])
              unlink(ndb_work);
            free_pools(&ctx);
            return 1;
          }
          opt.warn_unfair_compare = 1;
          if(over_hosts && over_v4) {
            snprintf(
                opt.unfair_reason, sizeof(opt.unfair_reason),
                "legacy skipped (exceeds default limits): hosts %zu > %u and ipv4 rules %zu > %u (use `--force-legacy`)",
                opt.hosts, (unsigned)LEGACY_MAX_HOSTS_DEFAULT, ipv4_rules, (unsigned)LEGACY_MAX_IPV4_RULES_DEFAULT);
          } else if(over_hosts) {
            snprintf(opt.unfair_reason, sizeof(opt.unfair_reason),
                "legacy skipped (exceeds default limits): hosts %zu > %u (use `--force-legacy`)", opt.hosts,
                (unsigned)LEGACY_MAX_HOSTS_DEFAULT);
          } else {
            snprintf(opt.unfair_reason, sizeof(opt.unfair_reason),
                "legacy skipped (exceeds default limits): ipv4 rules %zu > %u (use `--force-legacy`)", ipv4_rules,
                (unsigned)LEGACY_MAX_IPV4_RULES_DEFAULT);
          }
        }
      }
      if(!skip_legacy) {
        leg_m = ndpi_init_detection_module(NULL);
        if(!leg_m) {
          opt.warn_legacy_fallback = 1;
        } else {
          if(legacy_load_mirrored(leg_m, &opt, &load_legacy_ms) != 0) {
            opt.warn_legacy_fallback = 1;
	    if(leg_m)
              ndpi_exit_detection_module(leg_m);
            leg_m = NULL;
          } else {
            legacy_ran = 1;
            (void)rss_bytes_self(&rss_leg);
          }
        }
      }
    }
  }

  print_scenario_header(&opt, ndb_work, file_bytes, load_ndb_ms, load_legacy_ms, rss_ok ? rss_b : 0, rss_ok ? rss_ndb : 0,
      rss_ok ? rss_leg : 0, legacy_ran);
  printf("generator_rss_sample_after_file_bytes=%zu (best-effort RSS after .ndb on disk)\n", rss_after_gen);

  if(opt.only_load) {
    if(ndb_m) {
      ndpi_unload_category_ndb(ndb_m);
      ndpi_exit_detection_module(ndb_m);
    }
    if(leg_m)
      ndpi_exit_detection_module(leg_m);
    if(use_temp_file && ndb_work[0])
      unlink(ndb_work);
    free_pools(&ctx);
    return 0;
  }

  printf("%-12s %-28s (median ns/op + block percentiles; see --help)\n", "backend", "case");
  printf("%-12s %-28s %s\n", "-------", "----", "----------------------------------------");

#define RESET_CTX_INDICES()                                                                                            \
  do {                                                                                                                 \
    ctx.ix_hit = ctx.ix_miss = ctx.ix_ip_hit = ctx.ix_ip_lpm = ctx.ix_ip_miss = ctx.glob_ix = 0;                       \
  } while(0)

  lookup_ops_total = 0;
  if(ndb_m) {
    RESET_CTX_INDICES();
    run_case(".ndb", "hostname_hit", ndb_m, body_host_hit, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
    RESET_CTX_INDICES();
    run_case(".ndb", "hostname_miss", ndb_m, body_host_miss, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
    RESET_CTX_INDICES();
    run_case(".ndb", "ipv4_hit", ndb_m, body_ip_hit, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
    RESET_CTX_INDICES();
    run_case(".ndb", "ipv4_lpm", ndb_m, body_ip_lpm, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
    RESET_CTX_INDICES();
    run_case(".ndb", "ipv4_miss", ndb_m, body_ip_miss, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
  }
  if(leg_m) {
    RESET_CTX_INDICES();
    run_case("legacy", "hostname_hit", leg_m, body_host_hit, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
    RESET_CTX_INDICES();
    run_case("legacy", "hostname_miss", leg_m, body_host_miss, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
    RESET_CTX_INDICES();
    run_case("legacy", "ipv4_hit", leg_m, body_ip_hit, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
    RESET_CTX_INDICES();
    run_case("legacy", "ipv4_lpm", leg_m, body_ip_lpm, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
    RESET_CTX_INDICES();
    run_case("legacy", "ipv4_miss", leg_m, body_ip_miss, &ctx, &opt, (size_t)(opt.iters / (size_t)blocks_pr), blocks_pr);
    lookup_ops_total += opt.iters;
  }

#undef RESET_CTX_INDICES

  printf("\nlookup_ops_total=%zu  (5 cases × iters per backend row; see per-row ~ops_per_sec)\n", lookup_ops_total);
  printf("\nNote: IPv6 legacy vs .ndb not compared in this bench.\n");

  if(ndb_m) {
    ndpi_unload_category_ndb(ndb_m);
    ndpi_exit_detection_module(ndb_m);
  }
  if(leg_m)
    ndpi_exit_detection_module(leg_m);
  if(use_temp_file && ndb_work[0])
    unlink(ndb_work);
  free_pools(&ctx);
  return 0;
}

#endif
