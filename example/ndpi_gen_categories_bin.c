/*
 * ndpi_gen_categories_bin.c
 *
 * Usage:
 *   ./ndpi_gen_categories_bin -i /usr/local/ngfw/categories -o /usr/local/ngfw/base.ndb -V "2026-04-01"
 *
 * Format:
 *   [Header]
 *   [Category records]
 *   [Bucket table]
 *   [Entry table]
 *   [String pool]
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#if defined(_WIN32)
#include <io.h>
#endif

#include "ndpi_typedefs.h"
#include "ndpi_categories_bin.h"
#include "ndpi_category_host_norm.h"

#define INITIAL_CAP 1024

/*
 * PATH_MAX-sized buffers are too small for "dir/file" joins and trigger
 * -Wformat-truncation under -Werror: input_dir is PATH_MAX and readdir names
 * add up to NAME_MAX; temp output path also needs room for ".tmp." + pid.
 */
#ifndef NAME_MAX
#define NDPI_CATBIN_NAME_MAX 255u
#else
#define NDPI_CATBIN_NAME_MAX ((size_t)NAME_MAX)
#endif
#define NDPI_CATBIN_JOIN_BUFSZ ((size_t)PATH_MAX + NDPI_CATBIN_NAME_MAX + 2u)
#define NDPI_CATBIN_TMP_OUT_BUFSZ ((size_t)PATH_MAX + 64u)

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(ndb_header_disk_t) == 200, "ndb_header_disk_t size drift");
#endif

typedef struct {
  uint32_t id;
  char *name;
  uint32_t name_off;
} category_t;

typedef struct {
  uint64_t hash;
  char *domain;
  uint16_t domain_len;
  uint16_t flags;
  uint32_t category_id;
  uint32_t domain_off;
} entry_t;

typedef struct {
  uint32_t network_be;
  uint8_t  prefix_len;
  uint8_t  flags;
  uint32_t category_id;
} ipv4_entry_t;

typedef struct {
  uint8_t  addr[16];
  uint8_t  prefix_len;
  uint8_t  flags;
  uint32_t category_id;
} ipv6_entry_t;

typedef struct {
  ipv4_entry_t *items;
  size_t count;
  size_t cap;
} ipv4_entry_vec_t;

typedef struct {
  ipv6_entry_t *items;
  size_t count;
  size_t cap;
} ipv6_entry_vec_t;

typedef struct {
  category_t *items;
  size_t count;
  size_t cap;
} category_vec_t;

typedef struct {
  entry_t *items;
  size_t count;
  size_t cap;
} entry_vec_t;

typedef struct {
  char *data;
  size_t len;
  size_t cap;
} strpool_t;

typedef enum {
  RULE_INVALID = 0,
  RULE_DOMAIN,
  RULE_IPV4,
  RULE_IPV6
} rule_kind_t;

typedef struct {
  rule_kind_t kind;
  char text[4096]; /* domain or canonical textual representation of IP/CIDR */
} parsed_rule_t;

/* set per input file while parsing lines (error context) */
static const char *g_parse_src_file;
/* if set: in mixed lists, treat bare IPv4-looking tokens without '/' as domains, not hosts */
static int g_ip_only_cidr;

typedef enum {
  CONFLICT_POLICY_ERROR = 0,
  CONFLICT_POLICY_WARN_IGNORE,
  CONFLICT_POLICY_FIRST_WINS,
  CONFLICT_POLICY_LAST_WINS
} conflict_policy_t;

static conflict_policy_t g_conflict_policy = CONFLICT_POLICY_ERROR;
static const char *g_conflict_policy_label = "error";

static void dief(const char *msg);

static void set_conflict_policy_arg(const char *s) {
  if(!s || !*s)
    dief("invalid --conflict-policy");
  if(strcasecmp(s, "error") == 0) {
    g_conflict_policy = CONFLICT_POLICY_ERROR;
    g_conflict_policy_label = "error";
    return;
  }
  if(strcasecmp(s, "warn-ignore") == 0) {
    g_conflict_policy = CONFLICT_POLICY_WARN_IGNORE;
    g_conflict_policy_label = "warn-ignore";
    return;
  }
  if(strcasecmp(s, "first-wins") == 0) {
    g_conflict_policy = CONFLICT_POLICY_FIRST_WINS;
    g_conflict_policy_label = "first-wins";
    return;
  }
  if(strcasecmp(s, "last-wins") == 0) {
    g_conflict_policy = CONFLICT_POLICY_LAST_WINS;
    g_conflict_policy_label = "last-wins";
    return;
  }
  dief("invalid --conflict-policy (expected error|warn-ignore|first-wins|last-wins)");
}

static void die(const char *msg) {
  perror(msg);
  exit(1);
}

static void dief(const char *msg) {
  fprintf(stderr, "ERROR: %s\n", msg);
  exit(1);
}

/* MinGW/MSVC may not declare getline(); behaviour matches POSIX for this tool. */
static ssize_t catbin_getline(char **lineptr, size_t *n, FILE *fp) {
  size_t pos = 0;

  if(!lineptr || !n || !fp)
    return -1;

  for(;;) {
    if(pos + 2 > *n) {
      size_t newsz = *n ? *n * 2 : 256;
      while(newsz < pos + 2)
        newsz *= 2;
      char *p = realloc(*lineptr, newsz);
      if(!p)
        return -1;
      *lineptr = p;
      *n = newsz;
    }
    {
      int c = fgetc(fp);
      if(c == EOF) {
        if(pos == 0)
          return -1;
        (*lineptr)[pos] = '\0';
        return (ssize_t)pos;
      }
      (*lineptr)[pos++] = (char)(unsigned char)c;
      if(c == '\n') {
        (*lineptr)[pos] = '\0';
        return (ssize_t)pos;
      }
    }
  }
}

static void *xmalloc(size_t n) {
  void *p = malloc(n);
  if(!p) die("malloc");
  return p;
}

static void *xrealloc(void *p, size_t n) {
  void *q = realloc(p, n);
  if(!q) die("realloc");
  return q;
}

static char *xstrdup(const char *s) {
  char *p = strdup(s);
  if(!p) die("strdup");
  return p;
}

static uint64_t fnv1a64(const char *s, size_t len) {
  uint64_t h = 1469598103934665603ULL;
  for(size_t i = 0; i < len; ++i) {
    h ^= (unsigned char)s[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static int looks_like_ip_candidate(const char *s) {
  for(const char *p = s; *p; ++p) {
    unsigned char c = (unsigned char)*p;
    if(isdigit(c) || c == '.' || c == ':' || c == '/' ||
        (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
      continue;
    }
    return 0;
  }
  return 1;
}

static void category_vec_push(category_vec_t *v, category_t c) {
  if(v->count == v->cap) {
    v->cap = v->cap ? v->cap * 2 : INITIAL_CAP;
    v->items = xrealloc(v->items, v->cap * sizeof(v->items[0]));
  }
  v->items[v->count++] = c;
}

static void entry_vec_push(entry_vec_t *v, entry_t e) {
  if(v->count == v->cap) {
    v->cap = v->cap ? v->cap * 2 : INITIAL_CAP;
    v->items = xrealloc(v->items, v->cap * sizeof(v->items[0]));
  }
  v->items[v->count++] = e;
}

static void ipv4_entry_vec_push(ipv4_entry_vec_t *v, ipv4_entry_t e) {
  if(v->count == v->cap) {
    v->cap = v->cap ? v->cap * 2 : INITIAL_CAP;
    v->items = xrealloc(v->items, v->cap * sizeof(v->items[0]));
  }
  v->items[v->count++] = e;
}

static void ipv6_entry_vec_push(ipv6_entry_vec_t *v, ipv6_entry_t e) {
  if(v->count == v->cap) {
    v->cap = v->cap ? v->cap * 2 : INITIAL_CAP;
    v->items = xrealloc(v->items, v->cap * sizeof(v->items[0]));
  }
  v->items[v->count++] = e;
}

static category_t *find_category_by_id(category_vec_t *v, uint32_t id) {
  for(size_t i = 0; i < v->count; ++i) {
    if(v->items[i].id == id) return &v->items[i];
  }
  return NULL;
}

static category_t *find_or_add_category(category_vec_t *v, uint32_t id, const char *name) {
  category_t *found = find_category_by_id(v, id);
  if(found) {
    if(strcmp(found->name, name) != 0) {
      fprintf(stderr, "ERROR: category id %u reused with different names: '%s' vs '%s'\n",
          id, found->name, name);
      exit(1);
    }
    return found;
  }

  category_t cat = {0};
  cat.id = id;
  cat.name = xstrdup(name);
  category_vec_push(v, cat);
  return &v->items[v->count - 1];
}

static uint32_t strpool_add(strpool_t *p, const char *s, size_t len) {
  if(p->len + len + 1 > p->cap) {
    size_t new_cap = p->cap ? p->cap * 2 : 4096;
    while(new_cap < p->len + len + 1) new_cap *= 2;
    p->data = xrealloc(p->data, new_cap);
    p->cap = new_cap;
  }
  uint32_t off = (uint32_t)p->len;
  memcpy(p->data + p->len, s, len);
  p->len += len;
  p->data[p->len++] = '\0';
  return off;
}

static size_t next_pow2(size_t v) {
  size_t p = 1;
  while(p < v) p <<= 1;
  return p;
}

/* ---------- category-aware dedupe (cross-category policy) ---------- */

typedef enum { DEDUPE_DOMAIN = 0, DEDUPE_IPV4, DEDUPE_IPV6 } dedupe_kind_t;

typedef struct catdedupe_node {
  char *key;
  uint32_t cat_id;
  size_t entry_index;
  struct catdedupe_node *next;
} catdedupe_node_t;

typedef struct {
  catdedupe_node_t **buckets;
  size_t nbuckets;
} catdedupe_t;

typedef struct {
  conflict_policy_t policy;
  uint64_t *conflicts_total;
  uint64_t *conflicts_ignored;
  uint64_t *conflicts_overwritten;
  entry_vec_t *domain_entries;
  ipv4_entry_vec_t *ipv4_entries;
  ipv6_entry_vec_t *ipv6_entries;
} catdedupe_ctx_t;

static void catdedupe_init(catdedupe_t *d, size_t nbuckets) {
  d->nbuckets = nbuckets ? nbuckets : 65536;
  d->buckets = calloc(d->nbuckets, sizeof(*d->buckets));
  if(!d->buckets) die("calloc catdedupe");
}

static void catdedupe_free(catdedupe_t *d) {
  if(!d || !d->buckets) return;
  for(size_t i = 0; i < d->nbuckets; ++i) {
    catdedupe_node_t *n = d->buckets[i];
    while(n) {
      catdedupe_node_t *nx = n->next;
      free(n->key);
      free(n);
      n = nx;
    }
  }
  free(d->buckets);
  d->buckets = NULL;
}

/*
 * Return 0 = new key (out_interned = stable pointer to stored key when non-NULL),
 * 1 = duplicate (same category skip, or resolved conflict per policy).
 */
static int catdedupe_add(catdedupe_t *d, dedupe_kind_t kind, const char *key, uint32_t cat_id,
    const char *src_file, size_t new_entry_index, catdedupe_ctx_t *ctx,
    const char **out_interned) {
  uint64_t h = fnv1a64(key, strlen(key));
  size_t b = (size_t)(h % d->nbuckets);

  for(catdedupe_node_t *n = d->buckets[b]; n; n = n->next) {
    if(strcmp(n->key, key) == 0) {
      if(n->cat_id == cat_id)
        return 1;

      if(ctx->policy == CONFLICT_POLICY_ERROR) {
        fprintf(stderr,
            "ERROR: entry '%s' appears in category %u and %u (conflict). Source file: %s\n",
            key, n->cat_id, cat_id, src_file ? src_file : "?");
        exit(1);
      }

      (*ctx->conflicts_total)++;
      if(ctx->policy == CONFLICT_POLICY_WARN_IGNORE) {
        fprintf(stderr,
            "WARN: entry '%s' category conflict %u vs %u; keeping first (file %s ignored; policy=warn-ignore)\n",
            key, n->cat_id, cat_id, src_file ? src_file : "?");
        (*ctx->conflicts_ignored)++;
        return 1;
      }
      if(ctx->policy == CONFLICT_POLICY_FIRST_WINS) {
        (*ctx->conflicts_ignored)++;
        return 1;
      }
      if(ctx->policy == CONFLICT_POLICY_LAST_WINS) {
        n->cat_id = cat_id;
        (*ctx->conflicts_overwritten)++;
        switch(kind) {
          case DEDUPE_DOMAIN:
            if(n->entry_index < ctx->domain_entries->count)
              ctx->domain_entries->items[n->entry_index].category_id = cat_id;
            break;
          case DEDUPE_IPV4:
            if(n->entry_index < ctx->ipv4_entries->count)
              ctx->ipv4_entries->items[n->entry_index].category_id = cat_id;
            break;
          case DEDUPE_IPV6:
            if(n->entry_index < ctx->ipv6_entries->count)
              ctx->ipv6_entries->items[n->entry_index].category_id = cat_id;
            break;
        }
        return 1;
      }
      dief("internal: bad conflict policy");
    }
  }

  catdedupe_node_t *n = (catdedupe_node_t *)malloc(sizeof(*n));
  if(!n) die("malloc catdedupe_node");
  n->key = xstrdup(key);
  n->cat_id = cat_id;
  n->entry_index = new_entry_index;
  n->next = d->buckets[b];
  d->buckets[b] = n;
  if(out_interned)
    *out_interned = n->key;
  return 0;
}

static char *trim(char *s) {
  while(*s && isspace((unsigned char)*s)) s++;
  if(!*s) return s;

  char *end = s + strlen(s) - 1;
  while(end > s && isspace((unsigned char)*end)) {
    *end = '\0';
    end--;
  }
  return s;
}

static void strip_comment(char *s) {
  for(char *p = s; *p; ++p) {
    if(*p == '#') {
      *p = '\0';
      return;
    }
  }
}

static int normalize_raw_line(const char *input, char *out, size_t out_sz) {
  if(strlen(input) + 1 > out_sz) return 0;
  strcpy(out, input);

  strip_comment(out);

  char *s = trim(out);
  if(s != out) memmove(out, s, strlen(s) + 1);

  if(out[0] == '\0') return 0;
  return 1;
}

static int normalize_ipv4_or_cidr_line(const char *input, char *out, size_t out_sz) {
  if(strlen(input) + 1 > out_sz) return 0;
  strcpy(out, input);

  strip_comment(out);
  char *s = trim(out);
  if(s != out) memmove(out, s, strlen(s) + 1);
  if(out[0] == '\0') return 0;

  char *slash = strchr(out, '/');
  uint32_t prefix = 32;

  if(slash) {
    *slash = '\0';
    char *pfx = trim(slash + 1);
    if(*pfx == '\0') return 0;

    char *endp = NULL;
    unsigned long x = strtoul(pfx, &endp, 10);
    if(*endp != '\0' || x > 32) return 0;
    prefix = (uint32_t)x;
  }

  struct in_addr a4;
  if(inet_pton(AF_INET, out, &a4) != 1) return 0;

  uint32_t host = ntohl(a4.s_addr);
  uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
  uint32_t net = host & mask;

  struct in_addr net4;
  net4.s_addr = htonl(net);

  char ipbuf[INET_ADDRSTRLEN];
  if(!inet_ntop(AF_INET, &net4, ipbuf, sizeof(ipbuf))) return 0;

  if(prefix == 32) {
    if(strlen(ipbuf) + 1 > out_sz) return 0;
    snprintf(out, out_sz, "%s", ipbuf);
  } else {
    if(strlen(ipbuf) + 4 > out_sz) return 0;
    snprintf(out, out_sz, "%s/%u", ipbuf, prefix);
  }

  return 1;
}

static int normalize_ipv6_or_cidr_line(const char *input, char *out, size_t out_sz) {
  if(strlen(input) + 1 > out_sz) return 0;
  strcpy(out, input);

  strip_comment(out);
  char *s = trim(out);
  if(s != out) memmove(out, s, strlen(s) + 1);
  if(out[0] == '\0') return 0;

  char *slash = strchr(out, '/');
  uint32_t prefix = 128;

  if(slash) {
    *slash = '\0';
    char *pfx = trim(slash + 1);
    if(*pfx == '\0') return 0;

    char *endp = NULL;
    unsigned long x = strtoul(pfx, &endp, 10);
    if(*endp != '\0' || x > 128) return 0;
    prefix = (uint32_t)x;
  }

  uint8_t addr[16];
  if(inet_pton(AF_INET6, out, addr) != 1) return 0;

  uint8_t net[16];
  memcpy(net, addr, 16);

  uint32_t bits = prefix;
  for(int i = 0; i < 16; ++i) {
    if(bits >= 8) {
      bits -= 8;
    } else if(bits == 0) {
      net[i] = 0;
    } else {
      net[i] &= (uint8_t)(0xFF << (8 - bits));
      bits = 0;
    }
  }

  char ipbuf[INET6_ADDRSTRLEN];
  if(!inet_ntop(AF_INET6, net, ipbuf, sizeof(ipbuf))) return 0;

  if(prefix == 128) {
    if(strlen(ipbuf) + 1 > out_sz) return 0;
    snprintf(out, out_sz, "%s", ipbuf);
  } else {
    if(strlen(ipbuf) + 6 > out_sz) return 0;
    snprintf(out, out_sz, "%s/%u", ipbuf, prefix);
  }

  return 1;
}

static int parse_mixed_rule_line(const char *line, parsed_rule_t *out) {
  char raw[4096];

  memset(out, 0, sizeof(*out));

  if(!normalize_raw_line(line, raw, sizeof(raw))) {
    return 0;
  }

  /*
   * Order is important:
   * 1) IPv4/CIDR
   * 2) IPv6/CIDR
   * 3) domain (same normalization as the .ndb runtime)
   */
  {
    int try_ip = looks_like_ip_candidate(raw);

    if(try_ip && g_ip_only_cidr && strchr(raw, '/') == NULL)
      try_ip = 0;

    if(try_ip) {
      char ip4[128];
      if(normalize_ipv4_or_cidr_line(raw, ip4, sizeof(ip4))) {
        out->kind = RULE_IPV4;
        snprintf(out->text, sizeof(out->text), "%s", ip4);
        return 1;
      }

      char ip6[256];
      if(normalize_ipv6_or_cidr_line(raw, ip6, sizeof(ip6))) {
        out->kind = RULE_IPV6;
        snprintf(out->text, sizeof(out->text), "%s", ip6);
        return 1;
      }
    }
  }

  {
    char dom[4096];

    if(ndpi_category_normalize_host_for_ndb(raw, dom, sizeof(dom)) != 0)
      return 0;

    if(ndpi_category_hostname_is_isolated_tld(dom)) {
      fprintf(stderr,
          "ERROR: isolated public-TLD label not allowed in .ndb input: '%s' (%s)\n",
          dom, g_parse_src_file ? g_parse_src_file : "?");
      exit(1);
    }

    if(strchr(dom, '.') == NULL) {
      fprintf(stderr,
          "ERROR: hostname must include a dot (FQDN), not a single label: '%s' (%s)\n",
          dom, g_parse_src_file ? g_parse_src_file : "?");
      exit(1);
    }

    out->kind = RULE_DOMAIN;
    snprintf(out->text, sizeof(out->text), "%s", dom);
    return 1;
  }
}

static int is_regular_file(const char *path) {
  struct stat st;
  if(stat(path, &st) != 0) return 0;
  return S_ISREG(st.st_mode);
}

static int cmp_strptr(const void *a, const void *b) {
  const char * const *sa = a;
  const char * const *sb = b;
  return strcmp(*sa, *sb);
}

static int cmp_entry_hash_domain(const void *a, const void *b) {
  const entry_t *ea = a;
  const entry_t *eb = b;

  if(ea->hash < eb->hash) return -1;
  if(ea->hash > eb->hash) return 1;

  int c = strcmp(ea->domain, eb->domain);
  if(c != 0) return c;

  if(ea->category_id < eb->category_id) return -1;
  if(ea->category_id > eb->category_id) return 1;
  return 0;
}

static int cmp_ipv4_entry(const void *a, const void *b) {
  const ipv4_entry_t *ea = a;
  const ipv4_entry_t *eb = b;

  uint32_t na = ntohl(ea->network_be);
  uint32_t nb = ntohl(eb->network_be);

  if(na < nb) return -1;
  if(na > nb) return 1;

  if(ea->prefix_len < eb->prefix_len) return -1;
  if(ea->prefix_len > eb->prefix_len) return 1;

  if(ea->category_id < eb->category_id) return -1;
  if(ea->category_id > eb->category_id) return 1;

  return 0;
}

static int cmp_ipv6_entry(const void *a, const void *b) {
  const ipv6_entry_t *ea = a;
  const ipv6_entry_t *eb = b;

  int c = memcmp(ea->addr, eb->addr, 16);
  if(c != 0) return c;

  if(ea->prefix_len < eb->prefix_len) return -1;
  if(ea->prefix_len > eb->prefix_len) return 1;

  if(ea->category_id < eb->category_id) return -1;
  if(ea->category_id > eb->category_id) return 1;

  return 0;
}

static int has_suffix_exact(const char *s, const char *suffix) {
  size_t sl = strlen(s);
  size_t xl = strlen(suffix);
  if(sl < xl) return 0;
  return strcmp(s + sl - xl, suffix) == 0;
}

static int is_domain_list_file(const char *filename) {
  if(has_suffix_exact(filename, ".ipv4.list")) return 0;
  if(has_suffix_exact(filename, ".ipv6.list")) return 0;
  return has_suffix_exact(filename, ".list");
}

static int is_ipv4_list_file(const char *filename) {
  return has_suffix_exact(filename, ".ipv4.list");
}

static int is_ipv6_list_file(const char *filename) {
  return has_suffix_exact(filename, ".ipv6.list");
}

/* Canonical masked network for stable dedupe keys and on-disk rows. */
static void ipv4_apply_mask(ipv4_entry_t *e) {
  uint32_t a = ntohl(e->network_be);
  uint8_t pl = e->prefix_len;

  if(pl >= 32)
    return;
  if(pl == 0) {
    e->network_be = 0;
    return;
  }
  {
    uint32_t m = 0xffffffffu << (32u - (uint32_t)pl);
    e->network_be = htonl(a & m);
  }
}

static void ipv4_canonical_key(const ipv4_entry_t *e, char *out, size_t out_sz) {
  struct in_addr a4;
  char ip[INET_ADDRSTRLEN];

  a4.s_addr = e->network_be;
  inet_ntop(AF_INET, &a4, ip, sizeof(ip));
  snprintf(out, out_sz, "%s/%u", ip, (unsigned)e->prefix_len);
}

static void ipv6_apply_mask(uint8_t addr[16], uint8_t pl) {
  unsigned full = (unsigned)pl / 8;
  unsigned rem = (unsigned)pl % 8;
  unsigned i;

  if(pl >= 128)
    return;
  if(rem) {
    uint8_t m = (uint8_t)(0xffu << (8 - rem));
    addr[full] &= m;
    full++;
  }
  for(i = full; i < 16; i++)
    addr[i] = 0;
}

static void ipv6_canonical_key(const uint8_t addr[16], uint8_t pl, char *out, size_t out_sz) {
  size_t pos = 0;
  unsigned j;

  for(j = 0; j < 16 && pos + 3 < out_sz; j++)
    pos += (size_t)snprintf(out + pos, out_sz - pos, "%02x", addr[j]);
  snprintf(out + pos, out_sz - pos, "/%u", (unsigned)pl);
}

static int parse_ipv4_canonical(const char *s, ipv4_entry_t *out, uint32_t category_id) {
  char tmp[64];
  snprintf(tmp, sizeof(tmp), "%s", s);

  char *slash = strchr(tmp, '/');
  uint32_t prefix = 32;
  if(slash) {
    *slash = '\0';
    prefix = (uint32_t)strtoul(slash + 1, NULL, 10);
  }

  struct in_addr a4;
  if(inet_pton(AF_INET, tmp, &a4) != 1) return 0;

  out->network_be = a4.s_addr;
  out->prefix_len = (uint8_t)prefix;
  out->flags = 0;
  out->category_id = category_id;
  ipv4_apply_mask(out);
  return 1;
}

static int parse_ipv6_canonical(const char *s, ipv6_entry_t *out, uint32_t category_id) {
  char tmp[128];
  snprintf(tmp, sizeof(tmp), "%s", s);

  char *slash = strchr(tmp, '/');
  uint32_t prefix = 128;
  if(slash) {
    *slash = '\0';
    prefix = (uint32_t)strtoul(slash + 1, NULL, 10);
  }

  if(inet_pton(AF_INET6, tmp, out->addr) != 1) return 0;

  out->prefix_len = (uint8_t)prefix;
  out->flags = 0;
  out->category_id = category_id;
  ipv6_apply_mask(out->addr, out->prefix_len);
  return 1;
}

static int parse_category_filename(const char *filename, uint32_t auto_id,
    uint32_t *out_id, char *out_name, size_t out_name_sz) {
  char tmp[PATH_MAX];

  (void)auto_id;
  size_t len = strlen(filename);

  if(len >= sizeof(tmp)) {
    fprintf(stderr, "ERROR: filename too long: %s\n", filename);
    exit(EXIT_FAILURE);
  }

  memcpy(tmp, filename, len + 1);

  if(has_suffix_exact(tmp, ".ipv4.list")) {
    tmp[len - strlen(".ipv4.list")] = '\0';
  } else if(has_suffix_exact(tmp, ".ipv6.list")) {
    tmp[len - strlen(".ipv6.list")] = '\0';
  } else if(has_suffix_exact(tmp, ".list")) {
    tmp[len - strlen(".list")] = '\0';
  } else {
    return 0;
  }

  char *underscore = strchr(tmp, '_');
  if(underscore) {
    int all_digits = 1;
    for(char *p = tmp; p < underscore; ++p) {
      if(!isdigit((unsigned char)*p)) {
        all_digits = 0;
        break;
      }
    }
    if(all_digits && underscore > tmp) {
      *out_id = (uint32_t)strtoul(tmp, NULL, 10);

      if(strlen(underscore + 1) >= out_name_sz) {
        fprintf(stderr, "ERROR: category name too long: %s\n", filename);
        exit(EXIT_FAILURE);
      }
      snprintf(out_name, out_name_sz, "%s", underscore + 1);
      return 1;
    }
  }

  fprintf(stderr, "ERROR: category file name must use '<id>_<name>.list' (numeric id prefix): %s\n", filename);
  exit(EXIT_FAILURE);
}

static void ensure_parent_dir_exists(const char *path) {
  char tmp[PATH_MAX];
  snprintf(tmp, sizeof(tmp), "%s", path);
  char *slash = strrchr(tmp, '/');
  if(!slash) return;
  *slash = '\0';
  if(tmp[0] == '\0') return;

  struct stat st;
  if(stat(tmp, &st) != 0) {
    fprintf(stderr, "ERROR: parent directory does not exist: %s\n", tmp);
    exit(1);
  }
  if(!S_ISDIR(st.st_mode)) {
    fprintf(stderr, "ERROR: parent path is not a directory: %s\n", tmp);
    exit(1);
  }
}

static void catbin_join_path(char *dst, size_t dstsz, const char *dir, size_t dir_cap, const char *name,
    size_t name_max) {
  size_t dlen = strnlen(dir, dir_cap ? dir_cap - 1 : 0);
  size_t nlen = strnlen(name, name_max);

  if(dlen + 1 + nlen >= dstsz) dief("path too long");
  memcpy(dst, dir, dlen);
  dst[dlen] = '/';
  memcpy(dst + dlen + 1, name, nlen);
  dst[dlen + 1 + nlen] = '\0';
}

static void catbin_mk_tmp_output_path(char *dst, size_t dstsz, const char *output_file, size_t out_cap) {
  size_t olen = strnlen(output_file, out_cap ? out_cap - 1 : 0);
  char suf[48];
  int sl = snprintf(suf, sizeof(suf), ".tmp.%d", (int)getpid());

  if(sl < 0 || (size_t)sl >= sizeof(suf)) dief("temp output path suffix");
  if(olen + (size_t)sl + 1 > dstsz) dief("output path too long");

  memcpy(dst, output_file, olen);
  memcpy(dst + olen, suf, (size_t)sl + 1);
}

int main(int argc, char **argv) {
  char input_dir[PATH_MAX] = {0};
  char output_file[PATH_MAX] = {0};
  char base_version[64] = {0};

  g_ip_only_cidr = 0;

  static const struct option lopts[] = {
    { "ip-only-with-mask", no_argument, NULL, 1000 },
    { "conflict-policy", required_argument, NULL, 2001 },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
  };

  int opt;
  while((opt = getopt_long(argc, argv, "i:o:V:h", lopts, NULL)) != -1) {
    switch(opt) {
      case 'i':
        snprintf(input_dir, sizeof(input_dir), "%s", optarg);
        break;
      case 'o':
        snprintf(output_file, sizeof(output_file), "%s", optarg);
        break;
      case 'V':
        snprintf(base_version, sizeof(base_version), "%s", optarg);
        break;
      case 1000:
        g_ip_only_cidr = 1;
        break;
      case 2001:
        set_conflict_policy_arg(optarg);
        break;
      case 'h':
        fprintf(stderr,
            "Usage: %s -i <categories_dir> -o <output.ndb> -V <base_version> [options]\n",
            argv[0]);
        fprintf(stderr,
            "  --ip-only-with-mask     In mixed .list files, require '/' for IPv4/IPv6 (else parse as FQDN).\n");
        fprintf(stderr,
            "  --conflict-policy <p>   Cross-category duplicate key: error (default), warn-ignore, first-wins,\n"
            "                          last-wins. Processing order is deterministic (sorted input filenames,\n"
            "                          then line order per file); first/last refer to that order.\n");
        return 0;
      default:
        fprintf(stderr,
            "Usage: %s -i <categories_dir> -o <output.ndb> -V <base_version> [options]\n",
            argv[0]);
        return 1;
    }
  }

  if(input_dir[0] == '\0' || output_file[0] == '\0' || base_version[0] == '\0') {
    fprintf(stderr,
        "Usage: %s -i <categories_dir> -o <output.ndb> -V <base_version> [options]\n",
        argv[0]);
    return 1;
  }

  struct stat st;
  if(stat(input_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
    fprintf(stderr, "ERROR: invalid input directory: %s\n", input_dir);
    return 1;
  }

  ensure_parent_dir_exists(output_file);

  DIR *dir = opendir(input_dir);
  if(!dir) die("opendir");

  char **file_list = NULL;
  size_t file_count = 0, file_cap = 0;

  struct dirent *de;
  while((de = readdir(dir)) != NULL) {
    if(strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

    char path[NDPI_CATBIN_JOIN_BUFSZ];
    catbin_join_path(path, sizeof(path), input_dir, sizeof(input_dir), de->d_name, NDPI_CATBIN_NAME_MAX + 1);

    if(!is_regular_file(path)) continue;
    if(file_count == file_cap) {
      file_cap = file_cap ? file_cap * 2 : 128;
      file_list = xrealloc(file_list, file_cap * sizeof(file_list[0]));
    }
    file_list[file_count++] = xstrdup(de->d_name);
  }
  closedir(dir);

  if(file_count == 0) dief("no category files found");

  qsort(file_list, file_count, sizeof(file_list[0]), cmp_strptr);

  category_vec_t categories = {0};

  entry_vec_t domain_entries = {0};
  ipv4_entry_vec_t ipv4_entries = {0};
  ipv6_entry_vec_t ipv6_entries = {0};

  catdedupe_t domain_dedupe;
  catdedupe_t ipv4_dedupe;
  catdedupe_t ipv6_dedupe;

  catdedupe_init(&domain_dedupe, 1u << 20);
  catdedupe_init(&ipv4_dedupe, 65536);
  catdedupe_init(&ipv6_dedupe, 65536);

  uint64_t conflict_total = 0, conflict_ignored = 0, conflict_overwritten = 0;
  catdedupe_ctx_t dedupe_ctx = {.policy = g_conflict_policy,
    .conflicts_total = &conflict_total,
    .conflicts_ignored = &conflict_ignored,
    .conflicts_overwritten = &conflict_overwritten,
    .domain_entries = &domain_entries,
    .ipv4_entries = &ipv4_entries,
    .ipv6_entries = &ipv6_entries};

  for(size_t i = 0; i < file_count; ++i) {
    char filepath[NDPI_CATBIN_JOIN_BUFSZ];
    catbin_join_path(filepath, sizeof(filepath), input_dir, sizeof(input_dir), file_list[i],
        NDPI_CATBIN_NAME_MAX + 1);

    if(!(is_domain_list_file(file_list[i]) ||
          is_ipv4_list_file(file_list[i]) ||
          is_ipv6_list_file(file_list[i]))) {
      fprintf(stderr, "Skipping unsupported file: %s\n", file_list[i]);
      continue;
    }

    uint32_t cat_id;
    char cat_name[256];
    if(!parse_category_filename(file_list[i], 0, &cat_id, cat_name, sizeof(cat_name))) {
      fprintf(stderr, "WARN: failed to parse category file name: %s\n", file_list[i]);
      continue;
    }

    if(cat_id == 0 || cat_id >= NDPI_PROTOCOL_NUM_CATEGORIES) {
      fprintf(stderr, "ERROR: category id %u out of range (must be 0 < id < %d): %s\n", cat_id,
          NDPI_PROTOCOL_NUM_CATEGORIES, file_list[i]);
      exit(EXIT_FAILURE);
    }

    (void)find_or_add_category(&categories, cat_id, cat_name);

    FILE *fp = fopen(filepath, "r");
    if(!fp) {
      fprintf(stderr, "WARN: cannot open %s: %s\n", filepath, strerror(errno));
      continue;
    }

    fprintf(stderr, "Processing [%zu/%zu] %s...\n", i + 1, file_count, file_list[i]);

    g_parse_src_file = file_list[i];

    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;

    uint64_t added_domains_this_file = 0;
    uint64_t added_ipv4_this_file = 0;
    uint64_t added_ipv6_this_file = 0;
    uint64_t skipped_this_file = 0;

    while((linelen = catbin_getline(&line, &linecap, fp)) != -1) {
      (void)linelen;

      if(is_domain_list_file(file_list[i])) {
        parsed_rule_t rule;

        if(!parse_mixed_rule_line(line, &rule)) {
          skipped_this_file++;
          continue;
        }

        if(rule.kind == RULE_DOMAIN) {
          const char *interned = NULL;

          if(catdedupe_add(&domain_dedupe, DEDUPE_DOMAIN, rule.text, cat_id, file_list[i], domain_entries.count,
                &dedupe_ctx, &interned))
            continue;

          entry_t e = {0};
          e.hash = fnv1a64(interned, strlen(interned));
          e.domain = (char *)interned;
          e.domain_len = (uint16_t)strlen(interned);
          e.flags = 0;
          e.category_id = cat_id;
          entry_vec_push(&domain_entries, e);
          added_domains_this_file++;
          continue;
        }

        if(rule.kind == RULE_IPV4) {
          ipv4_entry_t e = {0};

          if(!parse_ipv4_canonical(rule.text, &e, cat_id)) {
            skipped_this_file++;
            continue;
          }
          {
            char dedk[INET_ADDRSTRLEN + 16];

            ipv4_canonical_key(&e, dedk, sizeof(dedk));
            if(catdedupe_add(&ipv4_dedupe, DEDUPE_IPV4, dedk, cat_id, file_list[i], ipv4_entries.count,
                  &dedupe_ctx, NULL))
              continue;
          }

          ipv4_entry_vec_push(&ipv4_entries, e);
          added_ipv4_this_file++;
          continue;
        }

        if(rule.kind == RULE_IPV6) {
          ipv6_entry_t e = {{0}, 0, 0, 0};

          if(!parse_ipv6_canonical(rule.text, &e, cat_id)) {
            skipped_this_file++;
            continue;
          }
          {
            char dedk[48];

            ipv6_canonical_key(e.addr, e.prefix_len, dedk, sizeof(dedk));
            if(catdedupe_add(&ipv6_dedupe, DEDUPE_IPV6, dedk, cat_id, file_list[i], ipv6_entries.count,
                  &dedupe_ctx, NULL))
              continue;
          }

          ipv6_entry_vec_push(&ipv6_entries, e);
          added_ipv6_this_file++;
          continue;
        }

        skipped_this_file++;
        continue;
      }

      if(is_ipv4_list_file(file_list[i])) {
        char normalized[128];
        if(!normalize_ipv4_or_cidr_line(line, normalized, sizeof(normalized))) {
          skipped_this_file++;
          continue;
        }

        ipv4_entry_t e = {0};

        if(!parse_ipv4_canonical(normalized, &e, cat_id)) {
          skipped_this_file++;
          continue;
        }
        {
          char dedk[INET_ADDRSTRLEN + 16];

          ipv4_canonical_key(&e, dedk, sizeof(dedk));
          if(catdedupe_add(&ipv4_dedupe, DEDUPE_IPV4, dedk, cat_id, file_list[i], ipv4_entries.count,
                &dedupe_ctx, NULL))
            continue;
        }
        ipv4_entry_vec_push(&ipv4_entries, e);
        added_ipv4_this_file++;
        continue;
      }

      if(is_ipv6_list_file(file_list[i])) {
        char normalized[256];
        if(!normalize_ipv6_or_cidr_line(line, normalized, sizeof(normalized))) {
          skipped_this_file++;
          continue;
        }

        ipv6_entry_t e = {{0}, 0, 0, 0};

        if(!parse_ipv6_canonical(normalized, &e, cat_id)) {
          skipped_this_file++;
          continue;
        }
        {
          char dedk[48];

          ipv6_canonical_key(e.addr, e.prefix_len, dedk, sizeof(dedk));
          if(catdedupe_add(&ipv6_dedupe, DEDUPE_IPV6, dedk, cat_id, file_list[i], ipv6_entries.count,
                &dedupe_ctx, NULL))
            continue;
        }
        ipv6_entry_vec_push(&ipv6_entries, e);
        added_ipv6_this_file++;
        continue;
      }

      skipped_this_file++;
    }

    free(line);
    fclose(fp);

    fprintf(stderr,
        "Category %-32s id=%u domains=%" PRIu64 " ipv4=%" PRIu64 " ipv6=%" PRIu64 " skipped=%" PRIu64 "\n",
        file_list[i], cat_id,
        added_domains_this_file,
        added_ipv4_this_file,
        added_ipv6_this_file,
        skipped_this_file);
  }

  fprintf(stderr, "Conflict summary: total=%" PRIu64 " ignored=%" PRIu64 " overwritten=%" PRIu64 " policy=%s\n",
      conflict_total, conflict_ignored, conflict_overwritten, g_conflict_policy_label);

  fprintf(stderr, "Finished reading all category domain files. entries=%zu\n", domain_entries.count);
  fprintf(stderr, "Finished reading all category ipv4 files. entries=%zu\n", ipv4_entries.count);
  fprintf(stderr, "Finished reading all category ipv6 files. entries=%zu\n", ipv6_entries.count);

  for(size_t i = 0; i < file_count; ++i) free(file_list[i]);
  free(file_list);

  if(domain_entries.count == 0 && ipv4_entries.count == 0 && ipv6_entries.count == 0) {
    dief("no valid entries parsed");
  }

  if(domain_entries.count > 0) {
    fprintf(stderr, "Starting global domain sort...\n");
    qsort(domain_entries.items, domain_entries.count, sizeof(domain_entries.items[0]), cmp_entry_hash_domain);
  }

  if(ipv4_entries.count > 0) {
    fprintf(stderr, "Starting IPv4 sort...\n");
    qsort(ipv4_entries.items, ipv4_entries.count, sizeof(ipv4_entries.items[0]), cmp_ipv4_entry);
    /* Rows are sorted for stable dumps; future optimization: binary search window + LPM. */
  }

  if(ipv6_entries.count > 0) {
    fprintf(stderr, "Starting IPv6 sort...\n");
    qsort(ipv6_entries.items, ipv6_entries.count, sizeof(ipv6_entries.items[0]), cmp_ipv6_entry);
    /* Same ordering contract as IPv4; future optimization: binary search window + LPM. */
  }

  strpool_t pool = {0};

  for(size_t i = 0; i < categories.count; ++i) {
    categories.items[i].name_off = strpool_add(&pool, categories.items[i].name, strlen(categories.items[i].name));
  }

  for(size_t i = 0; i < domain_entries.count; ++i) {
    domain_entries.items[i].domain_off =
      strpool_add(&pool, domain_entries.items[i].domain, domain_entries.items[i].domain_len);
  }

  size_t bucket_count = next_pow2(domain_entries.count / 2 + 1);
  if(bucket_count < 1024) bucket_count = 1024;

  ndb_bucket_disk_t *buckets = calloc(bucket_count, sizeof(*buckets));
  if(!buckets) die("calloc");

  uint32_t *bucket_tmp_counts = calloc(bucket_count, sizeof(uint32_t));
  if(!bucket_tmp_counts) die("calloc");

  for(size_t i = 0; i < domain_entries.count; ++i) {
    size_t b = (size_t)(domain_entries.items[i].hash & (bucket_count - 1));
    bucket_tmp_counts[b]++;
  }

  if(domain_entries.count > 0) {
    uint32_t max_fill = 0, min_fill = UINT32_MAX;
    size_t nonempty = 0;
    uint64_t sum_fill = 0;

    for(size_t b = 0; b < bucket_count; ++b) {
      uint32_t c = bucket_tmp_counts[b];

      sum_fill += c;
      if(c > 0) {
        nonempty++;
        if(c < min_fill)
          min_fill = c;
      }
      if(c > max_fill)
        max_fill = c;
    }

    fprintf(stderr,
        "Bucket stats: buckets=%zu nonempty=%zu max=%u min_nonempty=%u avg=%.2f\n",
        bucket_count, nonempty, max_fill, min_fill == UINT32_MAX ? 0u : min_fill,
        (double)sum_fill / (double)bucket_count);
  }

  uint32_t running = 0;
  for(size_t b = 0; b < bucket_count; ++b) {
    buckets[b].first = running;
    buckets[b].count = bucket_tmp_counts[b];
    running += bucket_tmp_counts[b];
  }

  entry_t *bucketed = xmalloc(domain_entries.count * sizeof(*bucketed));
  uint32_t *cursor = calloc(bucket_count, sizeof(uint32_t));
  if(!cursor) die("calloc");

  for(size_t b = 0; b < bucket_count; ++b) cursor[b] = buckets[b].first;

  for(size_t i = 0; i < domain_entries.count; ++i) {
    size_t b = (size_t)(domain_entries.items[i].hash & (bucket_count - 1));
    bucketed[cursor[b]++] = domain_entries.items[i];
  }

  free(domain_entries.items);
  domain_entries.items = bucketed;

  ndb_header_disk_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.magic, NDB_MAGIC, 4);
  hdr.format_version = NDB_FORMAT_VERSION;
  hdr.build_unix_time = (uint64_t)time(NULL);
  snprintf(hdr.base_version, sizeof(hdr.base_version), "%s", base_version);

  hdr.category_count = categories.count;

  hdr.domain_entry_count = domain_entries.count;
  hdr.domain_bucket_count = bucket_count;
  hdr.string_pool_size = pool.len;

  hdr.ipv4_entry_count = ipv4_entries.count;
  hdr.ipv6_entry_count = ipv6_entries.count;

  uint64_t off = sizeof(hdr);

  hdr.categories_off = off;
  off += (uint64_t)categories.count * sizeof(ndb_category_disk_t);

  hdr.domain_buckets_off = off;
  off += (uint64_t)bucket_count * sizeof(ndb_bucket_disk_t);

  hdr.domain_entries_off = off;
  off += (uint64_t)domain_entries.count * sizeof(ndb_entry_disk_t);

  hdr.string_pool_off = off;
  off += pool.len;

  hdr.ipv4_entries_off = off;
  off += (uint64_t)ipv4_entries.count * sizeof(ndb_ipv4_entry_disk_t);

  hdr.ipv6_entries_off = off;
  off += (uint64_t)ipv6_entries.count * sizeof(ndb_ipv6_entry_disk_t);

  hdr.file_size = off;

  char tmp_output[NDPI_CATBIN_TMP_OUT_BUFSZ];
  catbin_mk_tmp_output_path(tmp_output, sizeof(tmp_output), output_file, sizeof(output_file));

  int fd = open(tmp_output, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if(fd < 0) die("open output");

  FILE *out = fdopen(fd, "wb");
  if(!out) die("fdopen");

  if(fwrite(&hdr, 1, sizeof(hdr), out) != sizeof(hdr)) die("fwrite header");

  for(size_t i = 0; i < categories.count; ++i) {
    ndb_category_disk_t dc;
    dc.id = categories.items[i].id;
    dc.name_off = categories.items[i].name_off;
    if(fwrite(&dc, 1, sizeof(dc), out) != sizeof(dc)) die("fwrite category");
  }

  if(fwrite(buckets, sizeof(*buckets), bucket_count, out) != bucket_count) die("fwrite buckets");

  for(size_t i = 0; i < domain_entries.count; ++i) {
    ndb_entry_disk_t de;
    de.hash = domain_entries.items[i].hash;
    de.domain_off = domain_entries.items[i].domain_off;
    de.domain_len = domain_entries.items[i].domain_len;
    de.flags = domain_entries.items[i].flags;
    de.category_id = domain_entries.items[i].category_id;
    if(fwrite(&de, 1, sizeof(de), out) != sizeof(de)) die("fwrite entry");
  }

  if(pool.len > 0) {
    if(fwrite(pool.data, 1, pool.len, out) != pool.len) die("fwrite string pool");
  }

  for(size_t i = 0; i < ipv4_entries.count; ++i) {
    ndb_ipv4_entry_disk_t de;
    de.network_be = ipv4_entries.items[i].network_be;
    de.prefix_len = ipv4_entries.items[i].prefix_len;
    de.flags = ipv4_entries.items[i].flags;
    de.reserved0 = 0;
    de.category_id = ipv4_entries.items[i].category_id;

    if(fwrite(&de, 1, sizeof(de), out) != sizeof(de)) die("fwrite ipv4 entry");
  }

  for(size_t i = 0; i < ipv6_entries.count; ++i) {
    ndb_ipv6_entry_disk_t de;
    memcpy(de.addr, ipv6_entries.items[i].addr, 16);
    de.prefix_len = ipv6_entries.items[i].prefix_len;
    de.flags = ipv6_entries.items[i].flags;
    de.reserved0 = 0;
    de.category_id = ipv6_entries.items[i].category_id;

    if(fwrite(&de, 1, sizeof(de), out) != sizeof(de)) die("fwrite ipv6 entry");
  }

  if(fflush(out) != 0) die("fflush");
#if defined(_WIN32)
  if(_commit(fd) != 0) die("_commit");
#else
  if(fsync(fd) != 0) die("fsync");
#endif
  if(fclose(out) != 0) die("fclose");

  if(rename(tmp_output, output_file) != 0) {
    unlink(tmp_output);
    die("rename");
  }

  fprintf(stderr, "\nBuilt %s successfully\n", output_file);
  fprintf(stderr, "  categories   : %zu\n", categories.count);
  fprintf(stderr, "  domain entries : %zu\n", domain_entries.count);
  fprintf(stderr, "  ipv4 entries   : %zu\n", ipv4_entries.count);
  fprintf(stderr, "  ipv6 entries   : %zu\n", ipv6_entries.count);
  fprintf(stderr, "  domain buckets : %zu\n", bucket_count);
  fprintf(stderr, "  string pool    : %zu bytes\n", pool.len);
  fprintf(stderr, "  file size    : %" PRIu64 " bytes\n", hdr.file_size);
  fprintf(stderr, "  base version : %s\n", hdr.base_version);

  for(size_t i = 0; i < categories.count; ++i) free(categories.items[i].name);
  free(categories.items);

  free(domain_entries.items);
  free(ipv4_entries.items);
  free(ipv6_entries.items);

  free(pool.data);
  free(buckets);
  free(bucket_tmp_counts);
  free(cursor);

  catdedupe_free(&domain_dedupe);
  catdedupe_free(&ipv4_dedupe);
  catdedupe_free(&ipv6_dedupe);

  return 0;
}
