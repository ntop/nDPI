/*
 * ndpi_main.c
 *
 * Copyright (C) 2011-24 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#ifdef __APPLE__
#include <netinet/ip.h>
#endif

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_private.h"

#include "libcache.h"

/* ******************************************************************** */
/* ******************************************************************** */

/* LRU cache */
struct ndpi_lru_cache *ndpi_lru_cache_init(u_int32_t num_entries, u_int32_t ttl, int shared) {
  struct ndpi_lru_cache *c = (struct ndpi_lru_cache *) ndpi_calloc(1, sizeof(struct ndpi_lru_cache));

  if(!c)
    return(NULL);

  c->ttl = ttl & 0x7FFFFFFF;
  c->shared = !!shared;

#ifdef USE_GLOBAL_CONTEXT
  if(c->shared) {
    if(pthread_mutex_init(&c->mutex, NULL) != 0) {
      ndpi_free(c);
      return(NULL);
    }
  }
#endif

  c->entries = (struct ndpi_lru_cache_entry *) ndpi_calloc(num_entries, sizeof(struct ndpi_lru_cache_entry));

  if(!c->entries) {
    ndpi_free(c);
    return(NULL);
  } else
    c->num_entries = num_entries;

  return(c);
}

/* ******************************************************************** */

void ndpi_lru_free_cache(struct ndpi_lru_cache *c) {
  ndpi_free(c->entries);
  ndpi_free(c);
}

/* ******************************************************************** */

static void __lru_cache_lock(struct ndpi_lru_cache *c)
{
#ifdef USE_GLOBAL_CONTEXT
  if(c->shared) {
    pthread_mutex_lock(&c->mutex);
  }
#else
  (void)c;
#endif
}

/* ******************************************************************** */

static void __lru_cache_unlock(struct ndpi_lru_cache *c)
{
#ifdef USE_GLOBAL_CONTEXT
  if(c->shared) {
    pthread_mutex_unlock(&c->mutex);
  }
#else
  (void)c;
#endif
}

/* ******************************************************************** */

u_int8_t ndpi_lru_find_cache(struct ndpi_lru_cache *c, u_int64_t key,
			     u_int16_t *value, u_int8_t clean_key_when_found, u_int32_t now_sec) {
  u_int32_t slot = ndpi_quick_hash((unsigned char *)&key, sizeof(key)) % c->num_entries;
  u_int8_t ret;

  __lru_cache_lock(c);

  c->stats.n_search++;
  if(c->entries[slot].is_full && c->entries[slot].key == key &&
     now_sec >= c->entries[slot].timestamp &&
     (c->ttl == 0 || now_sec - c->entries[slot].timestamp <= c->ttl)) {
    *value = c->entries[slot].value;
    
    if(clean_key_when_found)
      c->entries[slot].is_full = 0;
    
    c->stats.n_found++;
    ret = 1;
  } else
    ret = 0;

  __lru_cache_unlock(c);

  return ret;
}

/* ******************************************************************** */

void ndpi_lru_add_to_cache(struct ndpi_lru_cache *c, u_int64_t key, u_int16_t value, u_int32_t now_sec) {
  u_int32_t slot = ndpi_quick_hash((unsigned char *)&key, sizeof(key)) % c->num_entries;

  __lru_cache_lock(c);

  c->stats.n_insert++;
  c->entries[slot].is_full = 1, c->entries[slot].key = key,
    c->entries[slot].value = value, c->entries[slot].timestamp = now_sec;

  __lru_cache_unlock(c);
}

/* ******************************************************************** */

void ndpi_lru_get_stats(struct ndpi_lru_cache *c, struct ndpi_lru_cache_stats *stats) {
  if(c) {
    stats->n_insert = c->stats.n_insert;
    stats->n_search = c->stats.n_search;
    stats->n_found = c->stats.n_found;
  } else {
    stats->n_insert = 0;
    stats->n_search = 0;
    stats->n_found = 0;
  }
}

/* ******************************************************************** */

int ndpi_get_lru_cache_stats(struct ndpi_global_context *g_ctx,
			     struct ndpi_detection_module_struct *ndpi_struct,
			     lru_cache_type cache_type,
			     struct ndpi_lru_cache_stats *stats)
{
  int scope, is_local = 1;
  char param[64], buf[8], *rc;

  if(!stats || (!ndpi_struct && !g_ctx))
    return -1;
  if(!ndpi_struct) {
    is_local = 0;
  } else {
    snprintf(param, sizeof(param), "lru.%s.scope", ndpi_lru_cache_idx_to_name(cache_type));
    rc = ndpi_get_config(ndpi_struct, NULL, param, buf, sizeof(buf));

    if(rc == NULL)
      return -1;

    scope = atoi(buf);

    if(scope == NDPI_LRUCACHE_SCOPE_GLOBAL) {
      is_local = 0;
      if(!g_ctx)
        return -1;
    }
  }

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    ndpi_lru_get_stats(is_local ? ndpi_struct->ookla_cache : g_ctx->ookla_global_cache, stats);
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    ndpi_lru_get_stats(is_local ? ndpi_struct->bittorrent_cache : g_ctx->bittorrent_global_cache, stats);
    return 0;
  case NDPI_LRUCACHE_STUN:
    ndpi_lru_get_stats(is_local ? ndpi_struct->stun_cache : g_ctx->stun_global_cache, stats);
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    ndpi_lru_get_stats(is_local ? ndpi_struct->tls_cert_cache : g_ctx->tls_cert_global_cache, stats);
    return 0;
  case NDPI_LRUCACHE_MINING:
    ndpi_lru_get_stats(is_local ? ndpi_struct->mining_cache : g_ctx->mining_global_cache, stats);
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    ndpi_lru_get_stats(is_local ? ndpi_struct->msteams_cache : g_ctx->msteams_global_cache, stats);
    return 0;
  case NDPI_LRUCACHE_FPC_DNS:
    ndpi_lru_get_stats(is_local ? ndpi_struct->fpc_dns_cache : g_ctx->fpc_dns_global_cache, stats);
    return 0;
  default:
    return -1;
  }
}

/* ******************************************************************** */
