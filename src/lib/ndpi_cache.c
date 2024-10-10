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
/* ******************************************************************** */

struct ndpi_address_cache* ndpi_init_address_cache(u_int32_t max_num_entries) {
  struct ndpi_address_cache *ret = (struct ndpi_address_cache*)ndpi_malloc(sizeof(struct ndpi_address_cache));

  if(ret == NULL) return(ret);

  ret->num_cached_addresses = 0, ret->num_entries = 0,
    ret->max_num_entries = max_num_entries,
    ret->num_root_nodes = ndpi_min(NDPI_NUM_DEFAULT_ROOT_NODES, max_num_entries/16);
  ret->address_cache_root = (struct ndpi_address_cache_item**)ndpi_calloc(ret->num_root_nodes, sizeof(struct ndpi_address_cache_item*));

  if(ret->address_cache_root == NULL) {
    ndpi_free(ret);
    return(NULL);
  } else
    return(ret);
}

/* ***************************************************** */

static void ndpi_free_addr_item(struct ndpi_address_cache_item *addr) {
  ndpi_free(addr->hostname);
  ndpi_free(addr);
}

/* ***************************************************** */

void ndpi_term_address_cache(struct ndpi_address_cache *cache) {
  u_int i;

  for(i=0; i<cache->num_root_nodes; i++) {
    struct ndpi_address_cache_item *root = cache->address_cache_root[i];

    while(root != NULL) {
      struct ndpi_address_cache_item *next = root->next;

      ndpi_free_addr_item(root);
      root = next;
    }
  }

  ndpi_free(cache->address_cache_root);
  ndpi_free(cache);
}

/* ***************************************************** */

/* Return the number of purged entries */
u_int32_t ndpi_address_cache_flush_expired(struct ndpi_address_cache *cache,
					   u_int32_t epoch_now) {
  u_int32_t i, num_purged = 0;
  
  for(i=0; i<cache->num_root_nodes; i++) {
    struct ndpi_address_cache_item *root = cache->address_cache_root[i];
    struct ndpi_address_cache_item *prev = NULL;

    while(root != NULL) {
      struct ndpi_address_cache_item *next = root->next;

      if(root->expire_epoch > epoch_now) {
	/* Time to purge */

	if(prev == NULL) {
	  /* Head element */
	  cache->address_cache_root[i] = next;
	} else {
	  /* Middle element */
	  prev->next = next;
	}

	ndpi_free_addr_item(root), num_purged++;
      } else {
	prev = root;
      }

      root = next;
    } /* while */
  } /* for */

  cache->num_entries -= num_purged;

  return(num_purged);
}


/* ***************************************************** */

struct ndpi_address_cache_item* ndpi_address_cache_find(struct ndpi_address_cache *cache,
							ndpi_ip_addr_t ip_addr, u_int32_t epoch_now) {
  u_int32_t hash_id = ndpi_quick_hash((const unsigned char *)&ip_addr, sizeof(ip_addr)) % cache->num_root_nodes;
  struct ndpi_address_cache_item *root = cache->address_cache_root[hash_id], *prev = NULL;

  while(root != NULL) {
    if((epoch_now != 0) && (root->expire_epoch < epoch_now)) {
      /* Expired entry: let's remove it */
      struct ndpi_address_cache_item *next = root->next;

      if(prev == NULL)
	cache->address_cache_root[hash_id] = next;
      else
	prev->next = next;

      ndpi_free_addr_item(root);
      root = next, cache->num_entries--;

      continue; /* Skip this entry */
    }

    if(memcmp(&root->addr, &ip_addr, sizeof(ndpi_ip_addr_t)) == 0) {
      return(root);
    } else
      root = root->next;
  }

  return(NULL);
}

/* ***************************************************** */

bool ndpi_address_cache_insert(struct ndpi_address_cache *cache,
			       ndpi_ip_addr_t ip_addr, char *hostname,
			       u_int32_t epoch_now,
			       u_int32_t ttl) {
  u_int32_t hash_id = ndpi_quick_hash((const unsigned char *)&ip_addr, sizeof(ip_addr)) % cache->num_root_nodes;
  struct ndpi_address_cache_item *ret;
  u_int32_t epoch_valid_until;

  if(epoch_now == 0) epoch_now = (u_int32_t)time(NULL);
  ret = ndpi_address_cache_find(cache, ip_addr, epoch_now);
  epoch_valid_until = epoch_now + ttl;

  /* printf("**** %s [%u][ttl: %u]\n", hostname, epoch_now, ttl); */

  if(ret == NULL) {
    if(cache->num_entries == cache->max_num_entries) {
      ndpi_address_cache_flush_expired(cache, epoch_now);

      if(cache->num_entries == cache->max_num_entries)
	return(false); /* Still no room left */

      /* We have room to add the new element */
      /* Let's continue */
    }

    /* We have room to insert the new element */
    ret = (struct ndpi_address_cache_item*)ndpi_malloc(sizeof(struct ndpi_address_cache_item));
    if(ret == NULL)
      return(false); /* No memory */

    memcpy(&ret->addr, &ip_addr, sizeof(ip_addr)),
      ret->expire_epoch = epoch_valid_until,
      ret->next = cache->address_cache_root[hash_id];

    /* Create linked list */
    cache->address_cache_root[hash_id] = ret;

    if((ret->hostname = strdup(hostname)) == NULL) {
      ndpi_free(ret);
      return(false);
    }
  } else {
    /* Element found: update TTL of the existing element */
    ret->expire_epoch = ndpi_max(ret->expire_epoch, epoch_valid_until);

    if(strcmp(ret->hostname, hostname)) {
      /* Hostnames are different: we overwrite it */
      char *new_hostname = ndpi_strdup(hostname);

      if(new_hostname) {
	/* Allocation ok */
	ndpi_free(ret->hostname);
	ret->hostname = new_hostname;
      }
    }
  }

  cache->num_entries++;
  return(true);
}

/* ***************************************************** */

bool ndpi_address_cache_dump(struct ndpi_address_cache *cache,
			     char *path, u_int32_t epoch_now) {
  FILE *fd = fopen(path, "w");
  u_int i;
  
  if(!fd) return(false);

  for(i=0; i<cache->num_root_nodes; i++) {
    struct ndpi_address_cache_item *root = cache->address_cache_root[i];

    while(root != NULL) {
      char buf[33];
      u_char *a = (u_char*)&(root->addr);
      u_int j, idx;
      
      if(epoch_now && (root->expire_epoch < epoch_now))
	continue; /* Expired epoch */
      
      for(j=0, idx=0; j<sizeof(ndpi_ip_addr_t); j++, idx += 2)
	snprintf(&buf[idx], sizeof(buf)-idx, "%02X", a[j]);	 
      
      fprintf(fd, "%s\t%s\t%u\n", buf, root->hostname, root->expire_epoch);
      
      root = root->next;
    }
  }
  
  fclose(fd);
  return(true);
}

/* ***************************************************** */

/* Return the number of items restored */
u_int32_t ndpi_address_cache_restore(struct ndpi_address_cache *cache, char *path, u_int32_t epoch_now) {
  FILE *fd = fopen(path,  "r");
  char ip[33], hostname[256];
  u_int32_t epoch, num_added = 0;
  
  if(!fd) return(false);

  while(fscanf(fd, "%s\t%s\t%u\n", ip, hostname, &epoch) > 0) {    
    if(epoch >= epoch_now) { /* Entry not yet expired */
      u_int ttl = epoch-epoch_now;
      ndpi_ip_addr_t addr;
      char *a = (char*)&addr;
      u_int i, j;
      
      for(i=0, j=0; i<(sizeof(ndpi_ip_addr_t)*2); i += 2, j++) {
	char buf[3];
	
	buf[0] = ip[i], buf[1] = ip[i+1], buf[2] = '\0';
	a[j] = strtol(buf, NULL, 16);
      }
      
      if(ndpi_address_cache_insert(cache, addr, hostname, epoch_now, ttl))
	num_added++;
    }
  }
  
  fclose(fd);
  
  return(num_added);
}

/* ***************************************************** */
/* ***************************************************** */

bool ndpi_cache_address(struct ndpi_detection_module_struct *ndpi_struct,
			ndpi_ip_addr_t ip_addr, char *hostname,
			u_int32_t epoch_now, u_int32_t ttl) {
  if(ndpi_struct->cfg.address_cache_size == 0) return(false);

  if(ndpi_struct->address_cache == NULL)
    ndpi_struct->address_cache = ndpi_init_address_cache(ndpi_struct->cfg.address_cache_size);

  if(ndpi_struct->address_cache)
    return(ndpi_address_cache_insert(ndpi_struct->address_cache, ip_addr, hostname, epoch_now, ttl));
  else
    return(false);
}

/* ***************************************************** */

struct ndpi_address_cache_item* ndpi_cache_address_find(struct ndpi_detection_module_struct *ndpi_struct,
							ndpi_ip_addr_t ip_addr) {
  if(ndpi_struct->address_cache == NULL) return(NULL);

  return(ndpi_address_cache_find(ndpi_struct->address_cache, ip_addr, 0));
}

/* ***************************************************** */

bool ndpi_cache_address_dump(struct ndpi_detection_module_struct *ndpi_struct, char *path, u_int32_t epoch_now) {
  if(ndpi_struct->address_cache == NULL) return(false);

  return(ndpi_address_cache_dump(ndpi_struct->address_cache, path, epoch_now));
}

/* ***************************************************** */

u_int32_t ndpi_cache_address_restore(struct ndpi_detection_module_struct *ndpi_struct, char *path, u_int32_t epoch_now) {
  if(ndpi_struct->address_cache == NULL) {
    if(ndpi_struct->cfg.address_cache_size == 0)
      return(0);

    if((ndpi_struct->address_cache = ndpi_init_address_cache(ndpi_struct->cfg.address_cache_size)) == 0)
      return(0);
  }

  return(ndpi_address_cache_restore(ndpi_struct->address_cache, path, epoch_now));
}

/* ***************************************************** */

u_int32_t ndpi_cache_address_flush_expired(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t epoch_now) {
  if(ndpi_struct->address_cache == NULL)
    return(0);
  else
    return(ndpi_address_cache_flush_expired(ndpi_struct->address_cache, epoch_now));
}
