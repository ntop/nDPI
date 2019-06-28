/**
 * libcache.c
 *
Copyright (c) 2017 William Guglielmo <william@deselmo.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "libcache.h"
#include "ndpi_api.h"


// https://en.wikipedia.org/wiki/Jenkins_hash_function
#define HASH_FUNCTION jenkins_one_at_a_time_hash
uint32_t jenkins_one_at_a_time_hash(const uint8_t* key, size_t length) {
  size_t i = 0;
  uint32_t hash = 0;
  while (i != length) {
    hash += key[i++];
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;
  return hash;
}


struct cache {
  uint32_t size;
  uint32_t max_size;
  cache_entry head;
  cache_entry tail;
  cache_entry_map *map;
};

struct cache_entry_map {
  cache_entry entry;
  cache_entry_map next;
};

struct cache_entry {
  void *item;
  uint32_t item_size;
  cache_entry prev;
  cache_entry next;
};


void cache_touch_entry(cache_t cache, cache_entry entry) {
  if(entry->prev) {
    if(entry->next) {
      entry->prev->next = entry->next;
      entry->next->prev = entry->prev;
    } else {
      entry->prev->next = NULL;
      cache->tail = entry->prev;
    }
    entry->prev = NULL;
    entry->next = cache->head;
    cache->head->prev = entry;
    cache->head = entry;
  }
}


cache_entry cache_entry_new(void) {
  return (cache_entry) ndpi_calloc(sizeof(struct cache_entry), 1);
}
cache_entry_map cache_entry_map_new(void) {
  return (cache_entry_map) ndpi_calloc(sizeof(struct cache_entry_map), 1);
}

cache_t cache_new(uint32_t cache_max_size) {
  cache_t cache;
  if(!cache_max_size) {
    return NULL;
  }

  cache = (cache_t) ndpi_calloc(sizeof(struct cache), 1);
  if(!cache) {
    return NULL;
  }
  
  cache->size = 0;
  cache->max_size = cache_max_size;

  cache->map = (cache_entry_map *) ndpi_calloc(sizeof(cache_entry_map ), cache->max_size);

  if(!cache->map) {
    ndpi_free(cache);
    return NULL;
  }

  return cache;
}

cache_result cache_add(cache_t cache, void *item, uint32_t item_size) {
  uint32_t hash;
  cache_entry entry;
  cache_entry_map map_entry;

  if(!cache || !item || !item_size) {
    return CACHE_INVALID_INPUT;
  }

  hash = HASH_FUNCTION(item, item_size) % cache->max_size;

  if((cache->map)[hash]) {
    cache_entry_map hash_entry_map = cache->map[hash];

    while(hash_entry_map) {
      if(item_size == hash_entry_map->entry->item_size &&
	 !memcmp(hash_entry_map->entry->item, item, item_size)) {
        break;
      }
      
      hash_entry_map = hash_entry_map->next;
    }

    if(hash_entry_map) {
      cache_touch_entry(cache, hash_entry_map->entry);
      return CACHE_NO_ERROR;
    }
  }

  entry = cache_entry_new();
  if(!entry) {
    return CACHE_MALLOC_ERROR;
  }

  map_entry = cache_entry_map_new();
  if(!map_entry) {
    ndpi_free(entry);
    return CACHE_MALLOC_ERROR;
  }


  entry->item = ndpi_malloc(item_size);
  memcpy(entry->item, item, item_size);
  entry->item_size = item_size;

  entry->prev = NULL;
  entry->next = cache->head;
  if(cache->head) cache->head->prev = entry;
  cache->head = entry;

  map_entry->entry = entry;
  map_entry->next = cache->map[hash];
  cache->map[hash] = map_entry;

  if(cache->max_size > cache->size) {
    (cache->size)++;
    if(cache->size == 1) {
      cache->tail = entry;
    }
  } else {
    cache_entry tail = cache->tail;

    uint32_t hash = HASH_FUNCTION(tail->item, tail->item_size) % cache->max_size;
    if(cache->map[hash]) {
      cache_entry_map hash_entry_map_prev = NULL;
      cache_entry_map hash_entry_map = cache->map[hash];
      while(hash_entry_map) {
        if(tail->item_size == hash_entry_map->entry->item_size &&
            !memcmp(tail->item, hash_entry_map->entry->item, item_size)) {
          break;
        }
        
        hash_entry_map_prev = hash_entry_map;
        hash_entry_map = hash_entry_map->next;
      }

      if(hash_entry_map_prev) {
        if (hash_entry_map) {
          hash_entry_map_prev->next = hash_entry_map->next;
        } else {
          hash_entry_map_prev->next = NULL;
        }
      } else {
        cache->map[hash] = hash_entry_map->next;
      }

      tail->prev->next = NULL;
      cache->tail = tail->prev;
      
      ndpi_free(tail->item);
      ndpi_free(tail);
      ndpi_free(hash_entry_map);
    }
  }

  return CACHE_NO_ERROR;
}

cache_result cache_contains(cache_t cache, void *item, uint32_t item_size) {
  uint32_t hash;

  if(!cache || !item || !item_size) {
    return CACHE_INVALID_INPUT;
  }

  hash = HASH_FUNCTION(item, item_size) % cache->max_size;

  if(cache->map[hash]) {
    cache_entry_map hash_entry_map = cache->map[hash];
    while(hash_entry_map) {
      if(item_size == hash_entry_map->entry->item_size &&
          !memcmp(hash_entry_map->entry->item, item, item_size)) {
        cache_touch_entry(cache, hash_entry_map->entry);

        return CACHE_CONTAINS_TRUE;
      }
      
      hash_entry_map = hash_entry_map->next;
    }
  }

  return CACHE_CONTAINS_FALSE;
}

cache_result cache_remove(cache_t cache, void *item, uint32_t item_size) {
  uint32_t hash;

  if(!cache || !item || !item_size) {
    return CACHE_INVALID_INPUT;
  }

  hash = HASH_FUNCTION(item, item_size) % cache->max_size;

  if(cache->map[hash]) {
    cache_entry_map hash_entry_map_prev = NULL;
    cache_entry_map hash_entry_map = cache->map[hash];
    while(hash_entry_map) {
      if(item_size == hash_entry_map->entry->item_size &&
          !memcmp(hash_entry_map->entry->item, item, item_size)) {
        break;
      }
      
      hash_entry_map_prev = hash_entry_map;
      hash_entry_map = hash_entry_map->next;
    }

    if(hash_entry_map) {
      cache_entry entry;

      if(hash_entry_map_prev) {
        hash_entry_map_prev->next = hash_entry_map->next;
      } else {
        cache->map[hash] = hash_entry_map->next;
      }

      entry = hash_entry_map->entry;

      if(entry->prev) {
        entry->prev->next = entry->next;
      } else {
        cache->head = entry->next;
      }
      if(entry->next) {
        entry->next->prev = entry->prev;
      } else {
        cache->tail = entry->prev;
      }

      ndpi_free(entry->item);
      ndpi_free(entry);
      ndpi_free(hash_entry_map);

      (cache->size)--;
      return CACHE_NO_ERROR;
    }
  }

  return CACHE_REMOVE_NOT_FOUND;
}

void cache_free(cache_t cache) {
  int i;
  if(!cache) {
    return;
  }

  for(i = 0; i < cache->max_size; i++) {
    cache_entry_map prev = NULL;
    cache_entry_map curr = cache->map[i];
    while(curr) {
      prev = curr;
      curr = curr->next;
      ndpi_free(prev->entry->item);
      ndpi_free(prev->entry);
      ndpi_free(prev);
    }
  }

  ndpi_free(cache->map);
  ndpi_free(cache);

  return;
}
