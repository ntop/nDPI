#ifndef __LIBCACHE_H__
#define __LIBCACHE_H__

#include <stdint.h>


/* Codes representing the result of some functions */
typedef enum {
  CACHE_NO_ERROR = 0,
  CACHE_CONTAINS_FALSE = 0,
  CACHE_CONTAINS_TRUE,
  CACHE_INVALID_INPUT,
  CACHE_REMOVE_NOT_FOUND,
  CACHE_MALLOC_ERROR
} cache_result;

/* CACHE_T */
typedef struct cache_t cache_t;

/* CACHE_ENTRY */
typedef struct cache_entry cache_entry;

/* CACHE_ENTRY_MAP */
typedef struct cache_entry_map cache_entry_map;


/* STRUCT CACHE_T */
struct cache_t {
  uint32_t size;
  uint32_t max_size;
  cache_entry *head;
  cache_entry *tail;
  cache_entry_map **map;
};

/* STRUCT CACHE_ENTRY */
struct cache_entry_map {
  cache_entry *entry;
  cache_entry_map *next;
};

/* STRUCT CACHE_ENTRY_MAP */
struct cache_entry {
  void *item;
  uint32_t item_size;
  cache_entry *prev;
  cache_entry *next;
};


/**
 * Returns a new cache_t
 * 
 * @par    cache_max_size  = max number of item that the new cache_t can contain
 * @return a new cache_t, or NULL if an error occurred
 *
 */
cache_t *cache_new(uint32_t cache_max_size);


/**
 * Add an item in the specified cache_t
 * 
 * @par    cache      = the cache_t
 * @par    item       = pointer to the item to add
 * @par    item_size  = size of the item
 * @return a code representing the result of the function
 *
 */
cache_result cache_add(cache_t *cache, void *item, uint32_t item_size);


/**
 * Check if an item is in the specified cache_t
 * 
 * @par    cache      = the cache_t
 * @par    item       = pointer to the item to check
 * @par    item_size  = size of the item
 * @return a code representing the result of the function
 *
 */
cache_result cache_contains(cache_t *cache, void *item, uint32_t item_size);


/**
 * Remove an item in the specified cache_t
 * 
 * @par    cache      = the cache_t
 * @par    item       = pointer to the item to remove
 * @par    item_size  = size of the item
 * @return a code representing the result of the function
 *
 */
cache_result cache_remove(cache_t *cache, void *item, uint32_t item_size);

/**
 * Free the specified cache_t
 * 
 * @par alist  = the cache
 *
 */
void cache_free(cache_t *cache);


#endif
