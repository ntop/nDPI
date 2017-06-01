/**
 * @file libcache.h
 * @author William Guglielmo <william@deselmo.com>
 * @brief File containing header of cache_t type.
 *
 */


#ifndef __DESELMO_LIBCACHE_H__
#define __DESELMO_LIBCACHE_H__

#include <stdint.h>

/**
 * @brief Codes representing the result of some functions
 *
 */
typedef enum cache_result {
  CACHE_NO_ERROR = 0,         /**< Returned by a function if no error occurs. */
  CACHE_CONTAINS_FALSE = 0,   /**< Returned by function cache_contains if item is not present. */
  CACHE_CONTAINS_TRUE,        /**< Returned by function cache_contains if item is present. */
  CACHE_INVALID_INPUT,        /**< Returned by a function if it is called with invalid input parameters. */
  CACHE_REMOVE_NOT_FOUND,     /**< Returned by function cache_remove if item is not present. */
  CACHE_MALLOC_ERROR          /**< Returned by a function if a malloc fail. */
} cache_result;


typedef struct cache_t *cache_t;


/**
 * @brief Returns a new cache_t
 * 
 * @par    cache_max_size  = max number of item that the new cache_t can contain
 * @return a new cache_t, or NULL if an error occurred
 *
 */
cache_t cache_new(uint32_t cache_max_size);


/**
 * @brief Add an item in the specified cache_t
 * 
 * @par    cache      = the cache_t
 * @par    item       = pointer to the item to add
 * @par    item_size  = size of the item
 * @return a code representing the result of the function
 *
 */
cache_result cache_add(cache_t cache, void *item, uint32_t item_size);


/**
 * @brief Check if an item is in the specified cache_t
 * 
 * @par    cache      = the cache_t
 * @par    item       = pointer to the item to check
 * @par    item_size  = size of the item
 * @return a code representing the result of the function
 *
 */
cache_result cache_contains(cache_t cache, void *item, uint32_t item_size);


/**
 * @brief Remove an item in the specified cache_t
 * 
 * @par    cache      = the cache_t
 * @par    item       = pointer to the item to remove
 * @par    item_size  = size of the item
 * @return a code representing the result of the function
 *
 */
cache_result cache_remove(cache_t cache, void *item, uint32_t item_size);

/**
 * @brief Free the specified cache_t
 * 
 * @par alist  = the cache
 *
 */
void cache_free(cache_t cache);


#endif
