#include <pthread.h>
#include <stdint.h>
#include <time.h>

#ifndef __lruc_header__
#define __lruc_header__

// ------------------------------------------
// errors
// ------------------------------------------
typedef enum {
  LRUC_NO_ERROR = 0,
  LRUC_MISSING_CACHE,
  LRUC_MISSING_KEY,
  LRUC_MISSING_VALUE,
  LRUC_PTHREAD_ERROR,
  LRUC_VALUE_TOO_LARGE
} lruc_error;


// ------------------------------------------
// types
// ------------------------------------------
typedef struct {
  void      *value;
  void      *key;
  uint32_t  value_length;
  uint32_t  key_length;
  uint64_t  access_count;
  void      *next;
} lruc_item;

typedef struct {
  lruc_item **items;
  uint64_t  access_count;
  uint64_t  free_memory;
  uint64_t  total_memory;
  uint64_t  average_item_length;
  uint32_t  hash_table_size;
  time_t    seed;
  lruc_item *free_items;
  pthread_mutex_t *mutex;
} lruc;


// ------------------------------------------
// api
// ------------------------------------------
lruc *lruc_new(uint64_t cache_size, uint32_t average_length);
lruc_error lruc_free(lruc *cache);
lruc_error lruc_set(lruc *cache, void *key, uint32_t key_length, void *value, uint32_t value_length);
lruc_error lruc_get(lruc *cache, void *key, uint32_t key_length, void **value);
lruc_error lruc_delete(lruc *cache, void *key, uint32_t key_length);

#endif
