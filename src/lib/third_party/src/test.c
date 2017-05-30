#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "libcache.h"


int main() {
  cache_t cache = cache_new(3);
  long e;

  e = 0;
  assert(cache_add(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  assert(cache_remove(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
  assert(cache_remove(cache, &e, sizeof(e)) == CACHE_REMOVE_NOT_FOUND);
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_FALSE);
  assert(cache_add(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  e = 1;
  assert(cache_add(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  e = 2;
  assert(cache_add(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  e = 3;
  assert(cache_add(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  e = 0;
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_FALSE);
  e = 1;
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  e = 2;
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  e = 3;
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  e = 1;
  assert(cache_add(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
  e = 4;
  assert(cache_add(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
  e = 0;
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_FALSE);
  e = 1;
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  e = 2;
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_FALSE);
  e = 3;
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  e = 4;
  assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  // e = 5;
  // assert(cache_add(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
  // e = 1;
  // assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_FALSE);

  for(e = 0; e < 1000; e++) {
    assert(cache_add(cache, &e, sizeof(e)) == CACHE_NO_ERROR);
    assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  }
  for(e = 0; e < 997; e++) {
    assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_FALSE);
  }  
  for(e = 997; e < 1000; e++) {
    assert(cache_contains(cache, &e, sizeof(e)) == CACHE_CONTAINS_TRUE);
  }

  cache_free(cache);

  puts("OK");
  return 0;
}
