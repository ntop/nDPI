#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include "ndpi_win32.h" /* For __sync_fetch_and_add */
#endif

/* ****************************************** */

static void *(*_ndpi_malloc)(size_t size);
static void (*_ndpi_free)(void *ptr);

static volatile long int ndpi_tot_allocated_memory;

/* ****************************************** */

void set_ndpi_malloc(void *(*__ndpi_malloc)(size_t size)) {
  _ndpi_malloc = __ndpi_malloc;
}

void set_ndpi_free(void (*__ndpi_free)(void *ptr)) {
  _ndpi_free = __ndpi_free;
}

/* ****************************************** */

u_int32_t ndpi_get_tot_allocated_memory() {
  return(__sync_fetch_and_add(&ndpi_tot_allocated_memory, 0));
}

/* ****************************************** */

void *ndpi_malloc(size_t size) {
  __sync_fetch_and_add(&ndpi_tot_allocated_memory, size);
  return(_ndpi_malloc ? _ndpi_malloc(size) : malloc(size));
}

/* ****************************************** */

void *ndpi_calloc(unsigned long count, size_t size) {
  size_t len = count * size;
  void *p = ndpi_malloc(len);

  if(p) {
    memset(p, 0, len);
    __sync_fetch_and_add(&ndpi_tot_allocated_memory, size);
  }

  return(p);
}

/* ****************************************** */

void ndpi_free(void *ptr) {
  if(_ndpi_free) {
    if(ptr)
      _ndpi_free(ptr);
  } else {
    if(ptr)
      free(ptr);
  }
}

/* ****************************************** */

void *ndpi_realloc(void *ptr, size_t old_size, size_t new_size) {
  void *ret = ndpi_malloc(new_size);

  if(!ret)
    return(ret);
  else {
    if(ptr != NULL) {
      memcpy(ret, ptr, (old_size < new_size ? old_size : new_size));
      ndpi_free(ptr);
    }
    return(ret);
  }
}

/* ****************************************** */

char *ndpi_strdup(const char *s) {
  if(s == NULL ){
    return NULL;
  }

  int len = strlen(s);
  char *m = ndpi_malloc(len + 1);

  if(m) {
    memcpy(m, s, len);
    m[len] = '\0';
  }

  return(m);
}
