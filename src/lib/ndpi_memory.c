/*
 * ndpi_memory.c
 *
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"

/* ****************************************** */

static void *(*_ndpi_malloc)(size_t size);
static void (*_ndpi_free)(void *ptr);
static void *(*_ndpi_calloc)(size_t nmemb, size_t size);
static void *(*_ndpi_realloc)(void *ptr, size_t size);
static void *(*_ndpi_aligned_malloc)(size_t alignment, size_t size);
static void (*_ndpi_aligned_free)(void *ptr);
static void *(*_ndpi_flow_malloc)(size_t size);
static void (*_ndpi_flow_free)(void *ptr);

static volatile long int ndpi_tot_allocated_memory;

/* ****************************************** */

void ndpi_set_memory_alloction_functions(void *(*__ndpi_malloc)(size_t size),
                                         void (*__ndpi_free)(void *ptr),
                                         void *(*__ndpi_calloc)(size_t nmemb, size_t size),
                                         void *(*__ndpi_realloc)(void *ptr, size_t size),
                                         void *(*__ndpi_aligned_malloc)(size_t alignment, size_t size),
                                         void (*__ndpi_aligned_free)(void *ptr),
                                         void *(*__ndpi_flow_malloc)(size_t size),
                                         void (*__ndpi_flow_free)(void *ptr)) {

  /* We can't log here */

  if(__ndpi_malloc && __ndpi_free &&
     __ndpi_calloc && __ndpi_realloc) {
    _ndpi_malloc = __ndpi_malloc;
    _ndpi_free = __ndpi_free;
    _ndpi_calloc = __ndpi_calloc;
    _ndpi_realloc = __ndpi_realloc;
  }
  if(__ndpi_aligned_malloc && __ndpi_aligned_free) {
    _ndpi_aligned_malloc = __ndpi_aligned_malloc;
    _ndpi_aligned_free = __ndpi_aligned_free;
  }
  if(__ndpi_flow_malloc && __ndpi_flow_free) {
    _ndpi_flow_malloc = __ndpi_flow_malloc;
    _ndpi_flow_free = __ndpi_flow_free;
  }
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

void *ndpi_calloc(size_t nmemb, size_t size) {
  __sync_fetch_and_add(&ndpi_tot_allocated_memory, nmemb * size);
  return(_ndpi_calloc ? _ndpi_calloc(nmemb, size) : calloc(nmemb, size));
}

/* ****************************************** */

void ndpi_free(void *ptr) {
  _ndpi_free ? _ndpi_free(ptr) : free(ptr);
}

/* ****************************************** */

void *ndpi_realloc(void *ptr, size_t size) {
  __sync_fetch_and_add(&ndpi_tot_allocated_memory, size);
  return(_ndpi_realloc ? _ndpi_realloc(ptr, size) : realloc(ptr, size));
}

/* ****************************************** */

void *ndpi_aligned_malloc(size_t alignment, size_t size) {
  __sync_fetch_and_add(&ndpi_tot_allocated_memory, size);
  if(_ndpi_aligned_malloc) {
    return _ndpi_aligned_malloc(alignment, size);
  }
  void* p;
#ifdef _MSC_VER
  p = _aligned_malloc(size, alignment);
#elif defined(__MINGW32__) || defined(__MINGW64__)
  p = __mingw_aligned_malloc(size, alignment);
#else
  if (posix_memalign(&p, alignment, size) != 0)
    return NULL;
#endif
  return p;
}

/* ****************************************** */

void ndpi_aligned_free(void *ptr) {
  if(_ndpi_aligned_free) {
    _ndpi_aligned_free(ptr);
    return;
  }
#ifdef _MSC_VER
  _aligned_free(ptr);
#elif defined(__MINGW32__) || defined(__MINGW64__)
  __mingw_aligned_free(ptr);
#else
  free(ptr); /* No ndpi_free!! */
#endif
}

/* ****************************************** */

void *ndpi_flow_malloc(size_t size) {
  return(_ndpi_flow_malloc ? _ndpi_flow_malloc(size) : ndpi_malloc(size));
}

/* ****************************************** */

void ndpi_flow_free(void *ptr) {
  if(ptr) {
    ndpi_free_flow_data((struct ndpi_flow_struct *)ptr);
    _ndpi_flow_free ? _ndpi_flow_free(ptr) : ndpi_free(ptr);
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
