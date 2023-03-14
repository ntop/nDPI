/*
 * ndpi_memory.c
 *
 * Copyright (C) 2011-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"

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
