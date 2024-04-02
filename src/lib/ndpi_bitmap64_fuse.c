/*
 * ndpi_bitmap64_fuse.c
 *
 * Copyright (C) 2011-24 - ntop.org and contributors
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
#include <math.h>
#include <sys/types.h>

#define NDPI_CURRENT_PROTO       NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "third_party/include/binaryfusefilter.h"

#define NDPI_BITMAP64_FUSE_REALLOC_SIZE  4096

// #define PRINT_DUPLICATED_HASHS

typedef struct {
  u_int32_t num_allocated_entries, num_used_entries;
  u_int64_t *entries;
  bool is_compressed;
  binary_fuse16_t bitmap;
} ndpi_bitmap64_fuse_t;

/* ********************************************************** */

ndpi_bitmap64_fuse* ndpi_bitmap64_fuse_alloc() {
  ndpi_bitmap64_fuse_t *rc = (ndpi_bitmap64_fuse_t*)ndpi_malloc(sizeof(ndpi_bitmap64_fuse_t));

  if(!rc) return(rc);

  rc->num_allocated_entries = NDPI_BITMAP64_FUSE_REALLOC_SIZE, rc->num_used_entries = 0;
  if((rc->entries = (u_int64_t*)ndpi_calloc(rc->num_allocated_entries, sizeof(u_int64_t))) == NULL) {
    ndpi_free(rc);
    return(NULL);
  }

  rc->is_compressed = false;

  return((ndpi_bitmap64_fuse*)rc);
}

/* ********************************************************** */

static int ndpi_bitmap64_fuse_entry_compare(const void *_a, const void *_b) {
  u_int64_t *a = (u_int64_t*)_a, *b = (u_int64_t*)_b;

  if(*a < *b) return -1;
  else if(*a > *b) return 1;
  else return 0;
}

/* ********************************************************** */

/* Sort and compact memory before searching */
bool ndpi_bitmap64_fuse_compress(ndpi_bitmap64_fuse *_b) {
  ndpi_bitmap64_fuse_t *b = (ndpi_bitmap64_fuse_t*)_b;
  u_int32_t i;

  if(!b)
    return(false);

  if(b->is_compressed)
    return(true);

  if(b->num_used_entries > 0) {
    if(b->num_used_entries > 1)
      qsort(b->entries, b->num_used_entries,
	    sizeof(u_int64_t),
	    ndpi_bitmap64_fuse_entry_compare);

    /* Now remove duplicates */
    u_int64_t old_value = b->entries[0], new_len = 1;

    for(i=1; i<b->num_used_entries; i++) {
      if(b->entries[i] != old_value) {
	if(new_len != i)
	  memcpy(&b->entries[new_len], &b->entries[i], sizeof(u_int64_t));

	old_value = b->entries[i];
	new_len++;
      } else {
#ifdef PRINT_DUPLICATED_HASHS
	printf("Skipping duplicate hash %lluu [id: %u/%u]\n",
	       b->entries[i].value, i, b->num_used_entries);
#endif
      }
    }

    b->num_used_entries = b->num_allocated_entries = new_len;
  }

  if(binary_fuse16_allocate(b->num_used_entries, &b->bitmap)) {
    if(binary_fuse16_populate(b->entries, b->num_used_entries, &b->bitmap)) {
      ndpi_free(b->entries), b->num_used_entries = b->num_allocated_entries = 0;
      b->entries = NULL;
    } else {
      binary_fuse16_free(&b->bitmap);
      return(false);
    }
  } else {
    return(false);
  }

  b->is_compressed = true;

  return(true);
}

/* ********************************************************** */

bool ndpi_bitmap64_fuse_set(ndpi_bitmap64_fuse *_b, u_int64_t value) {
  ndpi_bitmap64_fuse_t *b = (ndpi_bitmap64_fuse_t*)_b;

  if(!b)
    return(false);

  if(b->is_compressed) {
    /*
      We need to discard the filter and start over as this
      datastructure is immutable
    */

    binary_fuse16_free(&b->bitmap);
    /* No need to call b->is_compressed = false; as it will be set below */
  }

  if(b->num_used_entries >= b->num_allocated_entries) {
    u_int64_t *rc;
    u_int32_t new_len = b->num_allocated_entries + NDPI_BITMAP64_FUSE_REALLOC_SIZE;

    rc = (u_int64_t*)ndpi_realloc(b->entries,
				  sizeof(u_int64_t)*b->num_allocated_entries,
				  sizeof(u_int64_t)*new_len);
    if(rc == NULL) {
      b->is_compressed = false;
      return(false);
    }

    b->entries = rc, b->num_allocated_entries = new_len;
  }

  b->entries[b->num_used_entries] = value;
  b->num_used_entries++, b->is_compressed = false;

  return(true);
}

/* ********************************************************** */

bool ndpi_bitmap64_fuse_isset(ndpi_bitmap64_fuse *_b, u_int64_t value) {
  ndpi_bitmap64_fuse_t *b = (ndpi_bitmap64_fuse_t*)_b;

  if(!b)
    return(false);

  if(!b->is_compressed) {
    if(!ndpi_bitmap64_fuse_compress(b))
      return(false); /* Compresssion failed */
  }

  return(binary_fuse16_contain(value, &b->bitmap));
}

/* ********************************************************** */

void ndpi_bitmap64_fuse_free(ndpi_bitmap64_fuse *_b) {
  ndpi_bitmap64_fuse_t *b = (ndpi_bitmap64_fuse_t*)_b;

  if(!b)
    return;

  if(b->entries)        ndpi_free(b->entries);

  if(b->is_compressed)
    binary_fuse16_free(&b->bitmap);

  ndpi_free(b);
}

/* ********************************************************** */

u_int32_t ndpi_bitmap64_fuse_size(ndpi_bitmap64_fuse *_b) {
  ndpi_bitmap64_fuse_t *b = (ndpi_bitmap64_fuse_t*)_b;

  if(!b) return(0);

  if(!b->is_compressed) {
    if(!ndpi_bitmap64_fuse_compress(b))
      return(0); /* Compresssion failed */
  }

  return(sizeof(ndpi_bitmap64_fuse) + binary_fuse16_size_in_bytes(&b->bitmap));
}
