/*
 * ndpi_binary_bitmap.c
 *
 * Copyright (C) 2011-23 - ntop.org and contributors
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

#define NDPI_BINARY_BITMAP_REALLOC_SIZE  4096

// #define PRINT_DUPLICATED_HASHS

/* ********************************************************** */

ndpi_binary_bitmap* ndpi_binary_bitmap_alloc() {
  ndpi_binary_bitmap *rc = (ndpi_binary_bitmap*)ndpi_malloc(sizeof(ndpi_binary_bitmap));

  if(!rc) return(rc);

  rc->num_allocated_entries = NDPI_BINARY_BITMAP_REALLOC_SIZE, rc->num_used_entries = 0;
  if((rc->entries = (struct ndpi_binary_bitmap_entry*)ndpi_calloc(rc->num_allocated_entries,
								  sizeof(struct ndpi_binary_bitmap_entry))) == NULL) {
    ndpi_free(rc);
    return(NULL);
  }

  rc->is_compressed = false;

  return(rc);
}

/* ********************************************************** */

bool ndpi_binary_bitmap_set(ndpi_binary_bitmap *b, u_int64_t value, u_int8_t category) {
  if(b->num_used_entries >= b->num_allocated_entries) {
    struct ndpi_binary_bitmap_entry *rc;
    u_int32_t new_len = b->num_allocated_entries + NDPI_BINARY_BITMAP_REALLOC_SIZE;

    rc = (struct ndpi_binary_bitmap_entry*)ndpi_realloc(b->entries,
							sizeof(struct ndpi_binary_bitmap_entry)*b->num_allocated_entries,
							sizeof(struct ndpi_binary_bitmap_entry)*new_len);
    if(rc == NULL) return(false);

    b->entries = rc, b->num_allocated_entries = new_len;
  }

#ifdef PRINT_DUPLICATED_HASHS
  if(value == 0)
    printf("[add] ZERO hash !!!\n");
#endif
  
  b->entries[b->num_used_entries].value = value,
    b->entries[b->num_used_entries].category = category;
  b->num_used_entries++, b->is_compressed = false;

  return(true);
}

/* ********************************************************** */

static int ndpi_binary_bitmap_entry_compare(const void *_a, const void *_b) {
  struct ndpi_binary_bitmap_entry *a = (struct ndpi_binary_bitmap_entry*)_a;
  struct ndpi_binary_bitmap_entry *b = (struct ndpi_binary_bitmap_entry*)_b;

  // return(a->value > b->value) - (a->value < b->value);

  if (a->value < b->value) return -1;
  else if (a->value > b->value) return 1;
  else return 0;
}

/* ********************************************************** */

/* Sort and compact memory before searching */
bool ndpi_binary_bitmap_compress(ndpi_binary_bitmap *b) {
  u_int32_t i;

  if(b->num_used_entries > 0) {
    if(b->num_used_entries > 1)
      qsort(b->entries, b->num_used_entries,
	    sizeof(struct ndpi_binary_bitmap_entry),
	    ndpi_binary_bitmap_entry_compare);

    /* Now remove duplicates */
    u_int64_t old_value = b->entries[0].value, new_len = 1;
    
    for(i=1; i<b->num_used_entries; i++) {
      if(b->entries[i].value != old_value) {
	if(new_len != i)
	  memcpy(&b->entries[new_len], &b->entries[i], sizeof(struct ndpi_binary_bitmap_entry));
	
	old_value = b->entries[i].value;
	new_len++;
      } else {
#ifdef PRINT_DUPLICATED_HASHS
	printf("Skipping duplicate hash %lluu [id: %u/%u]\n",
	       b->entries[i].value, i, b->num_used_entries);
#endif
      }    
    
      // printf("Shrinking %u -> %u\n",  b->num_used_entries, new_len);
    }
    
    b->entries = (struct ndpi_binary_bitmap_entry*)
      ndpi_realloc(b->entries,
		   sizeof(struct ndpi_binary_bitmap_entry)*b->num_allocated_entries,
		   sizeof(struct ndpi_binary_bitmap_entry)*new_len);

    b->num_used_entries = b->num_allocated_entries = new_len;
  }

  b->is_compressed = true;

  return(true);
}

/* ********************************************************** */

bool ndpi_binary_bitmap_isset(ndpi_binary_bitmap *b, u_int64_t value, u_int8_t *out_category) {
  if(!b->is_compressed) ndpi_binary_bitmap_compress(b);

  if(b->num_used_entries > 0) {
    struct ndpi_binary_bitmap_entry *rc;
    struct ndpi_binary_bitmap_entry tofind;

    tofind.value = value;
    rc = (struct ndpi_binary_bitmap_entry*)bsearch(&tofind, b->entries,						  
						   b->num_used_entries,
						   sizeof(struct ndpi_binary_bitmap_entry),
						   ndpi_binary_bitmap_entry_compare);    
    if(rc != NULL)
      *out_category = rc->category;
        
    return(rc == NULL ? false : true);
  } else
    return(false);
}

/* ********************************************************** */

void ndpi_binary_bitmap_free(ndpi_binary_bitmap *b) {
  ndpi_free(b->entries);

  ndpi_free(b);
}

/* ********************************************************** */

u_int32_t ndpi_binary_bitmap_size(ndpi_binary_bitmap *b) {
  if(!b->is_compressed) ndpi_binary_bitmap_compress(b);
  
  return(sizeof(ndpi_binary_bitmap) + b->num_used_entries * sizeof(struct ndpi_binary_bitmap_entry));
}

/* ********************************************************** */

u_int32_t ndpi_binary_bitmap_cardinality(ndpi_binary_bitmap *b) {
  return(b->num_used_entries);
}
