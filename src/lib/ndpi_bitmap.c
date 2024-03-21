/*
 * ndpi_bitmap.c
 *
 * Copyright (C) 2011-23 - ntop.org and contributors
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
#include <math.h>
#include <sys/types.h>


#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"
#include "ndpi_encryption.h"

#include "third_party/include/roaring.h"

/* ******************************************* */

ndpi_bitmap* ndpi_bitmap_alloc() {
  return((ndpi_bitmap*)roaring_bitmap_create());
}

/* ******************************************* */

ndpi_bitmap* ndpi_bitmap_alloc_size(u_int32_t size) {
  return((ndpi_bitmap*)roaring_bitmap_create_with_capacity(size));
}

/* ******************************************* */

void ndpi_bitmap_free(ndpi_bitmap* b) {
  roaring_bitmap_free((const roaring_bitmap_t *)b);
}

/* ******************************************* */

ndpi_bitmap* ndpi_bitmap_copy(ndpi_bitmap* b) {
  return(roaring_bitmap_copy(b));
}

/* ******************************************* */

u_int64_t ndpi_bitmap_cardinality(ndpi_bitmap* b) {
  return(roaring_bitmap_get_cardinality((const roaring_bitmap_t *)b));
}

/* ******************************************* */

void ndpi_bitmap_set(ndpi_bitmap* b, u_int32_t value) {
  roaring_bitmap_add((roaring_bitmap_t *)b, value);
}

/* ******************************************* */

void ndpi_bitmap_unset(ndpi_bitmap* b, u_int32_t value) {
  roaring_bitmap_remove((roaring_bitmap_t *)b, value);
}

/* ******************************************* */

bool ndpi_bitmap_isset(ndpi_bitmap* b, u_int32_t value) {
  return(roaring_bitmap_contains((const roaring_bitmap_t *)b, value));
}

/* ******************************************* */

void ndpi_bitmap_clear(ndpi_bitmap* b) {
  roaring_bitmap_clear((roaring_bitmap_t *)b);
}

/* ******************************************* */

size_t ndpi_bitmap_serialize(ndpi_bitmap* b, char **buf) {
  const roaring_bitmap_t *r = (const roaring_bitmap_t *)b;
  size_t s = roaring_bitmap_size_in_bytes(r);

  *buf = (char*)ndpi_malloc(s);

  if((*buf) == NULL) return(0);

  return(roaring_bitmap_serialize(r, *buf));
}

/* ******************************************* */

ndpi_bitmap* ndpi_bitmap_deserialize(char *buf) {
  return((ndpi_bitmap*)roaring_bitmap_deserialize(buf));
}

/* ******************************************* */

/* b = b & b_and */
void ndpi_bitmap_and(ndpi_bitmap* a, ndpi_bitmap* b_and) {
  roaring_bitmap_and_inplace((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_and);
}

/* ******************************************* */

/* b = b & b_and */
ndpi_bitmap* ndpi_bitmap_and_alloc(ndpi_bitmap* a, ndpi_bitmap* b_and) {
  return((ndpi_bitmap*)roaring_bitmap_and((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_and));
}

/* ******************************************* */

/* b = b & !b_and */
void ndpi_bitmap_andnot(ndpi_bitmap* a, ndpi_bitmap* b_and) {
  roaring_bitmap_andnot_inplace((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_and);
}

/* ******************************************* */

/* b = b | b_or */
void ndpi_bitmap_or(ndpi_bitmap* a, ndpi_bitmap* b_or) {
  roaring_bitmap_or_inplace((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_or);
}

/* ******************************************* */

/* b = b | b_or */
ndpi_bitmap* ndpi_bitmap_or_alloc(ndpi_bitmap* a, ndpi_bitmap* b_or) {
  return((ndpi_bitmap*)roaring_bitmap_or((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_or));
}

/* ******************************************* */

/* b = b ^ b_xor */
void ndpi_bitmap_xor(ndpi_bitmap* a, ndpi_bitmap* b_xor) {
  roaring_bitmap_xor_inplace((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_xor);
}

/* ******************************************* */

void ndpi_bitmap_optimize(ndpi_bitmap* a) {
  roaring_bitmap_run_optimize(a);
}

/* ******************************************* */

ndpi_bitmap_iterator* ndpi_bitmap_iterator_alloc(ndpi_bitmap* b) {
#ifdef USE_ROARING_V2 
  return(roaring_create_iterator((roaring_bitmap_t*)b));
#else
  return(roaring_iterator_create((roaring_bitmap_t*)b));
#endif
}

/* ******************************************* */

void ndpi_bitmap_iterator_free(ndpi_bitmap* b) {
#ifdef USE_ROARING_V2
  roaring_free_uint32_iterator((roaring_uint32_iterator_t*)b);
#else
  roaring_uint32_iterator_free((roaring_uint32_iterator_t*)b);
#endif
}

/* ******************************************* */

bool ndpi_bitmap_is_empty(ndpi_bitmap* b) {
  return(roaring_bitmap_is_empty((roaring_bitmap_t*)b));
}

/* ******************************************* */

/* Return the next value in the bitmap iterator
   
   true is returned when a value is present, false when we reached the end 
*/
bool ndpi_bitmap_iterator_next(ndpi_bitmap_iterator* i, uint32_t *value) {
#ifdef USE_ROARING_V2 
  uint32_t num = roaring_read_uint32_iterator((roaring_uint32_iterator_t*)i, value, 1);
#else
  uint32_t num = roaring_uint32_iterator_read((roaring_uint32_iterator_t*)i, value, 1);
#endif
  
  return((num == 1) ? true /* found */ : false /* not found */);  
}
