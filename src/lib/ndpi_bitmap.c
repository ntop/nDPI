/*
 * ndpi_bitmap.c
 *
 * Copyright (C) 2011-24 - ntop.org and contributors
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

#ifdef USE_ROARING_V2 
#include "third_party/include/roaring_v2.h"
#else
#include "third_party/include/roaring.h"
#endif

/* ******************************************* */

ndpi_bitmap* ndpi_bitmap_alloc() {
#ifdef USE_ROARING_V2
  return((ndpi_bitmap*)roaring_bitmap_create());
#else
  return((ndpi_bitmap*)roaring64_bitmap_create());
#endif
}

/* ******************************************* */

void ndpi_bitmap_free(ndpi_bitmap* b) {
#ifdef USE_ROARING_V2
  roaring_bitmap_free((const roaring_bitmap_t *)b);
#else
  roaring64_bitmap_free((roaring64_bitmap_t *)b);
#endif
}

/* ******************************************* */

ndpi_bitmap* ndpi_bitmap_copy(ndpi_bitmap* b) {
#ifdef USE_ROARING_V2
  return(roaring_bitmap_copy(b));
#else
  return(roaring64_bitmap_copy(b));
#endif
}

/* ******************************************* */

u_int64_t ndpi_bitmap_cardinality(ndpi_bitmap* b) {
#ifdef USE_ROARING_V2
  return(roaring_bitmap_get_cardinality((const roaring_bitmap_t *)b));
#else
  return(roaring64_bitmap_get_cardinality((roaring64_bitmap_t *)b));
#endif
}

/* ******************************************* */

void ndpi_bitmap_set(ndpi_bitmap* b, u_int64_t value) {
#ifdef USE_ROARING_V2
  roaring_bitmap_add((roaring_bitmap_t *)b, value);
#else
  roaring64_bitmap_add((roaring64_bitmap_t *)b, value);
#endif
}

/* ******************************************* */

void ndpi_bitmap_unset(ndpi_bitmap* b, u_int64_t value) {
#ifdef USE_ROARING_V2
  roaring_bitmap_remove((roaring_bitmap_t *)b, value);
#else
  roaring64_bitmap_remove((roaring64_bitmap_t *)b, value);
#endif
}

/* ******************************************* */

bool ndpi_bitmap_isset(ndpi_bitmap* b, u_int64_t value) {
  bool ret;
  
#ifdef USE_ROARING_V2
  ret = roaring_bitmap_contains((const roaring_bitmap_t *)b, value);
#else
  ret = roaring64_bitmap_contains((const roaring64_bitmap_t *)b, value);
#endif

  return(ret);
}

/* ******************************************* */

size_t ndpi_bitmap_serialize(ndpi_bitmap* b, char **buf) {
  size_t s;

#ifdef USE_ROARING_V2
  const roaring_bitmap_t *r = (const roaring_bitmap_t *)b;
  
  s = roaring_bitmap_portable_size_in_bytes(r);
#else
  const roaring64_bitmap_t *r = (const roaring64_bitmap_t *)b;
  
  s = roaring64_bitmap_portable_size_in_bytes(r);
#endif
  
  *buf = (char*)ndpi_malloc(s);

  if((*buf) == NULL) return(0);

#ifdef USE_ROARING_V2
  return(roaring_bitmap_portable_serialize(r, *buf));
#else
  return(roaring64_bitmap_portable_serialize(r, *buf));
#endif
}

/* ******************************************* */

ndpi_bitmap* ndpi_bitmap_deserialize(char *buf, size_t buf_len) {
#ifdef USE_ROARING_V2
  return((ndpi_bitmap*)roaring_bitmap_portable_deserialize_safe(buf, buf_len));
#else
  return((ndpi_bitmap*)roaring64_bitmap_portable_deserialize_safe(buf, buf_len));
#endif
}

/* ******************************************* */

/* b = b & b_and */
void ndpi_bitmap_and(ndpi_bitmap* a, ndpi_bitmap* b_and) {
#ifdef USE_ROARING_V2
  roaring_bitmap_and_inplace((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_and);
#else
  roaring64_bitmap_and_inplace((roaring64_bitmap_t*)a, (roaring64_bitmap_t*)b_and);
#endif
}

/* ******************************************* */

/* b = b & b_and */
ndpi_bitmap* ndpi_bitmap_and_alloc(ndpi_bitmap* a, ndpi_bitmap* b_and) {
#ifdef USE_ROARING_V2
  return((ndpi_bitmap*)roaring_bitmap_and((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_and));
#else
  return((ndpi_bitmap*)roaring64_bitmap_and((roaring64_bitmap_t*)a, (roaring64_bitmap_t*)b_and));
#endif
}

/* ******************************************* */

/* b = b & !b_and */
void ndpi_bitmap_andnot(ndpi_bitmap* a, ndpi_bitmap* b_and) {
#ifdef USE_ROARING_V2
  roaring_bitmap_andnot_inplace((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_and);
#else
  roaring64_bitmap_andnot_inplace((roaring64_bitmap_t*)a, (roaring64_bitmap_t*)b_and);
#endif
}

/* ******************************************* */

/* b = b | b_or */
void ndpi_bitmap_or(ndpi_bitmap* a, ndpi_bitmap* b_or) {
#ifdef USE_ROARING_V2
  roaring_bitmap_or_inplace((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_or);
#else
  roaring64_bitmap_or_inplace((roaring64_bitmap_t*)a, (roaring64_bitmap_t*)b_or);
#endif
}

/* ******************************************* */

/* b = b | b_or */
ndpi_bitmap* ndpi_bitmap_or_alloc(ndpi_bitmap* a, ndpi_bitmap* b_or) {
#ifdef USE_ROARING_V2
  return((ndpi_bitmap*)roaring_bitmap_or((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_or));
#else
  return((ndpi_bitmap*)roaring64_bitmap_or((roaring64_bitmap_t*)a, (roaring64_bitmap_t*)b_or));
#endif
}

/* ******************************************* */

/* b = b ^ b_xor */
void ndpi_bitmap_xor(ndpi_bitmap* a, ndpi_bitmap* b_xor) {
#ifdef USE_ROARING_V2
  roaring_bitmap_xor_inplace((roaring_bitmap_t*)a, (roaring_bitmap_t*)b_xor);
#else
  roaring64_bitmap_xor_inplace((roaring64_bitmap_t*)a, (roaring64_bitmap_t*)b_xor);
#endif
}

/* ******************************************* */

void ndpi_bitmap_optimize(ndpi_bitmap* a) {
#ifdef USE_ROARING_V2
  roaring_bitmap_run_optimize(a);
#else
  roaring64_bitmap_run_optimize(a);
#endif
}

/* ******************************************* */

ndpi_bitmap_iterator* ndpi_bitmap_iterator_alloc(ndpi_bitmap* b) {
#ifdef USE_ROARING_V2 
  return((ndpi_bitmap_iterator*)roaring_create_iterator((roaring_bitmap_t*)b));
#else
  return((ndpi_bitmap_iterator*)roaring64_iterator_create((const roaring64_bitmap_t*)b));
#endif
}

/* ******************************************* */

void ndpi_bitmap_iterator_free(ndpi_bitmap* b) {
#ifdef USE_ROARING_V2
  roaring_free_uint32_iterator((roaring_uint32_iterator_t*)b);
#else
  roaring64_iterator_free((roaring64_iterator_t*)b);
#endif
}

/* ******************************************* */

bool ndpi_bitmap_is_empty(ndpi_bitmap* b) {
#ifdef USE_ROARING_V2
  return(roaring_bitmap_is_empty((roaring_bitmap_t*)b));
#else
  return(roaring64_bitmap_is_empty((roaring64_bitmap_t*)b));
#endif
}

/* ******************************************* */

/* Return the next value in the bitmap iterator
   
   true is returned when a value is present, false when we reached the end 
*/
bool ndpi_bitmap_iterator_next(ndpi_bitmap_iterator* i, u_int64_t *value) {
#ifdef USE_ROARING_V2
  uint32_t ret;
  uint32_t num = roaring_read_uint32_iterator((roaring_uint32_iterator_t*)i, &ret, 1);

  *value = (uint32_t)ret;
#else
  uint64_t num = roaring64_iterator_read((roaring64_iterator_t*)i, value, 1);
#endif
  
  return((num == 1) ? true /* found */ : false /* not found */);  
}
