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

#include "third_party/include/binaryfusefilter.h"

/* ******************************************* */

ndpi_bitmap64* ndpi_bitmap64_alloc_size(u_int32_t num_items) {
  binary_fuse16_t *b = (binary_fuse16_t*)ndpi_malloc(sizeof(binary_fuse16_t));
  
  if(b == NULL) return(NULL);

  if(binary_fuse16_allocate(num_items, b))
    return((ndpi_bitmap64*)b);
  else {
    ndpi_free(b);
    return(NULL);
  }
}

/* ******************************************* */

void ndpi_bitmap64_free(ndpi_bitmap64* b) {
  binary_fuse16_free((binary_fuse16_t*)b);
  ndpi_free(b);
}

/* ******************************************* */

void ndpi_bitmap64_set(ndpi_bitmap64* b, u_int64_t value) {
  binary_fuse16_populate(&value, 1, (binary_fuse16_t*)b);
}

/* ******************************************* */

bool ndpi_bitmap64_isset(ndpi_bitmap64* b, u_int64_t value) {
  return(binary_fuse16_contain(value, (binary_fuse16_t*)b));
}

/* ******************************************* */

u_int32_t ndpi_bitmap64_size(ndpi_bitmap64 *b) {
  return(binary_fuse16_size_in_bytes((binary_fuse16_t*)b));
}


