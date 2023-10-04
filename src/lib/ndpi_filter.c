/*
 * ndpi_filter.c
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

#include "third_party/include/MurmurHash3.h"

/* ******************************************* */

ndpi_filter* ndpi_filter_alloc() {
  return((ndpi_filter*)ndpi_bitmap_alloc());
}

/* ******************************************* */

bool ndpi_filter_add(ndpi_filter *f, u_int32_t value) {
  if(!f)
    return(false);
  else {
    ndpi_bitmap *filter = (ndpi_bitmap*)f;

    ndpi_bitmap_set(filter, value);
    return(true);
  }
}

/* ******************************************* */

bool ndpi_filter_add_string(ndpi_filter *f, char *string) {
  return(ndpi_filter_add(f, ndpi_hash_string(string)));
}

/* ******************************************* */

bool ndpi_filter_contains(ndpi_filter *f, u_int32_t value) {
  if(!f)
    return(false);
  else {
    ndpi_bitmap *filter = (ndpi_bitmap*)f;
    
    return(ndpi_bitmap_isset(filter, value));
  }
}

/* ******************************************* */

bool ndpi_filter_contains_string(ndpi_filter *f, char *string) {
  return(ndpi_filter_contains(f, ndpi_hash_string(string)));
}

/* ******************************************* */

void ndpi_filter_free(ndpi_filter *f) {
  if(f != NULL) {
    ndpi_bitmap *filter = (ndpi_bitmap*)f;
    
    ndpi_bitmap_free(filter);
  }
}

  /* ******************************************* */

size_t ndpi_filter_size(ndpi_filter *f) {
  if(f != NULL) {
    char *buf;
    size_t s = ndpi_bitmap_serialize(f, &buf);
    
    if(buf) ndpi_free(buf);
    return(s);
  } else
    return(0);
}

  /* ******************************************* */

u_int32_t ndpi_filter_cardinality(ndpi_filter *f) {
  return(f ? ndpi_bitmap_cardinality(f) : 0);
}

