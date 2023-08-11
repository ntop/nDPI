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

#include "third_party/include/binaryfusefilter.h"

/* ******************************************* */

ndpi_filter* ndpi_filter_alloc(uint32_t elements_number) {
  binary_fuse8_t *filter = (binary_fuse8_t*)ndpi_malloc(sizeof(binary_fuse8_t));
  
  if(filter == NULL) return(NULL);
  
  if(!binary_fuse8_allocate(elements_number, filter)) {
    ndpi_free(filter);
    return(NULL);
  } else
    return((ndpi_filter*)filter);
}

/* ******************************************* */

bool ndpi_filter_add(ndpi_filter *f, uint64_t value) {
  if(!f)
    return(false);
  else {
    binary_fuse8_t *filter = (binary_fuse8_t*)f;
    
    return(binary_fuse8_populate(&value, 1, filter));
  }
}

/* ******************************************* */

bool ndpi_filter_contains(ndpi_filter *f, uint64_t value) {
  if(!f)
    return(false);
  else {
    binary_fuse8_t *filter = (binary_fuse8_t*)f;
    
    return(binary_fuse8_contain(value, filter));
  }
}

/* ******************************************* */

void ndpi_filter_free(ndpi_filter *f) {
  if(f != NULL) {
    binary_fuse8_t *filter = (binary_fuse8_t*)f;
    
    binary_fuse8_free(filter);
    ndpi_free(filter);
  }
}

