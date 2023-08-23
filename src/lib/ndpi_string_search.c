/*
 * ndpi_string_search.c
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

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"
#include "ndpi_encryption.h"

/* ******************************************* */

ndpi_string_search* ndpi_string_search_alloc() {
  ndpi_string_search *s = (ndpi_string_search*)ndpi_malloc(sizeof(ndpi_string_search));
  int i;

  if(!s) return(NULL);

  for(i=0; i<2; i++)
    s->filter[i] = ndpi_filter_alloc();

  return(s);
}

/* ******************************************* */

void ndpi_string_search_free(ndpi_string_search *_s) {
  if(_s != NULL) {
    ndpi_string_search *s = (ndpi_string_search*)_s;
    int i;

    for(i=0; i<2; i++)
      ndpi_string_search_free(s->filter[i]);

    ndpi_free(s);
  }
}

/* ******************************************* */

u_int32_t ndpi_string_search_size(ndpi_string_search *s) {
  if(s != NULL) {
    int i;
    u_int32_t total_len = 0;

    for(i=0; i<2; i++)
      total_len += ndpi_filter_size(s->filter[i]);

    return(total_len);
  } else
    return(0);
}

/* ******************************************* */

u_int32_t ndpi_string_search_cardinality(ndpi_string_search *s) {
  return(s ? ndpi_filter_cardinality(s) : 0);
}

/* ********************************************************** */

static u_int32_t hashval(char *domain, bool revert_string) {
  u_int32_t ret = 0, shift_bit = 1;
  int i;

  if(revert_string) {
    i = strlen(domain) - 1;

    while(i >= 0) {
      u_int32_t v = ((u_int32_t)domain[i]) << shift_bit;

      i--, ret += v;
      if(++shift_bit == 25) shift_bit = 0;
    }
  } else {
    i = 0;

    while(domain[i] != '\0') {
      u_int32_t v = ((u_int32_t)domain[i]) << shift_bit;

      i++, ret += v;
      if(++shift_bit == 25) shift_bit = 0;
    }
  }

  return(ret + i);
}

/* ******************************************* */

bool ndpi_string_search_add(ndpi_string_search *s, char *string) {
  if(s != NULL) {
    u_int32_t h0 = hashval(string, false), h1 = hashval(string, true);

    ndpi_filter_add(s->filter[0], h0), ndpi_filter_add(s->filter[1], h1);
    return(true);
  } else
    return(false);
}

/* ******************************************* */

bool ndpi_string_search_contains(ndpi_string_search *s, char *string) {
  if(s != NULL) {
    u_int32_t h0 = hashval(string, false), h1;

    if(!ndpi_filter_contains(s->filter[0], h0)) return(false);

    h1 = hashval(string, true);
    if(!ndpi_filter_contains(s->filter[1], h1)) return(false);

    return(true);
  } else
    return(false);
}
