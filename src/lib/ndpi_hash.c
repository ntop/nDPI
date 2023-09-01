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


#include "ndpi_config.h"
#include "ndpi_api.h"

/* ******************************************************************** */

/* Based on djb2 hash - http://www.cse.yorku.ca/~oz/hash.html */
u_int32_t ndpi_quick_hash(unsigned char *str, u_int str_len) {
  u_int32_t hash = 5381, i;

  for(i=0; i<str_len; i++)
    hash = ((hash << 5) + hash) + str[i]; /* hash * 33 + str[i] */

  return(hash);
}

/* ******************************************************************** */

/*
  https://en.wikipedia.org/wiki/Jenkins_hash_function

  See also http://burtleburtle.net/bob/hash/spooky.html
*/
u_int32_t ndpi_hash_string(char *str) {
  u_int32_t hash, i;

  for(hash = i = 0; str[i] != '\0'; ++i) {
    hash += str[i];
    hash += (hash << 10);
    hash ^= (hash >> 6);
  }

  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  return(hash);
}

/* ******************************************************************** */

/* Same as above but with strings with lenght */
u_int32_t ndpi_hash_string_len(char *str, u_int len) {
  u_int32_t hash, i;

  for(hash = i = 0; i< len; ++i) {
    hash += str[i];
    hash += (hash << 10);
    hash ^= (hash >> 6);
  }

  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  return(hash);
}


