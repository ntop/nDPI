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

#include "third_party/include/MurmurHash3.h"

/* ******************************************************************** */

/* Based on djb2 hash - http://www.cse.yorku.ca/~oz/hash.html */
u_int32_t ndpi_murmur_hash(const char *str, u_int str_len) {
  return(MurmurHash((void*)str, str_len, 0x87654321));
}

/* ******************************************************************** */

/* Based on djb2 hash - http://www.cse.yorku.ca/~oz/hash.html */
u_int32_t ndpi_quick_hash(const unsigned char *str, u_int str_len) {
  u_int32_t hash = 5381, i;

  for(i=0; i<str_len; i++)
    hash = ((hash << 5) + hash) + str[i]; /* hash * 33 + str[i] */

  return(hash);
}

/* ******************************************************************** */

/* Based on Daniel Lemire code */
u_int64_t ndpi_quick_hash64(const char *str, u_int str_len) {
  u_int64_t h = 0;
  u_int i;
  
  for(i=0; i<str_len; i++)
    h = (h * 177) + str[i];

  h ^= strlen(str);
  
  return h;
}

/* ******************************************************************** */

/*
  https://en.wikipedia.org/wiki/Jenkins_hash_function

  See also http://burtleburtle.net/bob/hash/spooky.html
*/
u_int32_t ndpi_hash_string(const char *str) {
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

u_int32_t ndpi_rev_hash_string(const char *str) {
  u_int32_t hash, i;
  int len = strlen(str);

  if(len == 0) return(0);
  len--;
  
  for(hash = i = 0; len >= 0; len--) {
    hash += str[len];
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
u_int32_t ndpi_hash_string_len(const char *str, u_int len) {
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


