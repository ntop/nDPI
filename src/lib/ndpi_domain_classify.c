/*
 * ndpi_domain_classify.c
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

#include "ndpi_config.h"
#include "ndpi_api.h"

// #define DEBUG_ADD
// #define DEBUG_CONTAINS

/* ********************************************************** */

void ndpi_domain_classify_free(ndpi_domain_classify *search) {
  ndpi_binary_bitmap_free(search->bitmap);
  ndpi_free(search);
}

/* ********************************************************** */

ndpi_domain_classify* ndpi_domain_classify_alloc() {
  ndpi_domain_classify *search = (ndpi_domain_classify*)ndpi_malloc(sizeof(ndpi_domain_classify));

  if(!search) return(NULL);

  if((search->bitmap = ndpi_binary_bitmap_alloc()) == NULL)
    goto toobad;  

  return(search);

 toobad:
  ndpi_domain_classify_free(search);
  return(NULL);
}

/* ********************************************************** */

u_int32_t ndpi_domain_classify_size(ndpi_domain_classify *c) {
  return(sizeof(ndpi_domain_classify)+ndpi_binary_bitmap_size(c->bitmap));
}

/* ********************************************************** */

bool ndpi_domain_classify_add(ndpi_domain_classify *c,
			      u_int8_t class_id,
			      char *domain) {
  u_int64_t hash1, hash2, hash;
  char *dot = strrchr(domain, '.');
  
  if(!dot) return(false);
  if((!strcmp(dot, ".arpa")) || (!strcmp(dot, ".local")))
    return(false);

  /* Skip heading dots */
  while(domain[0] == '.') domain++;
  
  hash1 = ndpi_hash_string(domain), hash2 = ndpi_rev_hash_string(domain);
  hash = (hash1 << 32) | hash2;

#ifdef DEBUG_ADD
  printf("[add] %s @ %u [hash: %llu]\n", domain, class_id, hash);
#endif

  return(ndpi_binary_bitmap_set(c->bitmap, hash, class_id));
}

/* ********************************************************** */

u_int32_t ndpi_domain_classify_add_domains(ndpi_domain_classify *_c,
					   u_int8_t class_id,
					   char *file_path) {
  u_int32_t num_added = 0;
  char buf[256];
  FILE *fd;
  char *line;

  fd = fopen(file_path, "r");
  if(fd == NULL)
    return(false);

  while((line = fgets(buf, sizeof(buf), fd)) != NULL) {
    u_int len;

    if((line[0] == '#') ||  (line[0] == '\0'))
      continue;
    else {
      len = strlen(line) - 1;

      if(len == 0)
	continue;
      else
	line[len] = '\0';
    }
    
    if(ndpi_domain_classify_add(_c, class_id, line))
      num_added++;
  }

  fclose(fd);

  return(num_added);
}

/* ********************************************************** */

static bool is_valid_domain_char(u_char c) {
  if(((c >= 'A')&& (c <= 'Z'))
     || ((c >= 'a')&& (c <= 'z'))
     || ((c >= '0')&& (c <= '9'))
     || (c == '_')
     || (c == '-')
     || (c == '.'))
    return(true);
  else
    return(false);
}

/* ********************************************************** */

bool ndpi_domain_classify_contains(ndpi_domain_classify *c,
				   u_int8_t *class_id /* out */,
				   char *domain) {
  u_int32_t len;
  char *dot, *elem;

  if(!domain)                                             return(false);
  if((len = strlen(domain)) == 0)                         return(false);
  if((dot = strrchr(domain, '.')) == NULL)                return(false);
  if((!strcmp(dot, ".arpa")) || (!strcmp(dot, ".local"))) return(false);

  /* This is a number or a numeric IP or similar */
  if(isdigit(domain[len-1]) && isdigit(domain[0])) {
#ifdef DEBUG_CONTAINS
    printf("[contains] %s INVALID\n", domain);
#endif

    return(false);
  }
  
  if(!is_valid_domain_char(domain[0])) {
#ifdef DEBUG_CONTAINS
    printf("[contains] %s INVALID\n", domain);
#endif

    return(false);
  }

  elem = domain;

  while(true) {
    u_int64_t hash1, hash2, hash;

    hash1 = ndpi_hash_string(elem), hash2 = ndpi_rev_hash_string(elem);
    hash = (hash1 << 32) | hash2;
    
#ifdef DEBUG_CONTAINS
    printf("[contains] Searching %s [hash: %llu]\n", elem, hash);
#endif

    if(ndpi_binary_bitmap_isset(c->bitmap, hash, class_id)) {
#ifdef DEBUG_CONTAINS
      printf("[contains] %s = %d\n", domain, *class_id);
#endif
      return(true);
    }

    if((elem = strchr(elem, '.')) == NULL)
      break;
    else
      elem = &elem[1];
  }

#ifdef DEBUG_CONTAINS
  printf("[contains] %s NOT FOUND\n", domain);
#endif

  return(false);
}

