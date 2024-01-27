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

#if 0
#define DEBUG_ADD
#define DEBUG_CONTAINS
#endif

/* ********************************************************** */

ndpi_domain_classify* ndpi_domain_classify_alloc() {
  int i;
  ndpi_domain_classify *cat = (ndpi_domain_classify*)ndpi_malloc(sizeof(ndpi_domain_classify));

  if(!cat)
    return NULL;

  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++)
    cat->classes[i].class_id = 0, cat->classes[i].domains = NULL;

  return((ndpi_domain_classify*)cat);
}

/* ********************************************************** */

void ndpi_domain_classify_free(ndpi_domain_classify *s) {
  u_int32_t i;

  if(!s)
    return;

  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->classes[i].domains != NULL) {
      ndpi_bitmap64_free(s->classes[i].domains);
    } else
      break;
  }

  ndpi_free(s);
}

/* ********************************************************** */

u_int32_t ndpi_domain_classify_size(ndpi_domain_classify *s) {
  u_int32_t i, tot_len = sizeof(ndpi_domain_classify);

  if(!s)
    return(0);

  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->classes[i].domains != NULL) {
      tot_len += ndpi_bitmap64_size(s->classes[i].domains);
    } else
      break;
  }

  return(tot_len);
}

/* ********************************************************** */

bool ndpi_domain_classify_add(ndpi_domain_classify *s,
			      u_int8_t class_id,
			      const char *domain) {
  u_int32_t i;
  u_int64_t hash;

  if((!s) || (!domain))
    return(false);

  /* Skip initial string . in domain names */
  while(domain[0] == '.') domain++;

#if 0
  char *dot = strrchr(domain, '.');

  if(dot) {
    if((!strcmp(dot, ".arpa")) || (!strcmp(dot, ".local")))
      return(false);
  }
#endif
  
  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->classes[i].class_id == class_id) {
      break;
    } else if(s->classes[i].class_id == 0) {
      s->classes[i].class_id = class_id;
      s->classes[i].domains  = ndpi_bitmap64_alloc();

      if(!s->classes[i].domains)
        s->classes[i].class_id = 0;

      break;
    }
  }

  if(i == MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS)
    return(false);

  hash = ndpi_quick_hash64(domain, strlen(domain));

  return(ndpi_bitmap64_set(s->classes[i].domains, hash));
}

/* ********************************************************** */

u_int32_t ndpi_domain_classify_add_domains(ndpi_domain_classify *s,
					   u_int8_t class_id,
					   char *file_path) {
  u_int32_t i, num_added = 0;
  char buf[256];
  FILE *fd;
  char *line;

  if((!s) || (!file_path))
    return(false);

  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->classes[i].class_id == class_id) {
      break;
    } else if(s->classes[i].class_id == 0) {
      s->classes[i].class_id = class_id;
      s->classes[i].domains  = ndpi_bitmap64_alloc();
      if(!s->classes[i].domains)
        s->classes[i].class_id = 0;
      break;
    }
  }

  if(i == MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS)
    return(false);

  /* *************************************** */

  fd = fopen(file_path, "r");
  if(fd == NULL)
    return(false);

  while((line = fgets(buf, sizeof(buf), fd)) != NULL) {
    u_int len;
    u_int64_t hash;

    if((line[0] == '#') ||  (line[0] == '\0'))
      continue;
    else {
      len = strlen(line) - 1;

      if(len == 0)
	continue;
      else
	line[len] = '\0';
    }

    hash = ndpi_quick_hash64(line, strlen(line));

    if(ndpi_bitmap64_set(s->classes[i].domains, hash))
      num_added++;
  }

  fclose(fd);

  return(num_added);
}

/* ********************************************************** */

bool ndpi_domain_classify_finalize(ndpi_domain_classify *s) {
  u_int32_t i;

  if(!s)
    return(false);

  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->classes[i].class_id != 0) {
      ndpi_bitmap64_compress(s->classes[i].domains);
    }
  }
  return(true);
}

/* ********************************************************** */

static bool is_valid_domain_char(u_char c) {
  if(((c >= 'A') && (c <= 'Z'))
     || ((c >= 'a') && (c <= 'z'))
     || ((c >= '0') && (c <= '9'))
     || (c == '_')
     || (c == '-')
     || (c == '.'))
    return(true);
  else
    return(false);
}

/* ********************************************************** */

const char* ndpi_domain_classify_longest_prefix(ndpi_domain_classify *s,
						u_int8_t *class_id /* out */,
						const char *hostname,
						bool return_subprefix) {
  u_int32_t i, len;
  const char *dot, *elem, *prev_elem;

  *class_id = 0; /* Unknown class_id */

  if(!hostname || !s)                                       return(hostname);
  if((len = strlen(hostname)) == 0)                         return(hostname);
  if((dot = strrchr(hostname, '.')) == NULL)                return(hostname);
  if((!strcmp(dot, ".arpa")) || (!strcmp(dot, ".local")))   return(hostname);

  /* This is a number or a numeric IP or similar */
  if(ndpi_isdigit(hostname[len-1]) && isdigit(hostname[0])) {
#ifdef DEBUG_CONTAINS
    printf("[contains] %s INVALID\n", hostname);
#endif

    return(hostname);
  }

  if(!is_valid_domain_char(hostname[0])) {
#ifdef DEBUG_CONTAINS
    printf("[contains] %s INVALID\n", hostname);
#endif

    return(hostname);
  }

  elem = prev_elem = hostname;

  while(elem != NULL) {
    u_int64_t hash = ndpi_quick_hash64(elem, strlen(elem));

    for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
      if(s->classes[i].class_id != 0) {
	if(ndpi_bitmap64_isset(s->classes[i].domains, hash)) {
#ifdef DEBUG_CONTAINS
	  printf("[contains] %s = %d [%llu]\n",
		 hostname, s->classes[i].class_id, hash);
#endif
	  *class_id = s->classes[i].class_id;
	  return(return_subprefix ? prev_elem : elem);
	}
      } else
	break;
    }

    prev_elem = elem;
    elem = strchr(elem, '.');

    if(elem == NULL)   break;
    // if(elem == dot)    break;

    elem = &elem[1];
  } /* while */

  /* Not found */
  return(hostname);
}

/* ********************************************************** */

bool ndpi_domain_classify_contains(ndpi_domain_classify *s,
				   u_int8_t *class_id /* out */,
				   const char *domain) {
  (void)ndpi_domain_classify_longest_prefix(s, class_id, domain, false); /* UNUSED */

  return((*class_id == 0) ? false : true);
}
