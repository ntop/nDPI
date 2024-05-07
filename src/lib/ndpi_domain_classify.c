/*
 * ndpi_domain_classify.c
 *
 * Copyright (C) 2011-24 - ntop.org and contributors
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

#define ENCODE_DATA

/* ********************************************************** */

ndpi_domain_classify* ndpi_domain_classify_alloc() {
  ndpi_domain_classify *s = (ndpi_domain_classify*)ndpi_malloc(sizeof(ndpi_domain_classify));

  if(!s)
    return NULL;

  if(ndpi_hash_init(&s->domains) != 0) {
    ndpi_free(s);
    return(NULL);
  }

  return((ndpi_domain_classify*)s);
}

/* ********************************************************** */

void ndpi_domain_classify_free(ndpi_domain_classify *s) {
  if(!s)
    return;

  ndpi_hash_free(&s->domains);

  ndpi_free(s);
}

/* ********************************************************** */

u_int32_t ndpi_domain_classify_size(ndpi_domain_classify *s) {
  u_int32_t tot_len = sizeof(ndpi_domain_classify);

  if(!s)
    return(0);

  /* TODO */

  return(tot_len);
}

/* ********************************************************** */

bool ndpi_domain_classify_add(struct ndpi_detection_module_struct *ndpi_str,
			      ndpi_domain_classify *s,
			      u_int16_t class_id,
			      char *domain) {
#ifdef ENCODE_DATA
  u_int32_t out_len;
  char out[256];
#endif

  if((!s) || (!domain))
    return(false);

  /* Skip initial string . in domain names */
  while(domain[0] == '.') domain++;

  //printf("%s\n", domain);
  // fprintf(stdout, "."); fflush(stdout);

#ifdef ENCODE_DATA
  if(ndpi_str) {
    out_len = ndpi_encode_domain(ndpi_str, domain, out, sizeof(out));
    
    ndpi_hash_add_entry(&s->domains, out, out_len, class_id);
  } else
    ndpi_hash_add_entry(&s->domains, domain, strlen(domain), class_id);
#else
  ndpi_hash_add_entry(&s->domains, domain, strlen(domain), class_id);
#endif

  return(true);
}

/* ********************************************************** */

u_int32_t ndpi_domain_classify_add_domains(struct ndpi_detection_module_struct *ndpi_mod,
					   ndpi_domain_classify *s,
					   u_int16_t class_id,
					   char *file_path) {
  u_int32_t num_added = 0;
  char buf[256];
  FILE *fd;
  char *line;

  if((!s) || (!file_path))
    return(false);

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

    if(ndpi_domain_classify_add(ndpi_mod, s, class_id, line))
      num_added++;
  }

  fclose(fd);

  return(num_added);
}

/* ********************************************************** */

bool ndpi_domain_classify_hostname(struct ndpi_detection_module_struct *ndpi_mod,
				   ndpi_domain_classify *s,
				   u_int16_t *class_id /* out */,
				   char *hostname) {
  u_int32_t len;
  const char *dot;
  char *item;

  // ndpi_enable_loaded_categories(ndpi_mod); /* Make sure they have been enabled */

  *class_id = 0; /* Unknown class_id */

  if(!hostname || !s)                                       return(false);
  if((len = strlen(hostname)) == 0)                         return(false);
  if((dot = strrchr(hostname, '.')) == NULL)                return(false);
  if((!strcmp(dot, ".arpa")) || (!strcmp(dot, ".local")))   return(false);

  item = hostname;

  while(true) {
    char *next;

    /* This looks like a match so let's check the hash now */
#ifdef ENCODE_DATA
    if(ndpi_mod) {
      char out[256];
      u_int32_t out_len = ndpi_encode_domain(ndpi_mod, item, out, sizeof(out));
      
      if(ndpi_hash_find_entry(s->domains, out, out_len, class_id) == 0)
	return(true);
    } else {
      if(ndpi_hash_find_entry(s->domains, item, strlen(item), class_id) == 0)
	return(true);
    }
#else
    if(ndpi_hash_find_entry(s->domains, item, strlen(item), class_id) == 0)
      return(true);
#endif

    next = strchr(item, '.');

    if(!next) break; else item = &next[1];
  }

  /* Not found */
  return(false);
}
