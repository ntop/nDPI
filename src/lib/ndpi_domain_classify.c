/*
 * ndpi_domain_bitmap.c
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

#define NDPI_CURRENT_PROTO       NDPI_PROTOCOL_UNKNOWN

#define END_OF_TOKENS_DELIMITER         0x12345678
#define NUM_DOMAIN_BITMAPS              8
#define NUM_DOMAIN_BITMAPS_THRESHOLD    (NUM_DOMAIN_BITMAPS-1)

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"
#include "ndpi_encryption.h"

typedef struct {
  ndpi_bitmap *bitmap[NUM_DOMAIN_BITMAPS];
} ndpi_domain_search;

typedef struct {
  u_int16_t class_id;
  ndpi_domain_search *domains;
} ndpi_domain_classify_t;

typedef struct {
  ndpi_domain_classify_t *class[MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS];
} ndpi_domain_classifications_t;

// #define DEBUG_ADD
// #define DEBUG_CONTAINS

/* ********************************************************** */

static void ndpi_domain_search_free(ndpi_domain_search *search) {
  u_int16_t i;

  for(i=0; i<NUM_DOMAIN_BITMAPS; i++) {
    if(search->bitmap[i] == NULL)
      break;

    ndpi_bitmap_free(search->bitmap[i]);
  }

  ndpi_free(search);
}

/* ********************************************************** */

static ndpi_domain_search* ndpi_domain_search_alloc() {
  ndpi_domain_search *search = (ndpi_domain_search*)ndpi_calloc(NUM_DOMAIN_BITMAPS, sizeof(ndpi_domain_search));
  u_int16_t i;

  if(!search) return(NULL);

  for(i=0; i<NUM_DOMAIN_BITMAPS; i++) {
    if((search->bitmap[i] = ndpi_bitmap_alloc()) == NULL)
      goto toobad;
  }

  return(search);

 toobad:
  ndpi_domain_search_free(search);
  return(NULL);
}

/* ********************************************************** */

static u_int32_t ndpi_domain_search_size(ndpi_domain_search *search) {
  u_int32_t i, total_len = 0;

  for(i=0; i<NUM_DOMAIN_BITMAPS; i++) {
    char *buf;

    total_len += ndpi_bitmap_serialize(search->bitmap[i], &buf);
    ndpi_free(buf);
  }

  return(total_len);
}

/* ********************************************************** */

/*
  https://en.wikipedia.org/wiki/Jenkins_hash_function

  See also http://burtleburtle.net/bob/hash/spooky.html
*/
static inline u_int32_t ndpi_hash_string(char *domain) {
  u_int32_t hash, i;

  for(hash = i = 0; domain[i] != '\0'; ++i) {
    hash += domain[i];
    hash += (hash << 10);
    hash ^= (hash >> 6);
  }

  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  return(hash);
}

/* ********************************************************** */

/* NOTE: domain will be modified: copy it if necessary */
static bool ndpi_domain_search_add(ndpi_domain_search *search, char *domain) {
  char *elem;
  u_int32_t bitmap_id = 0, len;
  bool quit = false;

  if(domain == NULL)              return(false);
  if((len = strlen(domain)) == 0) return(false);

  len--;
  while((len > 0)
	&& ((domain[len] == '.')
	    || (domain[len] == '\n')
	    || (domain[len] == '\r'))
	)
    domain[len--] = '\0';

  if(domain[0] == '.') ++domain;

  elem = strrchr(domain, '.');
  while(elem) {
    u_int32_t h;

    if(elem[0] == '.') elem = &elem[1];

    h = ndpi_hash_string(elem);

    if(elem == domain) {
      /* We're adding the beginning of the domain, hence the last token before quitting */
      h += END_OF_TOKENS_DELIMITER;
    }

    ndpi_bitmap_set(search->bitmap[bitmap_id], h);

    bitmap_id++;

    if(quit)
      break;

    if(bitmap_id == NUM_DOMAIN_BITMAPS_THRESHOLD)
      elem = domain, quit = true; /* Hash the rest of the word */
    else {
      elem[-1] = '\0';
      elem = strrchr(domain, '.');

      if(elem == NULL)
	elem = domain, quit = true;
    }
  }

  return(bitmap_id);
}

/* ********************************************************** */

static bool ndpi_domain_search_contains(ndpi_domain_search *search, char *domain) {
  char *elem;
  u_int32_t bitmap_id = 0;
  bool quit = false;

  if((elem = strrchr(domain, '.')) == NULL)
    return(false); /* This does not look like a domain */
  
  while(elem) {
    u_int32_t h;

    if(elem[0] == '.') elem = &elem[1];

    h = ndpi_hash_string(elem);

    if(!ndpi_bitmap_isset(search->bitmap[bitmap_id], h)) {
      /* Exact match does not work, so let's see if a partial match works instead */

      /* We're adding the beginning of the domain, hence the last token before quitting */
      h += END_OF_TOKENS_DELIMITER;

      return(ndpi_bitmap_isset(search->bitmap[bitmap_id], h));
    }

    bitmap_id++;

    if(quit)
      break;

    if(bitmap_id == NUM_DOMAIN_BITMAPS_THRESHOLD)
      elem = domain, quit = true; /* Hash the rest of the word */
    else {
      elem[-1] = '\0';
      elem = strrchr(domain, '.');

      if(elem == NULL)
	elem = domain, quit = true;
    }
  }

  return(true);
}

/* ********************************************************** */
/* ********************************************************** */

ndpi_domain_classify* ndpi_domain_classify_alloc() {
  ndpi_domain_classify_t *cat = (ndpi_domain_classify_t*)ndpi_calloc(1, sizeof(ndpi_domain_classifications_t));

  return((ndpi_domain_classify*)cat);
}

/* ********************************************************** */

void ndpi_domain_classify_free(ndpi_domain_classify *_s) {
  u_int32_t i;
  ndpi_domain_classifications_t *s = (ndpi_domain_classifications_t*)_s;

  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->class[i] != NULL) {
      ndpi_domain_search_free(s->class[i]->domains);
      ndpi_free(s->class[i]);
    } else
      break;
  }

  ndpi_free(s);
}

/* ********************************************************** */

u_int32_t ndpi_domain_classify_size(ndpi_domain_classify *_s) {
  u_int32_t i, tot_len = sizeof(ndpi_domain_classify_t);
  ndpi_domain_classifications_t *s = (ndpi_domain_classifications_t*)_s;

  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->class[i] != NULL) {
      tot_len += ndpi_domain_search_size(s->class[i]->domains) + sizeof(ndpi_domain_classify_t);
    } else
      break;
  }

  return(tot_len);
}

/* ********************************************************** */

bool ndpi_domain_classify_add(ndpi_domain_classify *_s,
			      u_int16_t class_id,
			      char *domain) {
  u_int32_t i;
  ndpi_domain_classifications_t *s = (ndpi_domain_classifications_t*)_s;
  char buf[256], *dot = strrchr(domain, '.');

  if(!dot) return(false);
  if((!strcmp(dot, ".arpa")) || (!strcmp(dot, ".local")))
    return(false);
  
  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->class[i] != NULL) {
      if(s->class[i]->class_id == class_id) {
	break;
      }
    } else {
      s->class[i] = (ndpi_domain_classify_t*)ndpi_malloc(sizeof(ndpi_domain_classify_t));

      if(s->class[i] == NULL)
	return(false);

      s->class[i]->class_id = class_id;
      s->class[i]->domains  =  ndpi_domain_search_alloc();
      break;
    }
  }

  if(i == MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS)
    return(false);

  snprintf(buf, sizeof(buf), "%s", domain);

#ifdef DEBUG_ADD
  printf("[add] %s @ %u\n", domain, class_id);
#endif

  return(ndpi_domain_search_add(s->class[i]->domains, buf));
}

/* ********************************************************** */

u_int32_t ndpi_domain_classify_add_domains(ndpi_domain_classify *_s,
					   u_int16_t class_id,
					   char *file_path) {
  u_int32_t i, num_added = 0;
  ndpi_domain_classifications_t *s = (ndpi_domain_classifications_t*)_s;
  char buf[256];
  FILE *fd;
  char *line;

  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->class[i] != NULL) {
      if(s->class[i]->class_id == class_id) {
	break;
      }
    } else {
      s->class[i] = (ndpi_domain_classify_t*)ndpi_malloc(sizeof(ndpi_domain_classify_t));

      if(s->class[i] == NULL)
	return(false);

      s->class[i]->class_id = class_id;
      s->class[i]->domains     =  ndpi_domain_search_alloc();
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

    if((line[0] == '#') ||  (line[0] == '\0'))
      continue;
    else {
      len = strlen(line) - 1;

      if(len == 0)
	continue;
      else
	line[len] = '\0';
    }

    if(ndpi_domain_search_add(s->class[i]->domains, line))
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

u_int16_t ndpi_domain_classify_contains(ndpi_domain_classify *_s,
					char *domain) {
  u_int32_t i, len;
  ndpi_domain_classifications_t *s = (ndpi_domain_classifications_t*)_s;
  char *dot;

  if(!domain)                                             return(0);
  if((len = strlen(domain)) == 0)                         return(0);
  if((dot = strrchr(domain, '.')) == NULL)                return(0);
  if((!strcmp(dot, ".arpa")) || (!strcmp(dot, ".local"))) return(0);

  /* This is a number or a numeric IP or similar */
  if(isdigit(domain[len-1]) && isdigit(domain[0])) {
#ifdef DEBUG_CONTAINS
    printf("[contains] %s INVALID\n", domain);
#endif

    return(0);
  }
  
  if(!is_valid_domain_char(domain[0])) {
#ifdef DEBUG_CONTAINS
    printf("[contains] %s INVALID\n", domain);
#endif

    return(0);
  }
  
  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->class[i] != NULL) {
      char buf[256];
      
      snprintf(buf, sizeof(buf), "%s", domain);
      
      if(ndpi_domain_search_contains(s->class[i]->domains, buf)) {
#ifdef DEBUG_CONTAINS
	printf("[contains] %s = %d\n", domain, s->class[i]->class_id);
#endif
	return(s->class[i]->class_id);
      }
    }
  }

#ifdef DEBUG_CONTAINS
  printf("[contains] %s NOT FOUND\n", domain);
#endif

  return(0);
}
