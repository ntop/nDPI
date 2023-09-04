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

// #define USE_BINARY_BITMAP

#ifdef USE_BINARY_BITMAP

/* ********************************************************** */
/* ********************************************************** */

/* Faster but it uses more memory */

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

#ifdef DEBUG_ADD
  printf("[add] Trying to add %s\n", domain);
#endif

  if(!dot) return(false);
  if((!strcmp(dot, ".arpa")) || (!strcmp(dot, ".local")))
    return(false);

  /* Skip heading dots */
  while(domain[0] == '.') domain++;

  hash1 = ndpi_hash_string(domain), hash2 = ndpi_rev_hash_string(domain);
  hash = (hash1 << 32) | hash2;

#ifdef DEBUG_ADD
  printf("[add] %s @ %u [hash: %llu]\n", domain, class_id, hash);

  if(ndpi_binary_bitmap_isset(c->bitmap, hash, class_id)) {
    printf("[add] False positive %s @ %u [hash: %llu]\n", domain, class_id, hash);
  }
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

#else /* ! USE_BINARY_BITMAP */

/* ********************************************************** */
/* ********************************************************** */

#define END_OF_TOKENS_DELIMITER         0x12345678
#define NUM_DOMAIN_BITMAPS              8
#define NUM_DOMAIN_BITMAPS_THRESHOLD    (NUM_DOMAIN_BITMAPS-1)
#define MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS 8

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

/* NOTE: domain will be modified: copy it if necessary */
static bool ndpi_domain_search_add(ndpi_domain_search *search, char *domain) {
  char *elem;
  u_int32_t bitmap_id = 0, len, hsum = 0;
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

#ifdef DEBUG_ADD
      if(ndpi_bitmap_isset(search->bitmap[bitmap_id], h + hsum))
	printf("[add] False positive while adding %s (%s) [%u][bitmap_id: %u]\n",
	       elem, domain, h + hsum, bitmap_id);
#endif
    }

#ifdef DEBUG_ADD
    printf("[add] Trying to add %s [%s][%u][bitmap_id: %u]\n",
	   elem, domain, h + hsum, bitmap_id);
#endif

    ndpi_bitmap_set(search->bitmap[bitmap_id], h + hsum);

    bitmap_id++, hsum += h;

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
  u_int32_t bitmap_id = 0, hsum = 0;
  bool quit = false;

  if((elem = strrchr(domain, '.')) == NULL)
    return(false); /* This does not look like a domain */

  while(elem) {
    u_int32_t h;

    if(elem[0] == '.') elem = &elem[1];

    h = ndpi_hash_string(elem);

    if(!ndpi_bitmap_isset(search->bitmap[bitmap_id], h + hsum)) {
      /* Exact match does not work, so let's see if a partial match works instead */

      /* We're adding the beginning of the domain, hence the last token before quitting */
      h += END_OF_TOKENS_DELIMITER;

      return(ndpi_bitmap_isset(search->bitmap[bitmap_id], h + hsum));
    }

    bitmap_id++, hsum += h;

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
			      u_int8_t class_id,
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
					   u_int8_t class_id,
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
      s->class[i]->domains  =  ndpi_domain_search_alloc();
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

bool ndpi_domain_classify_contains(ndpi_domain_classify *_s,
				   u_int8_t *class_id /* out */,
				   char *domain) {
  u_int32_t i, len;
  ndpi_domain_classifications_t *s = (ndpi_domain_classifications_t*)_s;
  char *dot;

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

  for(i=0; i<MAX_NUM_NDPI_DOMAIN_CLASSIFICATIONS; i++) {
    if(s->class[i] != NULL) {
      char buf[256];

      snprintf(buf, sizeof(buf), "%s", domain);

      if(ndpi_domain_search_contains(s->class[i]->domains, buf)) {
#ifdef DEBUG_CONTAINS
	printf("[contains] %s = %d\n", domain, s->class[i]->class_id);
#endif
	*class_id = s->class[i]->class_id;
	return(true);
      }
    }
  }

#ifdef DEBUG_CONTAINS
  printf("[contains] %s NOT FOUND\n", domain);
#endif

  return(false);
}


#endif
