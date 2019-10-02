/* Based on https://gist.github.com/tonious/1377667 */

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

#include "ht_hash.h"

/* #define HASH_DEBUG 1 */

/* Create a new hashtable. */
hashtable_t *ht_create(int size) {
  hashtable_t *hashtable = NULL;
  int i;

  if(size < 1) return NULL;

  /* Allocate the table itself. */
  if((hashtable = ndpi_malloc(sizeof(hashtable_t))) == NULL)
    return NULL;

  /* Allocate pointers to the head nodes. */
  if((hashtable->table = ndpi_malloc(sizeof(entry_t *) * size)) == NULL) {
    free(hashtable);
    return NULL;
  } else {    
    for(i = 0; i < size; i++)
      hashtable->table[i] = NULL;
  }
  
  hashtable->size = size;

  return hashtable;
}

/* **************************************************** */

/* Hash a string for a particular hash table. */
int ht_hash(hashtable_t *hashtable, char *key) {
  unsigned long int hashval = 0;
  int i = 0;

  /* Convert our string to an integer */
  while(hashval < ULONG_MAX && i < strlen(key)) {
    hashval = hashval << 8;
    hashval += key[ i ];
    i++;
  }

  return hashval % hashtable->size;
}

/* **************************************************** */

/* Create a key-value pair. */
entry_t *ht_newpair(char *key, u_int16_t value) {
  entry_t *newpair;

  if((newpair = ndpi_malloc(sizeof(entry_t))) == NULL)
    return NULL;  
  
  if((newpair->key = ndpi_strdup(key)) == NULL) {
    free(newpair);
    return NULL;  
  }

  newpair->value = value, newpair->next = NULL;

  return newpair;
}

/* **************************************************** */

/* Insert a key-value pair into a hash table. */
void ht_set(hashtable_t *hashtable, char *key, u_int16_t value) {
  int bin = 0;
  entry_t *newpair = NULL;
  entry_t *next = NULL;
  entry_t *last = NULL;

#ifdef HASH_DEBUG
  printf("*** %s() %s = %u ***\n", __FUNCTION__, key, value);
#endif

  bin = ht_hash(hashtable, key);

  next = hashtable->table[ bin ];

  while(next != NULL && next->key != NULL && strcmp(key, next->key) > 0) {
    last = next;
    next = next->next;
  }

  /* There's already a pair.  Let's replace that string. */
  if(next != NULL && next->key != NULL && strcmp(key, next->key) == 0) {
    next->value = value;

    /* Nope, could't find it.  Time to grow a pair. */
  } else {
    newpair = ht_newpair(key, value);

    /* We're at the start of the linked list in this bin. */
    if(next == hashtable->table[ bin ]) {
      newpair->next = next;
      hashtable->table[ bin ] = newpair;

      /* We're at the end of the linked list in this bin. */
    } else if (next == NULL) {
      last->next = newpair;

      /* We're in the middle of the list. */
    } else  {
      newpair->next = next;
      last->next = newpair;
    }
  }
}

/* **************************************************** */

/* Retrieve a key-value pair from a hash table. */
u_int16_t ht_get(hashtable_t *hashtable, char *key) {
  int bin = 0;
  entry_t *pair;

  bin = ht_hash(hashtable, key);

  /* Step through the bin, looking for our value. */
  pair = hashtable->table[ bin ];
  while(pair != NULL && pair->key != NULL && strcmp(key, pair->key) > 0) {
    pair = pair->next;
  }

  /* Did we actually find anything? */
  if(pair == NULL || pair->key == NULL || strcmp(key, pair->key) != 0) {
    return 0;
  } else {
    return pair->value;
  }
}

/* **************************************************** */

void ht_free(hashtable_t *hashtable) {
  int i;
  
  for(i=0; i<hashtable->size; i++) {
    struct entry_s *t = hashtable->table[i];

    while(t != NULL) {
      struct entry_s *next = t->next;

      ndpi_free(t->key);
      ndpi_free(t);

      t = next;
    }
  }

  ndpi_free(hashtable->table);
  ndpi_free(hashtable);
}

/* **************************************************** */

#ifdef HASH_TEST

int main(int argc, char **argv) {
  hashtable_t *hashtable = ht_create(65536);

  ht_set(hashtable, "key1", 32);
  ht_set(hashtable, "key2", 34);
  ht_set(hashtable, "key3", 124);
  ht_set(hashtable, "key4", 98);

  printf("%u\n", ht_get(hashtable, "key1"));
  printf("%u\n", ht_get(hashtable, "key2"));
  printf("%u\n", ht_get(hashtable, "key3"));
  printf("%u\n", ht_get(hashtable, "key4"));

  return 0;
}

#endif
