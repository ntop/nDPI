/*
 * ahocorasick.h: Includes all types of ahocorasick library
 * This file is part of multifast.
 *
 Copyright 2010-2012 Kamiar Kanani <kamiar.kanani@gmail.com>

 multifast is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 multifast is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with multifast.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _AC_TYPES_H_
#define _AC_TYPES_H_

#define AC_AHOCORASICK_NEW
#define AC_PATTRN_MAX_LENGTH 256

/* reallocation step for AC_NODE_t.matched_patterns */
#define REALLOC_CHUNK_MATCHSTR 8

/* reallocation step for AC_NODE_t.outgoing array */
/* Must be a multiple of __SIZEOF_LONG__ ! */
#define REALLOC_CHUNK_OUTGOING 8

/* AC_ALPHABET_t:
 * defines the alphabet type.
 * Actually defining AC_ALPHABET_t as a char will work, but sometimes we deal
 * with streams of other (bigger) types e.g. integers, specific enum, objects.
 * Although they consists of string of bytes (chars), but using their specific
 * types for AC_ALPHABET_t will lead to a better performance. so instead of
 * dealing with strings of chars, we assume dealing with strings of
 * AC_ALPHABET_t and leave it optional for other developers to define their
 * own alphabets.
 **/
typedef char AC_ALPHABET_t;

/* AC_REP_t:
 * Provides a more readable representative for a pattern.
 * because patterns themselves are not always suitable for displaying
 * (e.g. for hex patterns), we offer this type to improve intelligibility
 * of output. furthermore, sometimes it is useful, for example while
 * retrieving patterns from a database, to maintain their identifiers in the
 * automata for further reference. we provisioned two possible types as a
 * union for this purpose. you can add your desired type in it.
 **/
typedef struct {
  uint32_t number; /* Often used to store procotolId */
  uint64_t number64;
  uint16_t breed, category;
  uint16_t        level,        /* Domain level for comparison */
                  from_start:1, /* match from start of string */
                  at_end:1,     /* match at end of string */
                  dot:1;        /* is domain name */
} AC_REP_t;

/* AC_PATTERN_t:
 * This is the pattern type that must be fed into AC automata.
 * the 'astring' field is not null-terminated, due to it can contain zero
 * value bytes. the 'length' field determines the number of AC_ALPHABET_t it
 * carries. the 'representative' field is described in AC_REP_t. despite
 * 'astring', 'representative' can have duplicate values for different given
 * AC_PATTERN_t. it is an optional field and you can just fill it with 0.
 * CAUTION:
 * Not always the 'astring' points to the correct position in memory.
 * it is the responsibility of your program to maintain a permanent allocation
 * for astring field of the added pattern to automata.
 **/

typedef struct
{
  AC_ALPHABET_t * astring; /* String of alphabets */
  uint16_t        length,  /* Length of pattern */
	          is_existing; /* not union_matchstr */
  AC_REP_t rep;   /* Representative string (optional) */
} AC_PATTERN_t;

typedef struct {
  unsigned short num; /* Number of matched patterns at this node */
  unsigned short max; /* Max capacity of allocated memory for matched_patterns */
  AC_PATTERN_t	patterns[];
} AC_PATTERNS_t;


/* AC_MATCH_t:
 * Provides the structure for reporting a match event.
 * a match event occurs when the automata reaches a final node. any final
 * node can match one or more pattern at a position in a text. the
 * 'patterns' field holds these matched patterns. obviously these
 * matched patterns have same end-position in the text. there is a relationship
 * between matched patterns: the shorter one is a factor (tail) of the longer
 * one. the 'position' maintains the end position of matched patterns. the
 * start position of patterns could be found by knowing their 'length' in
 * AC_PATTERN_t. e.g. suppose "recent" and "cent" are matched at
 * position 40 in the text, then the start position of them are 34 and 36
 * respectively. finally the field 'match_num' maintains the number of
 * matched patterns.
 **/

typedef struct
{
  AC_PATTERN_t *matched[4],   /* for ac_automata_exact_match() */
	       *last;         /* for callback              */
  AC_PATTERN_t *patterns;     /* Array of matched pattern  */
  unsigned int  match_map;    /* Matched patterns (bitmap) */
  unsigned int  position;     /* The end position of matching pattern(s) in the text */
  unsigned short int match_num;     /* Number of matched patterns */
  unsigned short int match_counter; /* Counter of found matches */
} AC_MATCH_t;

/* AC_TEXT_t:
 * The input text type that is fed to ac_automata_search() to be searched.
 * it is similar to AC_PATTERN_t. actually we could use AC_PATTERN_t as input
 * text, but for the purpose of being more readable, we defined this new type.
 **/
typedef struct
{
  AC_MATCH_t match;
  AC_ALPHABET_t * astring;    /* String of alphabets */
  unsigned short int  length, /* Length of string */
	                  option; /* AC_FEATURE_LC | AC_FEATURE_DEBUG */
} AC_TEXT_t;


/* AC_ERROR_t:
 * Error that may occur while adding a pattern to the automata.
 * it is returned by ac_automata_add().
 **/
typedef enum
  {
    ACERR_SUCCESS = 0, /* No error occurred */
    ACERR_DUPLICATE_PATTERN, /* Duplicate patterns */
    ACERR_LONG_PATTERN, /* Pattern length is longer than AC_PATTRN_MAX_LENGTH */
    ACERR_ZERO_PATTERN, /* Empty pattern (zero length) */
    ACERR_AUTOMATA_CLOSED, /* Automata is closed. after calling
			      ac_automata_finalize() you can not add new patterns to the automata. */
    ACERR_ERROR, /* common error */
  } AC_ERROR_t;

/* MATCH_CALLBACK_t:
 * This is the call-back function type that must be given to automata at
 * initialization to report match occurrence to the caller.
 * at a match event, the automata will reach you using this function and sends
 * you a pointer to AC_MATCH_t. using that pointer you can handle
 * matches. you can send parameters to the call-back function when you call
 * ac_automata_search(). at call-back, the automata will sent you those
 * parameters as the second parameter (void *) of MATCH_CALLBACK_t. inside
 * the call-back function you can cast it to whatever you want.
 * If you return 0 from MATCH_CALLBACK_t function to the automata, it will
 * continue searching, otherwise it will return from ac_automata_search()
 * to your calling function.
 **/
typedef int (*MATCH_CALLBACK_f)(AC_MATCH_t *, AC_TEXT_t *, AC_REP_t *);

/* AC_PATTRN_MAX_LENGTH:
 * Maximum acceptable pattern length in AC_PATTERN_t.length
 **/

/* Forward Declaration */
struct edge;

/*
 * automata node
 * 4 pointers + 8 bytes : 40/24 bytes for 64/32 bit
 */
typedef struct ac_node
{
  int id;                              /* Node ID : set after finalize(), only for ac_automata_dump */
  AC_ALPHABET_t  one_alpha;
  unsigned char  one:1,                /* one_char: yes/no */
		 range:1,              /* range symbols start from one_alpha */
		 root:1,               /* is root node */
	  	 final:1,	       /* 0: no ; 1: yes, it is a final node */
		 use:1,	               /* use: yes/no */ 
		 ff:1;		       /* finalized node */
  unsigned short depth;                /* depth: distance between this node and the root */

  AC_PATTERNS_t  *matched_patterns;   /* Array of matched patterns */
  struct edge    *outgoing;           /* Array of outgoing edges */

  struct ac_node *failure_node;       /* The failure node of this node */
  unsigned char  *a_ptr;
} AC_NODE_t;

struct edge {
  unsigned short degree;      /* Number of outgoing edges */
  unsigned short max;         /* Max capacity of allocated memory for outgoing */
  uint32_t       cmap[8];      /* 256 bit */
  AC_NODE_t	 *next[];
 /*
  * first N elements used for 'next' pointers +
  * M elements used for symbols storage
  * M = (max + sizeof(void*)-1) & ( ~(sizeof(void*)-1))
  *
  * if sizeof(void*)==8
  * for max = 8  we must alloc next[9];
  * for max = 16 we must alloc next[18];
  *
  */
};

struct ac_path {
  AC_NODE_t * n;
  unsigned short int idx,l;
};

struct ac_stats {
  uint64_t n_search;
  uint64_t n_found;
};

typedef struct
{
  /* The root of the Aho-Corasick trie */
  AC_NODE_t * root;
  MATCH_CALLBACK_f match_handler;
  unsigned int all_nodes_num; /* Number of all nodes in the automata */

  /* this flag indicates that if automata is finalized by
   * ac_automata_finalize() or not. 1 means finalized and 0
   * means not finalized (is open). after finalizing automata you can not
   * add pattern to automata anymore. */
  unsigned short automata_open,
		 to_lc:1, no_root_range:1,debug:1; /* lowercase match */

  /* Statistic Variables */
  unsigned long total_patterns; /* Total patterns in the automata */

  unsigned long max_str_len; /* largest pattern length. Update by ac_automata_finalize() */

  struct ac_path ac_path[AC_PATTRN_MAX_LENGTH+4]; /* for ac_automata_walk */
  int id;	/* node id */
  int add_to_range; /* for convert to range */
  int n_oc,n_range,n_find; /* statistics */
  char name[32]; /* if debug != 0 */
  struct ac_stats stats;
} AC_AUTOMATA_t;

typedef AC_ERROR_t (*NODE_CALLBACK_f)(AC_AUTOMATA_t *, AC_NODE_t *,int idx, void *);

typedef void (*ALPHA_CALLBACK_f)(AC_AUTOMATA_t *, AC_NODE_t *,AC_NODE_t *,int ,void *);

#define AC_FEATURE_DEBUG 1 
#define AC_FEATURE_LC 2
#define AC_FEATURE_NO_ROOT_RANGE 4

AC_AUTOMATA_t * ac_automata_init     (MATCH_CALLBACK_f mc);
AC_ERROR_t      ac_automata_feature  (AC_AUTOMATA_t * thiz, unsigned int feature);
AC_ERROR_t      ac_automata_name     (AC_AUTOMATA_t * thiz, char *name, int debug);
AC_ERROR_t      ac_automata_add      (AC_AUTOMATA_t * thiz, AC_PATTERN_t * str);
AC_ERROR_t      ac_automata_finalize (AC_AUTOMATA_t * thiz);
AC_ERROR_t      ac_automata_walk     (AC_AUTOMATA_t * thiz, NODE_CALLBACK_f node_cb,
						ALPHA_CALLBACK_f alpha_cb, void *);

int             ac_automata_search   (AC_AUTOMATA_t * thiz,
						AC_TEXT_t * str, 
						AC_REP_t * param);
int             ac_automata_exact_match(AC_PATTERNS_t *mp,int pos, AC_TEXT_t *);
void            ac_automata_clean    (AC_AUTOMATA_t * thiz);
void            ac_automata_release  (AC_AUTOMATA_t * thiz, uint8_t free_pattern);
#ifndef __KERNEL__
/* Global debug control. */
void            ac_automata_enable_debug (int debug);
/* See man open_memstream() for get result as string */
void            ac_automata_dump     (AC_AUTOMATA_t * thiz, FILE *);
#endif
void            ac_automata_get_stats(AC_AUTOMATA_t * thiz, struct ac_stats *stats);
#endif

#ifdef __cplusplus
}
#endif
