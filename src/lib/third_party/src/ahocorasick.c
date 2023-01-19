/*
 * ahocorasick.c: implementation of ahocorasick library's functions
 * This file is part of multifast.
 *
 Copyright 2010-2012 Kamiar Kanani <kamiar.kanani@gmail.com>
 Copyright 2012-21   ntop.org (Incremental improvements)

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

#ifndef __KERNEL__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#if !defined(WIN32) && !defined(_MSC_VER)
#include <unistd.h>
#else
#define __SIZEOF_LONG__ 4
#endif
#include <stdint.h>
#include <sys/types.h>
#else
#include <asm/byteorder.h>
#include <linux/kernel.h>
#include <linux/types.h>
typedef __kernel_size_t size_t;
#include <linux/string.h>
#include <linux/slab.h>
#endif

#include "ndpi_api.h"
#include "ahocorasick.h"

/* TODO: For different depth of node, number of outgoing edges differs
   considerably, It is efficient to use different chunk size for 
   different depths */

/* Private function prototype */
static int  node_edge_compare (struct edge * e, int a, int b);
static int  node_has_matchstr (AC_NODE_t * thiz, AC_PATTERN_t * newstr);

static AC_NODE_t * node_create            (void);
static AC_NODE_t * node_create_next       (AC_NODE_t * thiz, AC_ALPHABET_t alpha);
static int         node_register_matchstr (AC_NODE_t * thiz, AC_PATTERN_t * str, int is_existing);
static int         node_register_outgoing (AC_NODE_t * thiz, AC_NODE_t * next, AC_ALPHABET_t alpha);
static AC_NODE_t * node_find_next         (AC_NODE_t * thiz, AC_ALPHABET_t alpha);
static AC_NODE_t * node_findbs_next       (AC_NODE_t * thiz, uint8_t alpha);
static AC_NODE_t * node_findbs_next_ac    (AC_NODE_t * thiz, uint8_t alpha,int icase);
static void        node_release           (AC_NODE_t * thiz, int free_pattern);
static void        node_release_pattern   (AC_NODE_t * thiz);
static int         node_range_edges       (AC_AUTOMATA_t *thiz, AC_NODE_t * node);
static inline void node_sort_edges        (AC_NODE_t * thiz);

#ifndef __KERNEL__
struct aho_dump_info {
  size_t memcnt,node_oc,node_8c,node_xc,node_xr;
  int    buf_pos,ip;
  char   *bufstr;
  size_t bufstr_len;
  FILE   *file;
};

static void dump_node_header(AC_NODE_t * n, struct aho_dump_info *);
static int ac_automata_global_debug = 0;
#endif

/* Private function prototype */
static int ac_automata_union_matchstrs (AC_NODE_t * node);
static void ac_automata_set_failure
        (AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_NODE_t * next, int idx, void *);
static void ac_automata_traverse_setfailure
        (AC_AUTOMATA_t * thiz);

static inline AC_ALPHABET_t *edge_get_alpha(struct edge *e) {
        return (AC_ALPHABET_t *)(&e->next[e->max]);
}
static inline size_t edge_data_size(int num) {
        return sizeof(void *)*num + ((num + sizeof(void *) - 1) & ~(sizeof(void *)-1));
}

#ifdef __KERNEL__
static inline void *acho_calloc(size_t nmemb, size_t size) {
    return kcalloc(nmemb, size, GFP_ATOMIC);
}
static inline void *acho_malloc(size_t size) {
    return kmalloc(size, GFP_ATOMIC);
}
static inline void acho_free(void *old) {
    return kfree(old);
}
#else

#define acho_calloc(a,b) ndpi_calloc(a,b)
#define acho_malloc(a) ndpi_malloc(a)
#define acho_free(a) ndpi_free(a)
#endif

static void acho_sort(struct edge *e, size_t num,
      int (*cmp_func)(struct edge *e, int a, int b),
      void (*swap_func)(struct edge *e, int a, int b));

/* tolower() from glibc */
static uint8_t aho_lc[256] = {
  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,
 16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,
 32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,
 48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,
 64, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',  91,  92,  93,  94,  95,
 96,  97,  98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

/* toupper() from glibc */
static uint8_t aho_xc[256] = {
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
 32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,   0,   0,   0,   0,   0,
  0,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,
 32,  32,  32,  32,  32,  32,  32,  32,  32,  32,  32,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0
};

/******************************************************************************
 * FUNCTION: ac_automata_init
 * Initialize automata; allocate memories and set initial values
 * PARAMS:
 * MATCH_CALLBACK mc: call-back function
 * the call-back function will be used to reach the caller on match occurrence
 ******************************************************************************/
AC_AUTOMATA_t * ac_automata_init (MATCH_CALLBACK_f mc)
{
  AC_AUTOMATA_t * thiz;
//  if(!mc) return NULL;
  thiz = (AC_AUTOMATA_t *)acho_calloc(1,sizeof(AC_AUTOMATA_t));
  if(!thiz) return NULL;
  thiz->root = node_create ();
  if(!thiz->root) {
      acho_free(thiz);
      return NULL;
  }
  thiz->root->id = 1;
  thiz->root->root = 1;
  thiz->total_patterns = 0;
  thiz->automata_open = 1;
  thiz->match_handler = mc;
  thiz->to_lc = 0;
  thiz->no_root_range = 0;
  thiz->add_to_range = REALLOC_CHUNK_OUTGOING*2;
  return thiz;
}
/******************************************************************************
 * FUNCTION: ac_automata_casecmp
 * Case-insensitive comparison mode
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * lc: 1 for case-insensitive comparison mode
 * RETUERN VALUE: AC_ERROR_t
 * the return value indicates the success or failure of changes
 ******************************************************************************/
AC_ERROR_t ac_automata_feature (AC_AUTOMATA_t * thiz, unsigned int feature)
{
  if(!thiz) return ACERR_ERROR;
  if(thiz->all_nodes_num || thiz->total_patterns) return ACERR_ERROR;
  thiz->to_lc = (feature & AC_FEATURE_LC) != 0;
  thiz->no_root_range = (feature & AC_FEATURE_NO_ROOT_RANGE) != 0;
  return ACERR_SUCCESS;
}

AC_ERROR_t ac_automata_name (AC_AUTOMATA_t * thiz, char *name, int debug)
{
  if(!thiz) return ACERR_ERROR;
  strncpy(thiz->name,name,sizeof(thiz->name)-1);
  thiz->debug = debug != 0;
  return ACERR_SUCCESS;
}

#ifndef __KERNEL__
void ac_automata_enable_debug (int debug) {
    ac_automata_global_debug = debug != 0;
}
#endif

/******************************************************************************
 * FUNCTION: ac_automata_add
 * Adds pattern to the automata.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * AC_PATTERN_t * patt: the pointer to added pattern
 * RETUERN VALUE: AC_ERROR_t
 * the return value indicates the success or failure of adding action
 ******************************************************************************/
AC_ERROR_t ac_automata_add (AC_AUTOMATA_t * thiz, AC_PATTERN_t * patt)
{
  unsigned int i;
  AC_NODE_t * n;
  AC_NODE_t * next;
  AC_ALPHABET_t alpha;

  if(!thiz || !patt || !patt->astring)
    return ACERR_ERROR;

  n = thiz->root;

  if(!thiz->automata_open)
    return ACERR_AUTOMATA_CLOSED;

  if (!patt->length)
    return ACERR_ZERO_PATTERN;

  if (patt->length > AC_PATTRN_MAX_LENGTH)
    return ACERR_LONG_PATTERN;

  for (i=0; i<patt->length; i++) {
      alpha = patt->astring[i];
      if(thiz->to_lc)
           alpha = (AC_ALPHABET_t)aho_lc[(uint8_t)alpha];

      if((next = node_find_next(n, alpha)) != 0) {
          n = next;
          continue;
      }
      if(!(next = node_create_next(n, alpha))) 
              return ACERR_ERROR;
      next->id = ++thiz->id;
      thiz->all_nodes_num++;
      n = next;
    }
  if(thiz->max_str_len < patt->length)
     thiz->max_str_len = patt->length;

  if(n->final && n->matched_patterns) {
    patt->rep.number = n->matched_patterns->patterns[0].rep.number;
    return ACERR_DUPLICATE_PATTERN;
  }

  if(node_register_matchstr(n, patt, 0))
      return ACERR_ERROR;
 
  thiz->total_patterns++;

  return ACERR_SUCCESS;
}

AC_ERROR_t ac_automata_walk(AC_AUTOMATA_t * thiz,
        NODE_CALLBACK_f node_cb, ALPHA_CALLBACK_f alpha_cb, void *data)
{
  unsigned int ip;
  AC_NODE_t *next, *n;
  struct ac_path * path = thiz->ac_path;
  AC_ERROR_t r;

  ip = 1;
  path[1].n = thiz->root;
  path[1].idx = 0;

  while(ip) {
    unsigned int i,last;
    n = path[ip].n;
    i = path[ip].idx;
    last = !n->outgoing || (n->one && i > 0) || (!n->one && i >= n->outgoing->degree);
    if(node_cb && (!i || last)) {
            r = node_cb(thiz, n, i, data);
            if(r != ACERR_SUCCESS) return r;
    }
    if(last) {
        ip--; continue;
    }
    next = NULL;
    if(n->one) {
        next = (AC_NODE_t *)n->outgoing;
    } else {
        while(i < n->outgoing->degree) {
            next = n->outgoing->next[i];
            if(next) break;
            i++;
        }
    }
    if(!next) {
        if(!n->range || i >= n->outgoing->degree) {
            r = node_cb ? node_cb(thiz, n, i, data):ACERR_SUCCESS;
            if(r != ACERR_SUCCESS) return r;
        }
        ip--; continue;
    }

    if(n->depth < AC_PATTRN_MAX_LENGTH) {
            path[n->depth].l = n->one ? n->one_alpha:
                                    edge_get_alpha(n->outgoing)[i];
            if(alpha_cb)
                alpha_cb(thiz, n, next, i, data);
    }

    path[ip].idx = i+1;
    if(ip >= AC_PATTRN_MAX_LENGTH)
        continue;

    ip++;

    path[ip].n = next;
    path[ip].idx = 0;

  }
  return ACERR_SUCCESS;
}


static AC_ERROR_t ac_finalize_node(AC_AUTOMATA_t * thiz,AC_NODE_t * n, int idx, void *data) {
    if(!n->ff) {
        n->id = ++(thiz->id);
        n->ff = 1;
        if(ac_automata_union_matchstrs (n))
            return ACERR_ERROR;
        if(n->use) {
            if(!n->one) {
                if(node_range_edges (thiz,n)) {
                    node_sort_edges (n);
                    thiz->n_range++;
                } else
                    thiz->n_find++;
            } else
                thiz->n_oc++;
        }
    }
    if(!n->a_ptr && n->outgoing && !n->one) {
        n->a_ptr = (unsigned char *)edge_get_alpha(n->outgoing);
    }
    return ACERR_SUCCESS;
}


/******************************************************************************
 * FUNCTION: ac_automata_finalize
 * Locate the failure node for all nodes and collect all matched pattern for
 * every node. it also sorts outgoing edges of node, so binary search could be
 * performed on them. after calling this function the automate literally will
 * be finalized and you can not add new patterns to the automate.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 ******************************************************************************/

AC_ERROR_t ac_automata_finalize (AC_AUTOMATA_t * thiz) {

    AC_ERROR_t r = ACERR_SUCCESS;
    if(!thiz || !thiz->automata_open) return r;

    ac_automata_traverse_setfailure (thiz);
    thiz->id=0;
    thiz->n_oc = 0;
    thiz->n_range = 0;
    thiz->n_find = 0;
    r = ac_automata_walk(thiz,ac_finalize_node,NULL,NULL);
    if(r == ACERR_SUCCESS)
        thiz->automata_open = 0;
    return r;
}

int ac_automata_exact_match(AC_PATTERNS_t *mp,int pos, AC_TEXT_t *txt) {
    AC_PATTERN_t *patterns = mp->patterns;
    AC_PATTERN_t **matched = txt->match.matched;
    unsigned int i;
    int match_map = 0;
    for(i=0; i < mp->num && i < ((sizeof(int)*8)-1); i++,patterns++) {
      do {
        if(patterns->rep.from_start && patterns->rep.at_end) {
            if(pos == txt->length && patterns->length == pos)
                matched[0] = patterns, match_map |= 1 << i;
            break;
        }
        if(patterns->rep.from_start) {
            if(patterns->length == pos)
                matched[1] = patterns, match_map |= 1 << i;
            break;
        }
        if(patterns->rep.at_end) {
            if(pos == txt->length) 
                matched[2] = patterns, match_map |= 1 << i;
            break;
        }
        matched[3] = patterns, match_map |= 1 << i;
      } while(0);
    }
    return match_map;
}

/******************************************************************************
 * FUNCTION: ac_automata_search
 * Search in the input text using the given automata. on match event it will
 * call the call-back function. and the call-back function in turn after doing
 * its job, will return an integer value to ac_automata_search(). 0 value means
 * continue search, and non-0 value means stop search and return to the caller.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * AC_TEXT_t * txt: the input text that must be searched
 * void * param: this parameter will be send to call-back function. it is
 * useful for sending parameter to call-back function from caller function.
 * RETURN VALUE:
 * -1: failed call; automata is not finalized
 *  0: success; continue searching; call-back sent me a 0 value
 *  1: success; stop searching; call-back sent me a non-0 value
 ******************************************************************************/
int ac_automata_search (AC_AUTOMATA_t * thiz,
        AC_TEXT_t * txt, AC_REP_t * param)
{
  unsigned long position;
  int icase = 0,i,debug=0;
  AC_MATCH_t *match;
  AC_NODE_t *curr;
  AC_NODE_t *next;
  AC_ALPHABET_t *apos;

  if(!thiz || !txt) return -1;

  thiz->stats.n_search++;

  if(thiz->automata_open)
    /* you must call ac_automata_locate_failure() first */
    return -1;
  position = 0;
  curr = thiz->root;
  apos = txt->astring;
#ifndef __KERNEL__
  if(thiz->debug && ac_automata_global_debug) debug = 1;
  if(debug) {
      txt->option = debug;  /* for callback */
      printf("aho %s: search %.*s\n", thiz->name[0] ? thiz->name:"unknown", txt->length, apos);
  }
#endif
  match = &txt->match;
  memset((char*)match,0,sizeof(*match));

  /* The 'txt->ignore_case' option is checked
   * separately otherwise clang will detect
   * uninitialized memory usage much later. */
  if(txt->option & AC_FEATURE_LC) icase = 1;
  /* This is the main search loop.
   * it must be keep as lightweight as possible. */
  while (position < txt->length) {
      uint8_t alpha = (uint8_t)apos[position];
      if(thiz->to_lc) alpha = aho_lc[alpha];
      if(!(next = node_findbs_next_ac(curr, (uint8_t)alpha, icase))) {
          if(curr->failure_node) /* we are not in the root node */
            curr = curr->failure_node;
          else
            position++;
      } else {
          curr = next;
          position++;
          if(curr->final && curr->matched_patterns) {
              /* select best match */
              match->match_map = ac_automata_exact_match(curr->matched_patterns,position,txt);
              if(match->match_map) {
                  match->match_counter++; /* we have a matching */
#ifndef __KERNEL__
                  if(debug) {
                      int i;
                      AC_PATTERN_t *patterns = curr->matched_patterns->patterns;
                      for(i=0; i < curr->matched_patterns->num; i++) {
                          if(!(match->match_map & (1 << i))) continue;
                          printf("  match%d: %c%.*s%c [%u]\n",i+1,
                              patterns[i].rep.from_start ? '^':' ',
                              patterns[i].length,patterns[i].astring,
                              patterns[i].rep.at_end ? '$':' ',
                              patterns[i].rep.number);
                      }
                  }
#endif
                  if(thiz->match_handler) {
                      /* We check 'next' to find out if we came here after a alphabet
                       * transition or due to a fail. in second case we should not report
                       * matching because it was reported in previous node */
                      match->position = position;
                      match->match_num = curr->matched_patterns->num;
                      match->patterns = curr->matched_patterns->patterns;
                      if (thiz->match_handler(match, txt, param)) {
                          thiz->stats.n_found++;
                          return 1;
		      }
                  }
              } /* match->match_map */
          }
      }
  }
  if(thiz->match_handler) {
    if(match->match_counter > 0)
      thiz->stats.n_found++;
    return match->match_counter > 0 ? 1:0;
  }

  for(i = 0; i < 4; i++)
      if(txt->match.matched[i]) {
            *param = (txt->match.matched[i])->rep;
#ifndef __KERNEL__
            if(debug) {
                AC_PATTERN_t *pattern = txt->match.matched[i];
                printf("best match: %c%.*s%c [%u]\n",
                          pattern->rep.from_start ? '^':' ',
                          pattern->length,pattern->astring,
                          pattern->rep.at_end ? '$':' ',
                          pattern->rep.number);
            }
#endif
            thiz->stats.n_found++;
            return 1;
      }
  return 0;
}

/******************************************************************************
 * FUNCTION: ac_automata_release
 * Release all allocated memories to the automata
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * free_pattern: 
 *  0 - free all struct w/o free pattern
 *  1 - free all struct and pattern
 *  2 - clean struct w/o free pattern
 ******************************************************************************/

static AC_ERROR_t ac_automata_release_node(AC_AUTOMATA_t * thiz,
        AC_NODE_t *n, int idx, void *data) {

    if(!n->outgoing || idx) {
        if(n->outgoing) {
          if(n->one) thiz->n_oc--;
            else if(n->range) thiz->n_range--;
                  else thiz->n_find--;
        }
        node_release(n,data != NULL);
    }

    return ACERR_SUCCESS;
}
void ac_automata_release (AC_AUTOMATA_t * thiz, uint8_t free_pattern) {

    if(!thiz)
      return;

    ac_automata_walk(thiz,ac_automata_release_node,NULL,free_pattern ? (void *)1:NULL);

    if(free_pattern <= 1) {
        node_release(thiz->root,free_pattern | 0x4);
        thiz->root = NULL;
        acho_free(thiz);
    } else {
        AC_NODE_t *n;
        thiz->all_nodes_num  = 0;
        thiz->total_patterns = 0;
        thiz->max_str_len    = 0;
        thiz->automata_open  = 1;

        n = thiz->root;
        n->failure_node = NULL;
        n->id    = 0;
        n->final = 0;
        n->depth = 0;
        if(n->outgoing) {
            acho_free(n->outgoing);
            n->outgoing = NULL;
        }
        if(n->matched_patterns) {
            acho_free(n->matched_patterns);
            n->matched_patterns=NULL;
        }
        n->use = 0;
        n->one = 0;
    }
}

#ifndef __KERNEL__

static void dump_node_header(AC_NODE_t * n, struct aho_dump_info *ai) {
    char *c;
    int i;
    fprintf(ai->file,"%04d: ",n->id);
    if(n->failure_node) fprintf(ai->file," failure %04d:",n->failure_node->id);
    fprintf(ai->file," d:%d %c",n->depth, n->use ? '+':'-');
    ai->memcnt += sizeof(*n);
    if(n->matched_patterns) {
        ai->memcnt += sizeof(n->matched_patterns) + 
                n->matched_patterns->max*sizeof(n->matched_patterns->patterns[0]);
    }
    if(!n->use) { fprintf(ai->file,"\n"); return; }
    if(n->one) {
            (ai->node_oc)++;
            fprintf(ai->file," '%c' next->%d\n",n->one_alpha,
                n->outgoing ? ((AC_NODE_t *)n->outgoing)->id : -1);
            return;
    }
    if(!n->outgoing) {
            fprintf(ai->file," BUG! !outgoing\n");
            return;
    }
    fprintf(ai->file,"%s\n",n->range ? " RANGE":"");
    c = (char *)edge_get_alpha(n->outgoing);
    if(n->outgoing->degree <= 8)
            (ai->node_8c)++;
       else
            (ai->node_xc)++;
    if(n->range)
            (ai->node_xr)++;
    for(i=0; i < n->outgoing->degree; i++) {
            fprintf(ai->file,"  %d: \"%c\" -> %d\n",i,c[i],
                    n->outgoing->next[i] ? n->outgoing->next[i]->id:-1);
    }
    ai->memcnt += sizeof(n->outgoing) + edge_data_size(n->outgoing->max);
}

static AC_ERROR_t dump_node_common(AC_AUTOMATA_t * thiz,
        AC_NODE_t * n, int idx, void *data) {
    struct aho_dump_info *ai = (struct aho_dump_info *)data;
    char *rstr = ai->bufstr;

    if(idx) return ACERR_SUCCESS;
    dump_node_header(n,ai);
    if (n->matched_patterns && n->matched_patterns->num && n->final) {
        char lbuf[512];
        int nl = 0,j,ret;

        nl = ndpi_snprintf(lbuf,sizeof(lbuf),"'%.100s' N:%d{",rstr,n->matched_patterns->num);
        for (j=0; j<n->matched_patterns->num; j++) {
            AC_PATTERN_t *sid = &n->matched_patterns->patterns[j];
            if(j) {
                ret = ndpi_snprintf(&lbuf[nl],sizeof(lbuf)-nl-1,", ");
                if (ret < 0 || (unsigned int)ret >= sizeof(lbuf)-nl-1)
                    break;
                nl += (unsigned int)ret;
            }
            ret = ndpi_snprintf(&lbuf[nl],sizeof(lbuf)-nl-1,"%d %c%.100s%c",
                            sid->rep.number & 0x3fff,
                            sid->rep.number & 0x8000 ? '^':' ',
                            sid->astring,
                            sid->rep.number & 0x4000 ? '$':' ');
            if (ret < 0 || (unsigned int)ret >= sizeof(lbuf)-nl-1)
                break;
            nl += (unsigned int)ret;
        }
        fprintf(ai->file,"%s}\n",lbuf);
      }
    return ACERR_SUCCESS;
}
static void dump_node_str(AC_AUTOMATA_t * thiz, AC_NODE_t * node,
        AC_NODE_t * next, int idx, void *data) {
    struct aho_dump_info *ai = (struct aho_dump_info *)data;
    ai->bufstr[node->depth] = thiz->ac_path[node->depth].l;
    ai->bufstr[node->depth+1] = 0;
}

/******************************************************************************
 * FUNCTION: ac_automata_dump
 * Prints the automata to output in human readable form. it is useful for
 * debugging purpose.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * rstr: char[] buffer
 * rstr_size: size of rstr buffser
 * char repcast: 'n': print AC_REP_t as number, 's': print AC_REP_t as string
 ******************************************************************************/

void ac_automata_dump(AC_AUTOMATA_t * thiz, FILE *file) {
  struct aho_dump_info ai;

  if(!thiz) return;

  memset((char *)&ai,0,sizeof(ai));
  ai.file = file ? file : stdout;
  fprintf(ai.file,"---DUMP- all nodes %u - max strlen %u -%s---\n",
          (unsigned int)thiz->all_nodes_num,
          (unsigned int)thiz->max_str_len,
          thiz->automata_open ? "open":"ready");

  ai.bufstr = acho_malloc(AC_PATTRN_MAX_LENGTH+1);
  ai.bufstr_len = AC_PATTRN_MAX_LENGTH;
  if(!ai.bufstr) return;
  ai.bufstr[0] = '\0';

  ac_automata_walk(thiz,dump_node_common,dump_node_str,(void *)&ai);
#ifdef WIN32
  fprintf(ai.file,"---\n mem size %lu avg node size %d, node one char %d, <=8c %d, >8c %d, range %d\n---DUMP-END-\n",
              (long unsigned int)ai.memcnt,(int)ai.memcnt/(thiz->all_nodes_num+1),(int)ai.node_oc,(int)ai.node_8c,(int)ai.node_xc,(int)ai.node_xr);
#else
  fprintf(ai.file,"---\n mem size %zu avg node size %d, node one char %d, <=8c %d, >8c %d, range %d\n---DUMP-END-\n",
              ai.memcnt,(int)ai.memcnt/(thiz->all_nodes_num+1),(int)ai.node_oc,(int)ai.node_8c,(int)ai.node_xc,(int)ai.node_xr);
#endif
  acho_free(ai.bufstr);
}
#endif

/******************************************************************************
 * FUNCTION: ac_automata_union_matchstrs
 * Collect accepted patterns of the node. the accepted patterns consist of the
 * node's own accepted pattern plus accepted patterns of its failure node.
 ******************************************************************************/
static int ac_automata_union_matchstrs (AC_NODE_t * node)
{
  unsigned int i;
  AC_NODE_t * m;

  for (m = node; m; m = m->failure_node) {
      if(!m->matched_patterns) continue;

      for (i=0; i < m->matched_patterns->num; i++)
        if(node_register_matchstr(node, &(m->matched_patterns->patterns[i]), 1))
        return 1;

      if (m->final)
        node->final = 1;
    }
  return 0;
}

/******************************************************************************
 * FUNCTION: ac_automata_set_failure
 * find failure node for the given node.
 ******************************************************************************/
static void ac_automata_set_failure
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_NODE_t * next, int idx, void *data)
{
  unsigned int i, j;
  AC_NODE_t * m;
  struct ac_path * path = thiz->ac_path;

  for (i=1; i < next->depth; i++) {
        m = thiz->root;
        for (j=i; j < next->depth && m; j++) {
            m = node_find_next (m, path[j].l);
        }
        if (m) {
          next->failure_node = m;
          break;
        }
  }
  if (!next->failure_node)
    next->failure_node = thiz->root;
}

/******************************************************************************
 * FUNCTION: ac_automata_traverse_setfailure
 * Traverse all automata nodes using DFS (Depth First Search), meanwhile it set
 * the failure node for every node it passes through. this function must be
 * called after adding last pattern to automata. i.e. after calling this you
 * can not add further pattern to automata.
 ******************************************************************************/
static inline void ac_automata_traverse_setfailure (AC_AUTOMATA_t * thiz)
{
    ac_automata_walk(thiz,NULL,ac_automata_set_failure,NULL);
}

/******************************************************************************
 * FUNCTION: node_create
 * Create the node
 ******************************************************************************/
static inline AC_NODE_t * node_create(void)
{
  return  (AC_NODE_t *) acho_calloc (1,sizeof(AC_NODE_t));
}


static void node_release_pattern(AC_NODE_t * thiz)
{
  int i;
  AC_PATTERN_t * str;

    if(!thiz->matched_patterns) return;
    str = thiz->matched_patterns->patterns;

    for (i=0; i < thiz->matched_patterns->num; str++,i++)
    {
      if(!str->is_existing && str->astring) {
              acho_free(str->astring);
              str->astring = NULL;
      }
    }
}


/******************************************************************************
 * FUNCTION: node_release
 * Release node
 ******************************************************************************/
static void node_release(AC_NODE_t * thiz, int free_pattern)
{
  if(thiz->root && (free_pattern & 0x4) == 0) return;

  if(free_pattern & 1) node_release_pattern(thiz);
 
  if(thiz->matched_patterns) {
    acho_free(thiz->matched_patterns);
    thiz->matched_patterns = NULL;
  }
  if(!thiz->one && thiz->outgoing) {
    acho_free(thiz->outgoing);
  }
  thiz->outgoing = NULL;
  acho_free(thiz);
}

/* Nonzero if X is not aligned on a "long" boundary.  */
#undef UNALIGNED /* Windows defined it but differently from what Aho expects */
#define UNALIGNED(X) ((intptr_t)X & (__SIZEOF_LONG__ - 1))

#define LBLOCKSIZE __SIZEOF_LONG__ 

#if __SIZEOF_LONG__ == 4
#define DETECTNULL(X) (((X) - 0x01010101UL) & ~(X) & 0x80808080UL)
#define DUPC 0x01010101UL

static inline size_t bsf(uint32_t bits)
{
#ifdef __GNUC__
    return __builtin_ctz(bits);
#else
    size_t i=0;
    if(!bits) return i;
    if((bits & 0xffff) == 0) { i+=16; bits >>=16; }
    if((bits & 0xff) == 0) i+=8;
    return i;
#endif
}

#else
#define DETECTNULL(X) (((X) - 0x0101010101010101ULL) & ~(X) & 0x8080808080808080ULL)
#define DUPC 0x0101010101010101UL

static inline size_t bsf(uint64_t bits)
{
#ifdef __GNUC__
    return __builtin_ctzll(bits);
#else
    size_t i=0;
    if(!bits) return i;
    if((bits & 0xffffffff) == 0) { i+=32; bits >>=32; }
    if((bits & 0xffff) == 0) { i+=16; bits >>=16; }
    if((bits & 0xff) == 0) i+=8;
    return i;
#endif
}
#endif

static inline unsigned char *
xmemchr(unsigned char *s, unsigned char c,int n)
{
  while(n > 0) {
    if (n >= LBLOCKSIZE && !UNALIGNED (s)) {
      unsigned long int mask = c * DUPC;

      while (n >= LBLOCKSIZE) {
#if __SIZEOF_LONG__ == 4
        unsigned long int nc = DETECTNULL(le32toh(*(unsigned long int *)s) ^ mask);
#else
        unsigned long int nc = DETECTNULL(le64toh(*(unsigned long int *)s) ^ mask);
#endif
        if(nc)
            return s + (bsf(nc) >> 3);
        s += LBLOCKSIZE;
        n -= LBLOCKSIZE;
      }
      if(!n) return NULL;
    }
    if (*s == c) return s;
    s++;
    n--;
  }
  return NULL;
}


/******************************************************************************
 * FUNCTION: node_find_next
 * Find out the next node for a given Alpha to move. this function is used in
 * the pre-processing stage in which edge array is not sorted. so it uses
 * linear search.
 ******************************************************************************/
static AC_NODE_t * node_find_next(AC_NODE_t * thiz, AC_ALPHABET_t alpha)
{
  unsigned char *alphas, *fc;

  if(thiz->one) return alpha == thiz->one_alpha ? (AC_NODE_t *)thiz->outgoing:NULL;
  if(!thiz->outgoing) return NULL;

  alphas = (unsigned char *)edge_get_alpha(thiz->outgoing);
  fc = xmemchr(alphas,(unsigned char)alpha,thiz->outgoing->degree);
  return fc ? thiz->outgoing->next[fc-alphas] : NULL;
}


/******************************************************************************
 * FUNCTION: node_findbs_next
 * Find out the next node for a given Alpha. this function is used after the
 * pre-processing stage in which we sort edges. so it uses Binary Search.
 ******************************************************************************/

static inline AC_NODE_t *node_findbs_next (AC_NODE_t * thiz, uint8_t alpha)
{

  if(thiz->one)
        return alpha == thiz->one_alpha ? (AC_NODE_t *)thiz->outgoing:NULL;

  if(!(thiz->outgoing->cmap[(uint8_t)alpha >> 5] & (1u << (alpha & 0x1f))))
        return NULL;

  if(thiz->range)
        return thiz->outgoing->next[alpha - (uint8_t)thiz->one_alpha];

  return thiz->outgoing->next[
      xmemchr(thiz->a_ptr,alpha,thiz->outgoing->degree) - thiz->a_ptr];
}

static AC_NODE_t *node_findbs_next_ac (AC_NODE_t * thiz, uint8_t alpha,int icase) {
  AC_NODE_t *next;
  uint8_t alpha_c;

  if(!thiz->outgoing) return NULL;

  next = node_findbs_next(thiz,alpha);
  if(next || !icase) return next;

  alpha_c = aho_xc[alpha];
  if(!alpha_c) return NULL;
  return  node_findbs_next(thiz, alpha ^ alpha_c);
}

/******************************************************************************
 * FUNCTION: node_has_matchstr
 * Determine if a final node contains a pattern in its accepted pattern list
 * or not. return values: 1 = it has, 0 = it hasn't
 ******************************************************************************/
static int node_has_matchstr (AC_NODE_t * thiz, AC_PATTERN_t * newstr)
{
  int i;
  
  if(!thiz->matched_patterns) return 0;
  
  for (i=0; i < thiz->matched_patterns->num; i++)
  {
    AC_PATTERN_t *str = &(thiz->matched_patterns->patterns[i]);
    
    if (str->length != newstr->length)
      continue;
    
    if(!memcmp(str->astring,newstr->astring,str->length))
      return 1;    
  }
  
  return 0;
}

/******************************************************************************
 * FUNCTION: node_create_next
 * Create the next node for the given alpha.
 ******************************************************************************/
static AC_NODE_t * node_create_next (AC_NODE_t * thiz, AC_ALPHABET_t alpha)
{
  AC_NODE_t * next;
  next = node_find_next (thiz, alpha);
  if (next)
    /* The edge already exists */
    return NULL;
  /* Otherwise register new edge */
  next = node_create ();
  if(next) {
    if(node_register_outgoing(thiz, next, alpha)) {
        node_release(next,0);
        return NULL;
    }
    next->depth = thiz->depth+1;
  }

  return next;
}

static inline size_t mp_data_size(int n) {
    return sizeof(AC_PATTERNS_t) + n*sizeof(AC_PATTERN_t);
}

static AC_PATTERNS_t * node_resize_mp(AC_PATTERNS_t *m) {
AC_PATTERNS_t *new_m;

    if(!m) {
        m = acho_calloc(1,mp_data_size(REALLOC_CHUNK_MATCHSTR));
        if(!m) return m;
        m->max = REALLOC_CHUNK_MATCHSTR;
        return m;
    }
    new_m = acho_malloc(mp_data_size(m->max+REALLOC_CHUNK_MATCHSTR));
    if(!new_m) return new_m;
    memcpy((char *)new_m,(char *)m,mp_data_size(m->max));
    new_m->max += REALLOC_CHUNK_MATCHSTR;
    acho_free(m);
    return new_m;
}

/******************************************************************************
 * FUNCTION: node_register_matchstr
 * Adds the pattern to the list of accepted pattern.
 ******************************************************************************/
static int node_register_matchstr (AC_NODE_t * thiz, AC_PATTERN_t * str,int is_existing)
{
  AC_PATTERN_t *l;

  if(!is_existing)
      thiz->final = 1;
  /* Check if the new pattern already exists in the node list */
  if (thiz->matched_patterns && node_has_matchstr(thiz, str))
    return 0;

  if(!thiz->matched_patterns) {
    thiz->matched_patterns = node_resize_mp(thiz->matched_patterns);
    if(!thiz->matched_patterns)
      return 1;
  }

  /* Manage memory */
  if (thiz->matched_patterns->num >= thiz->matched_patterns->max) {
      AC_PATTERNS_t *new_mp = node_resize_mp(thiz->matched_patterns);
      if(!new_mp) return 1;
      thiz->matched_patterns = new_mp; 
    }
  l = &thiz->matched_patterns->patterns[thiz->matched_patterns->num];
  l->astring = str->astring;
  l->length  = str->length;
  l->is_existing = is_existing;
  l->rep = str->rep;
  thiz->matched_patterns->num++;
  return 0;
}

static struct edge *node_resize_outgoing(struct edge * e,size_t added) {
struct edge *new_e;
int ds;

    if(!added) added = REALLOC_CHUNK_OUTGOING;
    if(!e) {
        e = acho_calloc(1,sizeof(struct edge) + edge_data_size(REALLOC_CHUNK_OUTGOING));
        if(!e) return e;
        e->max = REALLOC_CHUNK_OUTGOING;
        return e;
    }
    ds = edge_data_size(e->max + added);
    new_e = acho_calloc(1,sizeof(struct edge) + ds);
    if(!new_e) return new_e;
    memcpy(new_e,e,sizeof(struct edge) + sizeof(AC_NODE_t *)*e->max);
    new_e->max += added;

    if(e->degree)
        memcpy(edge_get_alpha(new_e),edge_get_alpha(e),e->degree);

    acho_free(e);
    return new_e;
}

/******************************************************************************
 * FUNCTION: node_register_outgoing
 * Establish an edge between two nodes
 ******************************************************************************/
static int node_register_outgoing
(AC_NODE_t * thiz, AC_NODE_t * next, AC_ALPHABET_t alpha)
{
  struct edge *o;
  if(!thiz->use) {
        thiz->use = 1;
        thiz->one = 1;
        thiz->one_alpha = alpha;
        thiz->outgoing = (struct edge *)next;
        return 0;
  }
  if(thiz->one) {
        o = node_resize_outgoing(NULL,0);
        if(!o) return 1;
        o->next[0] = (AC_NODE_t *)thiz->outgoing;
        *edge_get_alpha(o) = thiz->one_alpha;
        o->degree = 1;
        thiz->one = 0;
        thiz->one_alpha = 0;
        thiz->outgoing = o;
  } else
        o = thiz->outgoing;

  if(!o) return 1;
 
  if(o->degree >= o->max)
    {
        struct edge *new_o = node_resize_outgoing(thiz->outgoing,0);
        if(!new_o) return 1;

        thiz->outgoing = new_o;
        o = new_o;
    }
  edge_get_alpha(o)[o->degree] = alpha;
  o->next[o->degree] = next;
  o->degree++;
  return 0;
}

/******************************************************************************
 * FUNCTION: node_edge_compare
 * Comparison function for qsort. see man qsort.
 ******************************************************************************/
static int node_edge_compare (struct edge * e, int a, int b) {
    unsigned char *c = (unsigned char *)edge_get_alpha(e);
    return c[a] >= c[b] ? 1:0;
}

static void node_edge_swap (struct edge * e, int a, int b)
{
AC_ALPHABET_t *c,tc;
AC_NODE_t *tn;
    c = edge_get_alpha(e);
    tc = c[a]; c[a] = c[b]; c[b] = tc;
    tn = e->next[a]; e->next[a] = e->next[b]; e->next[b] = tn;
}

/******************************************************************************
 * FUNCTION: acho_2range
 * Adds missing characters in the range low - high
 ******************************************************************************/
static void acho_2range(AC_NODE_t * thiz,uint8_t low, uint8_t high) {
    struct edge *e;
    int i;
    uint8_t *c = (uint8_t *)edge_get_alpha(thiz->outgoing);

    thiz->range = 1;
    thiz->one_alpha = (AC_ALPHABET_t)low;
    e = thiz->outgoing;
    for (i=0; low <= high && i < e->max; i++,low++) {
      if(e->cmap[(low >> 5) & 0x7] & (1u << (low & 0x1f))) continue;
      c[e->degree] = low;
      e->next[e->degree] = NULL;
      e->degree++;
    }
}

/******************************************************************************
 * FUNCTION: node_range_edges
 * Converts to a range if possible.
 ******************************************************************************/
static int node_range_edges (AC_AUTOMATA_t *thiz, AC_NODE_t * node)
{
    struct edge *e = node->outgoing;
    uint8_t *c = (uint8_t *)edge_get_alpha(node->outgoing);
    uint8_t low = 0xff,high = 0;
    int i;

    memset((char *)&e->cmap,0,sizeof(e->cmap));
    for(i = 0; i < e->degree; i++) {
      uint8_t cc = c[i];
      if(cc < low) low = cc;
      if(cc > high) high = cc;
      e->cmap[(cc >> 5) & 0x7] |= 1u << (cc & 0x1f);
    }
    if(high - low + 1 == e->degree) {
        node->range = 1;
        node->one_alpha = (AC_ALPHABET_t)low;
        return 1;
    }
    if(high - low + 1 < e->max) {
        acho_2range(node,low,high);
        return 1;
    }

    i = (high - low)/8;
    if (i < thiz->add_to_range) i = thiz->add_to_range;
    i += REALLOC_CHUNK_OUTGOING-1;
    i -= i % REALLOC_CHUNK_OUTGOING;

    if(high - low + 1 < e->max + i || (node->root && !thiz->no_root_range)) {
        int added = (high - low + 1) - e->max;
        struct edge *new_o = node_resize_outgoing(node->outgoing,added);
        if(new_o) {
            node->outgoing = new_o;
            acho_2range(node,low,high);
            return 1;
        }
        return 0;
    }

    return 0;
}
/******************************************************************************
 * FUNCTION: node_sort_edges
 * sorts edges alphabets.
 ******************************************************************************/
static inline void node_sort_edges (AC_NODE_t * thiz)
{

  acho_sort (thiz->outgoing, thiz->outgoing->degree, 
        node_edge_compare, node_edge_swap);
}

/**
 * sort - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp_func: pointer to comparison function
 * @swap_func: pointer to swap function or NULL
 *
 * This function does a heapsort on the given array. You may provide a
 * swap_func function optimized to your element type.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * qsort is about 20% faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */

 void acho_sort(struct edge *e, size_t num,
      int (*cmp_func)(struct edge *e, int a, int b),
      void (*swap_func)(struct edge *e, int a, int b))
{
  /* pre-scale counters for performance */
  int i = (num/2 - 1) , n = num, c, r;

  if (!swap_func) return;
  if (!cmp_func) return;

  /* heapify */
  for ( ; i >= 0; i -= 1) {
    for (r = i; r * 2 + 1 < n; r = c) {
      c = r * 2 + 1;
      if (c < n - 1 && cmp_func(e, c, c + 1) == 0)
            c += 1;
      if (cmp_func(e, r, c) != 0)
            break;
      swap_func(e, r, c);
    }
  }

  /* sort */
  for (i = n - 1; i > 0; i -= 1) {
    swap_func(e,0,i);
    for (r = 0; r * 2 + 1 < i; r = c) {
      c = r * 2 + 1;
      if (c < i - 1 && cmp_func(e, c, c + 1) == 0)
        c += 1;
      if (cmp_func(e, r, c) != 0)
        break;
      swap_func(e, r, c);
    }
  }
}

void ac_automata_get_stats(AC_AUTOMATA_t * thiz, struct ac_stats *stats)
{
  if (thiz) {
    stats->n_search = thiz->stats.n_search;
    stats->n_found = thiz->stats.n_found;
  } else {
    stats->n_search = 0;
    stats->n_found = 0;
  }
}

/* vim: set ts=4 sw=4 et :  */

