/*
 * ahocorasick.c: implementation of ahocorasick library's functions
 * This file is part of multifast.
 *
 Copyright 2010-2012 Kamiar Kanani <kamiar.kanani@gmail.com>
 Copyright 2012-2019 ntop.org (Incremental improvements)
 
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ndpi_api.h"
#include "ahocorasick.h"

/* Allocation step for automata.all_nodes */
#define REALLOC_CHUNK_ALLNODES 200

/* Private function prototype */
static void ac_automata_register_nodeptr
(AC_AUTOMATA_t * thiz, AC_NODE_t * node);
static void ac_automata_union_matchstrs
(AC_NODE_t * node);
static void ac_automata_set_failure
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_ALPHABET_t * alphas);
static void ac_automata_traverse_setfailure
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_ALPHABET_t * alphas);


/******************************************************************************
 * FUNCTION: ac_automata_init
 * Initialize automata; allocate memories and set initial values
 * PARAMS:
 * MATCH_CALLBACK mc: call-back function
 * the call-back function will be used to reach the caller on match occurrence
 ******************************************************************************/
AC_AUTOMATA_t * ac_automata_init (MATCH_CALLBACK_f mc)
{
  AC_AUTOMATA_t * thiz = (AC_AUTOMATA_t *)ndpi_malloc(sizeof(AC_AUTOMATA_t));
  memset (thiz, 0, sizeof(AC_AUTOMATA_t));
  thiz->root = node_create ();
  thiz->all_nodes_max = REALLOC_CHUNK_ALLNODES;
  thiz->all_nodes = (AC_NODE_t **) ndpi_malloc (thiz->all_nodes_max*sizeof(AC_NODE_t *));
  thiz->match_callback = mc;
  ac_automata_register_nodeptr (thiz, thiz->root);
  thiz->total_patterns = 0;
  thiz->automata_open = 1;
  return thiz;
}

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
  AC_NODE_t * n = thiz->root;
  AC_NODE_t * next;
  AC_ALPHABET_t alpha;

  if(!thiz->automata_open)
    return ACERR_AUTOMATA_CLOSED;

  if (!patt->length)
    return ACERR_ZERO_PATTERN;

  if (patt->length > AC_PATTRN_MAX_LENGTH)
    return ACERR_LONG_PATTERN;

  for (i=0; i<patt->length; i++)
  {
    alpha = patt->astring[i];
    if ((next = node_find_next(n, alpha)))
    {
      n = next;
      continue;
    }
    else
    {
      next = node_create_next(n, alpha);
      next->depth = n->depth + 1;
      n = next;
      ac_automata_register_nodeptr(thiz, n);
    }
  }

  if(n->final) {
#if 0
    /* Original code */
    return ACERR_DUPLICATE_PATTERN;
#else
    /* ntop */
    memcpy(&n->matched_patterns->rep, &patt->rep, sizeof(AC_REP_t));
    return ACERR_SUCCESS;
#endif
  }
      
  n->final = 1;
  node_register_matchstr(n, patt, 0);
  thiz->total_patterns++;

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
void ac_automata_finalize (AC_AUTOMATA_t * thiz)
{
  unsigned int i;
  AC_ALPHABET_t *alphas;
  AC_NODE_t * node;

  if((alphas = ndpi_malloc(AC_PATTRN_MAX_LENGTH)) != NULL) {
    ac_automata_traverse_setfailure (thiz, thiz->root, alphas);

    for (i=0; i < thiz->all_nodes_num; i++)
    {
      node = thiz->all_nodes[i];
      ac_automata_union_matchstrs (node);
      node_sort_edges (node);
    }
    thiz->automata_open = 0; /* do not accept patterns any more */
    ndpi_free(alphas);
  }
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
int ac_automata_search (AC_AUTOMATA_t * thiz, AC_TEXT_t * txt, AC_REP_t * param) {
  unsigned long position;
  AC_NODE_t *curr;
  AC_NODE_t *next;
  AC_SEARCH_t s;
  
  if(thiz->automata_open)
    /* you must call ac_automata_locate_failure() first */
    return -1;

  /* Reset search */
  s.current_node = thiz->root;
  s.base_position = 0;

  position = 0;
  curr = s.current_node;

  /* This is the main search loop.
   * it must be keep as lightweight as possible. */
  while (position < txt->length) {
    if(!(next = node_findbs_next(curr, txt->astring[position]))) {
      if(curr->failure_node /* we are not in the root node */)
	curr = curr->failure_node;
      else
	position++;
    } else {
      curr = next;
      position++;
    }

    if(curr->final && next) {
      /* We check 'next' to find out if we came here after a alphabet
       * transition or due to a fail. in second case we should not report
       * matching because it was reported in previous node */
      thiz->match.position = position + s.base_position;
      thiz->match.match_num = curr->matched_patterns_num;
      thiz->match.patterns = curr->matched_patterns;
      /* we found a match! do call-back */
      if (thiz->match_callback(&thiz->match, txt, param))
	return 1;
    }
  }

  return 0;
}

/******************************************************************************
 * FUNCTION: ac_automata_release
 * Release all allocated memories to the automata
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * uint8_t free_pattern: if true, deallocate the patterns strings
 ******************************************************************************/
void ac_automata_release (AC_AUTOMATA_t * thiz, u_int8_t free_pattern)
{
  unsigned int i;
  AC_NODE_t * n;

  for (i=0; i < thiz->all_nodes_num; i++)
  {
    n = thiz->all_nodes[i];
    node_release(n, free_pattern);
  }
  ndpi_free(thiz->all_nodes);
  ndpi_free(thiz);
}

/******************************************************************************
 * FUNCTION: ac_automata_display
 * Prints the automata to output in human readable form. it is useful for
 * debugging purpose.
 * PARAMS:
 * AC_AUTOMATA_t * thiz: the pointer to the automata
 * char repcast: 'n': print AC_REP_t as number, 's': print AC_REP_t as string
 ******************************************************************************/
void ac_automata_display (AC_AUTOMATA_t * thiz, char repcast)
{
  unsigned int i, j;
  AC_NODE_t * n;
  struct edge * e;
  AC_PATTERN_t sid;

  printf("---------------------------------\n");

  for (i=0; i<thiz->all_nodes_num; i++)
  {
    n = thiz->all_nodes[i];
    printf("NODE(%3d)/----fail----> NODE(%3d)\n",
	   n->id, (n->failure_node)?n->failure_node->id:1);
    for (j=0; j<n->outgoing_degree; j++)
    {
      e = &n->outgoing[j];
      printf("         |----(");
      if(isgraph(e->alpha))
	printf("%c)---", e->alpha);
      else
	printf("0x%x)", e->alpha);
      printf("--> NODE(%3d)\n", e->next->id);
    }
    if (n->matched_patterns_num) {
      printf("Accepted patterns: {");
      for (j=0; j<n->matched_patterns_num; j++)
      {
	sid = n->matched_patterns[j];
	if(j) printf(", ");
	switch (repcast)
	{
	case 'n':
	  printf("%u/%u/%u",
		 sid.rep.number,
		 sid.rep.category,
		 sid.rep.breed);
	  break;
	}
      }
      printf("}\n");
    }
    printf("---------------------------------\n");
  }
}

/******************************************************************************
 * FUNCTION: ac_automata_register_nodeptr
 * Adds the node pointer to all_nodes.
 ******************************************************************************/
static void ac_automata_register_nodeptr (AC_AUTOMATA_t * thiz, AC_NODE_t * node)
{
  if(thiz->all_nodes_num >= thiz->all_nodes_max)
  {
    thiz->all_nodes = ndpi_realloc(thiz->all_nodes,
				   thiz->all_nodes_max*sizeof(AC_NODE_t *),
				   (REALLOC_CHUNK_ALLNODES+thiz->all_nodes_max)*sizeof(AC_NODE_t *)
      );
    thiz->all_nodes_max += REALLOC_CHUNK_ALLNODES;
  }
  thiz->all_nodes[thiz->all_nodes_num++] = node;
}

/******************************************************************************
 * FUNCTION: ac_automata_union_matchstrs
 * Collect accepted patterns of the node. the accepted patterns consist of the
 * node's own accepted pattern plus accepted patterns of its failure node.
 ******************************************************************************/
static void ac_automata_union_matchstrs (AC_NODE_t * node)
{
  unsigned int i;
  AC_NODE_t * m = node;

  while ((m = m->failure_node))
  {
    for (i=0; i < m->matched_patterns_num; i++)
      node_register_matchstr(node, &(m->matched_patterns[i]), 1 /* this is an existing node */);

    if (m->final)
      node->final = 1;
  }
  // TODO : sort matched_patterns? is that necessary? I don't think so.
}

/******************************************************************************
 * FUNCTION: ac_automata_set_failure
 * find failure node for the given node.
 ******************************************************************************/
static void ac_automata_set_failure
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_ALPHABET_t * alphas)
{
  unsigned int i, j;
  AC_NODE_t * m;

  for (i=1; i < node->depth; i++)
  {
    m = thiz->root;
    for (j=i; j < node->depth && m; j++)
      m = node_find_next (m, alphas[j]);
    if (m)
    {
      node->failure_node = m;
      break;
    }
  }
  if (!node->failure_node)
    node->failure_node = thiz->root;
}

/******************************************************************************
 * FUNCTION: ac_automata_traverse_setfailure
 * Traverse all automata nodes using DFS (Depth First Search), meanwhile it set
 * the failure node for every node it passes through. this function must be
 * called after adding last pattern to automata. i.e. after calling this you
 * can not add further pattern to automata.
 ******************************************************************************/
static void ac_automata_traverse_setfailure
(AC_AUTOMATA_t * thiz, AC_NODE_t * node, AC_ALPHABET_t * alphas)
{
  unsigned int i;
  AC_NODE_t * next;

  for (i=0; i < node->outgoing_degree; i++) {
    alphas[node->depth] = node->outgoing[i].alpha;
    next = node->outgoing[i].next;

    /* At every node look for its failure node */
    ac_automata_set_failure (thiz, next, alphas);

    /* Recursively call itself to traverse all nodes */
    ac_automata_traverse_setfailure (thiz, next, alphas);
  }
}
