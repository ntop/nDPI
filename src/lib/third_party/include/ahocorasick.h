/*
 * ahocorasick.h: the main ahocorasick header file.
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

#ifndef _AUTOMATA_H_
#define _AUTOMATA_H_

#include "node.h"

typedef struct
{
  /* The root of the Aho-Corasick trie */
  AC_NODE_t * root;

  /* maintain all nodes pointers. it will be used to access or release
   * all nodes. */
  AC_NODE_t ** all_nodes;

  unsigned int all_nodes_num; /* Number of all nodes in the automata */
  unsigned int all_nodes_max; /* Current max allocated memory for *all_nodes */

  AC_MATCH_t match; /* Any match is reported with this */
  MATCH_CALBACK_f match_callback; /* Match call-back function */

  /* this flag indicates that if automata is finalized by
   * ac_automata_finalize() or not. 1 means finalized and 0
   * means not finalized (is open). after finalizing automata you can not
   * add pattern to automata anymore. */
  unsigned short automata_open;

  /* It is possible to feed a large input to the automata chunk by chunk to
   * be searched using ac_automata_search(). in fact by default automata
   * thinks that all chunks are related unless you do ac_automata_reset().
   * followings are variables that keep track of searching state. */
  AC_NODE_t * current_node; /* Pointer to current node while searching */
  unsigned long base_position; /* Represents the position of current chunk
				  related to whole input text */

  /* Statistic Variables */
  unsigned long total_patterns; /* Total patterns in the automata */

} AC_AUTOMATA_t;


AC_AUTOMATA_t * ac_automata_init     (MATCH_CALBACK_f mc);
AC_ERROR_t      ac_automata_add      (AC_AUTOMATA_t * thiz, AC_PATTERN_t * str);
void            ac_automata_finalize (AC_AUTOMATA_t * thiz);
int             ac_automata_search   (AC_AUTOMATA_t * thiz, AC_TEXT_t * str, void * param);
void            ac_automata_reset    (AC_AUTOMATA_t * thiz);
void            ac_automata_release  (AC_AUTOMATA_t * thiz);
void            ac_automata_display  (AC_AUTOMATA_t * thiz, char repcast);

#endif
