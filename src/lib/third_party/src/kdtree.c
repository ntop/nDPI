/*
  Code taken from https://github.com/jtsiomb/kdtree

  See https://www.cs.cmu.edu/~ckingsf/bioinfo-lectures/kdtrees.pdf for details
  
  for high cardinalities, KD-trees are outpaced by
  - https://github.com/nmslib/hnswlib
  - https://en.wikipedia.org/wiki/Hierarchical_navigable_small_world  
*/
/*
  This file is part of ``kdtree'', a library for working with kd-trees.
  Copyright (C) 2007-2011 John Tsiombikas <nuclear@member.fsf.org>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
  EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
  OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
  OF SUCH DAMAGE.
*/
/* single nearest neighbor search written by Tamas Nepusz <tamas@cs.rhul.ac.uk> */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "kdtree.h"

#if defined(WIN32) || defined(__WIN32__)
#include <malloc.h>
#endif

#ifdef USE_LIST_NODE_ALLOCATOR

#ifndef NO_PTHREADS
#include <pthread.h>
#else

#ifndef I_WANT_THREAD_BUGS
#error "You are compiling with the fast list node allocator, with pthreads disabled! This WILL break if used from multiple threads."
#endif	/* I want thread bugs */

#endif	/* pthread support */
#endif	/* use list node allocator */

#include "ndpi_api.h"

struct kdhyperrect {
  int dim;
  double *min, *max;              /* minimum/maximum coords */
};

struct kdnode {
  double *pos;
  int dir;
  void *data;

  struct kdnode *left, *right;	/* negative/positive side */
};

struct res_node {
  struct kdnode *item;
  double dist_sq;
  struct res_node *next;
};

struct kdtree {
  int dim;
  struct kdnode *root;
  struct kdhyperrect *rect;
  void (*destr)(void*);
};

struct kdres {
  struct kdtree *tree;
  struct res_node *rlist, *riter;
  int size;
};

#define SQ(x)			((x) * (x))


static void clear_rec(struct kdnode *node, void (*destr)(void*));
static int insert_rec(struct kdnode **node, const double *pos, void *data, int dir, int dim);
static int rlist_insert(struct res_node *list, struct kdnode *item, double dist_sq);
static void clear_results(struct kdres *set);

static struct kdhyperrect* hyperrect_create(int dim, const double *min, const double *max);
static void hyperrect_free(struct kdhyperrect *rect);
static struct kdhyperrect* hyperrect_duplicate(const struct kdhyperrect *rect);
static void hyperrect_extend(struct kdhyperrect *rect, const double *pos);
static double hyperrect_dist_sq(struct kdhyperrect *rect, const double *pos);

#ifdef USE_LIST_NODE_ALLOCATOR
static struct res_node *alloc_resnode(void);
static void free_resnode(struct res_node*);
#else
#define alloc_resnode()		ndpi_malloc(sizeof(struct res_node))
#define free_resnode(n)		ndpi_free(n)
#endif



struct kdtree *kd_create(int k)
{
  struct kdtree *tree;

  if(!(tree = ndpi_malloc(sizeof *tree))) {
    return 0;
  }

  tree->dim = k;
  tree->root = 0;
  tree->destr = 0;
  tree->rect = 0;

  return tree;
}

void kd_free(struct kdtree *tree)
{
  if(tree) {
    kd_clear(tree);
    ndpi_free(tree);
  }
}

static void clear_rec(struct kdnode *node, void (*destr)(void*))
{
  if(!node) return;

  clear_rec(node->left, destr);
  clear_rec(node->right, destr);

  if(destr) {
    destr(node->data);
  }
  ndpi_free(node->pos);
  ndpi_free(node);
}

void kd_clear(struct kdtree *tree)
{
  if (!tree)
    return;

  clear_rec(tree->root, tree->destr);
  tree->root = 0;

  if (tree->rect) {
    hyperrect_free(tree->rect);
    tree->rect = 0;
  }
}

void kd_data_destructor(struct kdtree *tree, void (*destr)(void*))
{
  tree->destr = destr;
}


static int insert_rec(struct kdnode **nptr, const double *pos, void *data, int dir, int dim)
{
  int new_dir;
  struct kdnode *node;

  if(!*nptr) {
    if(!(node = ndpi_malloc(sizeof *node))) {
      return -1;
    }
    if(!(node->pos = ndpi_malloc(dim * sizeof(double)))) {
      ndpi_free(node);
      return -1;
    }
    memcpy(node->pos, pos, dim * sizeof(double));
    node->data = data;
    node->dir = dir;
    node->left = node->right = 0;
    *nptr = node;
    return 0;
  }

  node = *nptr;
  new_dir = (node->dir + 1) % dim;
  if(pos[node->dir] < node->pos[node->dir]) {
    return insert_rec(&(*nptr)->left, pos, data, new_dir, dim);
  }
  return insert_rec(&(*nptr)->right, pos, data, new_dir, dim);
}

int kd_insert(struct kdtree *tree, const double *pos, void *data)
{
  if (!tree)
    return -1;

  if (insert_rec(&tree->root, pos, data, 0, tree->dim)) {
    return -1;
  }

  if (tree->rect == 0) {
    tree->rect = hyperrect_create(tree->dim, pos, pos);
  } else {
    hyperrect_extend(tree->rect, pos);
  }

  return 0;
}

static int find_nearest(struct kdnode *node, const double *pos, double range, struct res_node *list, int ordered, int dim)
{
  double dist_sq, dx;
  int i, ret, added_res = 0;

  if(!node) return 0;

  dist_sq = 0;
  for(i=0; i<dim; i++) {
    dist_sq += SQ(node->pos[i] - pos[i]);
  }
  if(dist_sq <= SQ(range)) {
    if(rlist_insert(list, node, ordered ? dist_sq : -1.0) == -1) {
      return -1;
    }
    added_res = 1;
  }

  dx = pos[node->dir] - node->pos[node->dir];

  ret = find_nearest(dx <= 0.0 ? node->left : node->right, pos, range, list, ordered, dim);
  if(ret >= 0 && fabs(dx) < range) {
    added_res += ret;
    ret = find_nearest(dx <= 0.0 ? node->right : node->left, pos, range, list, ordered, dim);
  }
  if(ret == -1) {
    return -1;
  }
  added_res += ret;

  return added_res;
}

#if 0
static int find_nearest_n(struct kdnode *node, const double *pos, double range, int num, struct rheap *heap, int dim)
{
  double dist_sq, dx;
  int i, ret, added_res = 0;

  if(!node) return 0;

  /* if the photon is close enough, add it to the result heap */
  dist_sq = 0;
  for(i=0; i<dim; i++) {
    dist_sq += SQ(node->pos[i] - pos[i]);
  }
  if(dist_sq <= range_sq) {
    if(heap->size >= num) {
      /* get furthest element */
      struct res_node *maxelem = rheap_get_max(heap);

      /* and check if the new one is closer than that */
      if(maxelem->dist_sq > dist_sq) {
	rheap_remove_max(heap);

	if(rheap_insert(heap, node, dist_sq) == -1) {
	  return -1;
	}
	added_res = 1;

	range_sq = dist_sq;
      }
    } else {
      if(rheap_insert(heap, node, dist_sq) == -1) {
	return =1;
      }
      added_res = 1;
    }
  }


  /* find signed distance from the splitting plane */
  dx = pos[node->dir] - node->pos[node->dir];

  ret = find_nearest_n(dx <= 0.0 ? node->left : node->right, pos, range, num, heap, dim);
  if(ret >= 0 && fabs(dx) < range) {
    added_res += ret;
    ret = find_nearest_n(dx <= 0.0 ? node->right : node->left, pos, range, num, heap, dim);
  }

}
#endif

static void kd_nearest_i(struct kdnode *node, const double *pos, struct kdnode **result, double *result_dist_sq, struct kdhyperrect* rect)
{
  int dir = node->dir;
  int i;
  double dummy, dist_sq;
  struct kdnode *nearer_subtree, *farther_subtree;
  double *nearer_hyperrect_coord, *farther_hyperrect_coord;

  /* Decide whether to go left or right in the tree */
  dummy = pos[dir] - node->pos[dir];
  if (dummy <= 0) {
    nearer_subtree = node->left;
    farther_subtree = node->right;
    nearer_hyperrect_coord = rect->max + dir;
    farther_hyperrect_coord = rect->min + dir;
  } else {
    nearer_subtree = node->right;
    farther_subtree = node->left;
    nearer_hyperrect_coord = rect->min + dir;
    farther_hyperrect_coord = rect->max + dir;
  }

  if (nearer_subtree) {
    /* Slice the hyperrect to get the hyperrect of the nearer subtree */
    dummy = *nearer_hyperrect_coord;
    *nearer_hyperrect_coord = node->pos[dir];
    /* Recurse down into nearer subtree */
    kd_nearest_i(nearer_subtree, pos, result, result_dist_sq, rect);
    /* Undo the slice */
    *nearer_hyperrect_coord = dummy;
  }

  /* Check the distance of the point at the current node, compare it
   * with our best so far */
  dist_sq = 0;
  for(i=0; i < rect->dim; i++) {
    dist_sq += SQ(node->pos[i] - pos[i]);
  }
  if (dist_sq < *result_dist_sq) {
    *result = node;
    *result_dist_sq = dist_sq;
  }

  if (farther_subtree) {
    /* Get the hyperrect of the farther subtree */
    dummy = *farther_hyperrect_coord;
    *farther_hyperrect_coord = node->pos[dir];
    /* Check if we have to recurse down by calculating the closest
     * point of the hyperrect and see if it's closer than our
     * minimum distance in result_dist_sq. */
    if (hyperrect_dist_sq(rect, pos) < *result_dist_sq) {
      /* Recurse down into farther subtree */
      kd_nearest_i(farther_subtree, pos, result, result_dist_sq, rect);
    }
    /* Undo the slice on the hyperrect */
    *farther_hyperrect_coord = dummy;
  }
}

struct kdres *kd_nearest(struct kdtree *kd, const double *pos)
{
  struct kdhyperrect *rect;
  struct kdnode *result;
  struct kdres *rset;
  double dist_sq;
  int i;

  if (!kd) return 0;
  if (!kd->rect) return 0;

  /* Allocate result set */
  if(!(rset = ndpi_malloc(sizeof *rset))) {
    return 0;
  }
  if(!(rset->rlist = alloc_resnode())) {
    ndpi_free(rset);
    return 0;
  }
  rset->rlist->next = 0;
  rset->tree = kd;

  /* Duplicate the bounding hyperrectangle, we will work on the copy */
  if (!(rect = hyperrect_duplicate(kd->rect))) {
    kd_res_free(rset);
    return 0;
  }

  /* Our first guesstimate is the root node */
  result = kd->root;
  dist_sq = 0;
  for (i = 0; i < kd->dim; i++)
    dist_sq += SQ(result->pos[i] - pos[i]);

  /* Search for the nearest neighbour recursively */
  kd_nearest_i(kd->root, pos, &result, &dist_sq, rect);

  /* Free the copy of the hyperrect */
  hyperrect_free(rect);

  /* Store the result */
  if (result) {
    if (rlist_insert(rset->rlist, result, -1.0) == -1) {
      kd_res_free(rset);
      return 0;
    }
    rset->size = 1;
    kd_res_rewind(rset);
    return rset;
  } else {
    kd_res_free(rset);
    return 0;
  }
}

/* ---- nearest N search ---- */
/*
  static kdres *kd_nearest_n(struct kdtree *kd, const double *pos, int num)
  {
  int ret;
  struct kdres *rset;

  if(!(rset = ndpi_malloc(sizeof *rset))) {
  return 0;
  }
  if(!(rset->rlist = alloc_resnode())) {
  ndpi_free(rset);
  return 0;
  }
  rset->rlist->next = 0;
  rset->tree = kd;

  if((ret = find_nearest_n(kd->root, pos, range, num, rset->rlist, kd->dim)) == -1) {
  kd_res_free(rset);
  return 0;
  }
  rset->size = ret;
  kd_res_rewind(rset);
  return rset;
  }*/

struct kdres *kd_nearest_range(struct kdtree *kd, const double *pos, double range)
{
  int ret;
  struct kdres *rset;

  if(!(rset = ndpi_malloc(sizeof *rset))) {
    return 0;
  }
  if(!(rset->rlist = alloc_resnode())) {
    ndpi_free(rset);
    return 0;
  }
  rset->rlist->next = 0;
  rset->tree = kd;

  if((ret = find_nearest(kd->root, pos, range, rset->rlist, 0, kd->dim)) == -1) {
    kd_res_free(rset);
    return 0;
  }
  rset->size = ret;
  kd_res_rewind(rset);
  return rset;
}

void kd_res_free(struct kdres *rset)
{
  clear_results(rset);
  free_resnode(rset->rlist);
  ndpi_free(rset);
}

int kd_res_size(struct kdres *set)
{
  return (set->size);
}

void kd_res_rewind(struct kdres *rset)
{
  rset->riter = rset->rlist->next;
}

int kd_res_end(struct kdres *rset)
{
  return rset->riter == 0;
}

int kd_res_next(struct kdres *rset)
{
  rset->riter = rset->riter->next;
  return rset->riter != 0;
}

double *kd_res_item(struct kdres *rset, double **user_data)
{
  if(rset->riter) {
    if(user_data)
      *user_data = rset->riter->item->data;
    
    return(rset->riter->item->pos);
  }
  
  return NULL;
}

void *kd_res_item_data(struct kdres *set)
{
  return kd_res_item(set, 0);
}

/* ---- hyperrectangle helpers ---- */
static struct kdhyperrect* hyperrect_create(int dim, const double *min, const double *max)
{
  size_t size = dim * sizeof(double);
  struct kdhyperrect* rect = 0;

  if (!(rect = ndpi_malloc(sizeof(struct kdhyperrect)))) {
    return 0;
  }

  rect->dim = dim;
  if (!(rect->min = ndpi_malloc(size))) {
    ndpi_free(rect);
    return 0;
  }
  if (!(rect->max = ndpi_malloc(size))) {
    ndpi_free(rect->min);
    ndpi_free(rect);
    return 0;
  }
  memcpy(rect->min, min, size);
  memcpy(rect->max, max, size);

  return rect;
}

static void hyperrect_free(struct kdhyperrect *rect)
{
  ndpi_free(rect->min);
  ndpi_free(rect->max);
  ndpi_free(rect);
}

static struct kdhyperrect* hyperrect_duplicate(const struct kdhyperrect *rect)
{
  return hyperrect_create(rect->dim, rect->min, rect->max);
}

static void hyperrect_extend(struct kdhyperrect *rect, const double *pos)
{
  int i;

  for (i=0; i < rect->dim; i++) {
    if (pos[i] < rect->min[i]) {
      rect->min[i] = pos[i];
    }
    if (pos[i] > rect->max[i]) {
      rect->max[i] = pos[i];
    }
  }
}

static double hyperrect_dist_sq(struct kdhyperrect *rect, const double *pos)
{
  int i;
  double result = 0;

  for (i=0; i < rect->dim; i++) {
    if (pos[i] < rect->min[i]) {
      result += SQ(rect->min[i] - pos[i]);
    } else if (pos[i] > rect->max[i]) {
      result += SQ(rect->max[i] - pos[i]);
    }
  }

  return result;
}

/* ---- static helpers ---- */

#ifdef USE_LIST_NODE_ALLOCATOR
/* special list node allocators. */
static struct res_node *free_nodes;

#ifndef NO_PTHREADS
static pthread_mutex_t alloc_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static struct res_node *alloc_resnode(void)
{
  struct res_node *node;

#ifndef NO_PTHREADS
  pthread_mutex_lock(&alloc_mutex);
#endif

  if(!free_nodes) {
    node = ndpi_malloc(sizeof *node);
  } else {
    node = free_nodes;
    free_nodes = free_nodes->next;
    node->next = 0;
  }

#ifndef NO_PTHREADS
  pthread_mutex_unlock(&alloc_mutex);
#endif

  return node;
}

static void free_resnode(struct res_node *node)
{
#ifndef NO_PTHREADS
  pthread_mutex_lock(&alloc_mutex);
#endif

  node->next = free_nodes;
  free_nodes = node;

#ifndef NO_PTHREADS
  pthread_mutex_unlock(&alloc_mutex);
#endif
}
#endif	/* list node allocator or not */


/* inserts the item. if dist_sq is >= 0, then do an ordered insert */
/* TODO make the ordering code use heapsort */
static int rlist_insert(struct res_node *list, struct kdnode *item, double dist_sq)
{
  struct res_node *rnode;

  if(!(rnode = alloc_resnode())) {
    return -1;
  }
  rnode->item = item;
  rnode->dist_sq = dist_sq;

  if(dist_sq >= 0.0) {
    while(list->next && list->next->dist_sq < dist_sq) {
      list = list->next;
    }
  }
  rnode->next = list->next;
  list->next = rnode;
  return 0;
}

static void clear_results(struct kdres *rset)
{
  struct res_node *tmp, *node = rset->rlist->next;

  while(node) {
    tmp = node;
    node = node->next;
    free_resnode(tmp);
  }

  rset->rlist->next = 0;
}
