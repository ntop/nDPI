/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ball.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: elee <elee@student.42.us.org>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/06/28 10:55:27 by elee              #+#    #+#             */
/*   Updated: 2017/06/28 20:56:18 by elee             ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef BALL_H
# define BALL_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <limits.h>
# include <math.h>
# include <float.h>
# include <sys/stat.h>
# include <time.h>

# define TRUE 1
# define FALSE 0

typedef struct s_data
{
  int   n_neighbors;
  int   leaf_size;
  double  **data;
  int   n_samples;
  int   n_features;
} t_data;

typedef struct s_nheap
{
  double  **distances;
  int   **indices;
  int   n_pts;
  int   n_nbrs;
} t_nheap;

#if 0
/* See ndpi_typedefs.h */
typedef struct s_knn
{
  double  **distances;
  int   **indices;
  int   n_samples;
  int   n_neighbors;
} ndpi_knn;
#endif

typedef struct s_nodedata
{
  int   idx_start;
  int   idx_end;
  int   is_leaf;
  double  radius;
} t_nodedata;

typedef struct s_btree
{
  double  **data;
  int   *idx_array;
  t_nodedata *node_data;
  double  ***node_bounds;

  int   n_samples;
  int   n_features;

  int   leaf_size;
  int   n_levels;
  int   n_nodes;
} t_btree;


/*
** metrics.c
*/

double manhattan_dist(double *x1, double *x2, int size);
double min_dist(t_btree *tree, int i_node, double *pt);

/*
** neighbors_heap.c
*/

t_nheap *nheap_init(int n_pts, int n_nbrs);
double nheap_largest(t_nheap *h, int row);
int  nheap_push(t_nheap *h, int row, double val, int i_val);
ndpi_knn nheap_get_arrays(t_nheap *h);

/*
** ball.c
*/

t_btree *btree_init(double **data, int n_samples, int n_features, int leaf_size);
ndpi_knn btree_query(t_btree *b, double **x, int n_samples, int n_features, int k);
void free_2d_double(double **arr, int row);
void free_2d_int(int **arr, int row);
void free_tree(t_btree *tree);
void free_knn(ndpi_knn knn, int row);

#endif
