/*
 * Isolation Forest Anomaly Detection
 *
 * Copyright (C) 2026 - ntop.org
 *
 */

#ifndef _ISOLATION_FOREST_H
#define _ISOLATION_FOREST_H

#include <stddef.h>

#define MAX_DEPTH 10
#define N_TREES   100

typedef struct Node {
  double *normal_vector; // Random slope for EIF
  double intercept;      // Random split point
  struct Node *left, *right;
  int is_leaf, depth;
} Node;

typedef struct Forest {
  Node* forest[N_TREES];
  unsigned int num_features, n_samples;
} Forest;


Forest* build_forest(double **data,  unsigned int n_samples, unsigned int num_features);
double forest_compute_score(Forest *f, double *data);
void free_forest(Forest *f);

#endif /* _ISOLATION_FOREST_H */
