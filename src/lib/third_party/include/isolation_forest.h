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
  bool is_leaf;
  u_int8_t depth;
} Node;

typedef struct Forest {
  Node* forest[N_TREES];
  u_int32_t n_samples, tot_memory;
  u_int16_t num_features;
} Forest;


Forest* build_forest(double **data,  u_int32_t n_samples, u_int16_t num_features);
double forest_compute_score(Forest *f, double *data);
void free_forest(Forest *f);

#endif /* _ISOLATION_FOREST_H */
