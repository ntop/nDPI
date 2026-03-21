/*
 * Isolation Forest Anomaly Detection
 *
 * Copyright (C) 2026 - ntop.org
 *
 * Algorithm: Liu, Fei Tony, Kai Ming Ting, and Zhi-Hua Zhou.
 *            "Isolation forest." ICDM 2008.
 *
 * https://ieeexplore.ieee.org/document/4781136
 *
 * Key ideas:
 *   1. Anomalies are "few and different" — they isolate quickly.
 *   2. Build random binary trees by repeatedly picking a random
 *      feature and a random split within [min, max] of that feature.
 *   3. Path length to isolation is the anomaly score:
 *      short path → anomaly,  long path → normal.
 *   4. Score is normalised by the expected path length c(n) so that
 *      it sits in (0, 1) regardless of dataset size.
 */

#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "ndpi_main.h"
#include "../include/isolation_forest.h"

static double rand_range(double min, double max) {
  return min + (double)rand() / RAND_MAX * (max - min);
}

static Node* create_node(Forest *f, int depth, u_int16_t num_features) {
  Node* node = (Node*)ndpi_malloc(sizeof(Node));

  if(node) {
    u_int32_t len = num_features * sizeof(double);
    
    node->normal_vector = (double*)ndpi_malloc(len);
    node->left = node->right = NULL;
    node->is_leaf = false;
    node->depth = depth;

    f->tot_memory += len + sizeof(Node);
  }

  return node;
}

// Builds one tree by recursively splitting data with random hyperplanes
static Node* build_tree(Forest *f, double **data, u_int32_t n_samples, u_int16_t num_features, int depth) {
  Node* node = create_node(f, depth, num_features);
  u_int32_t i, j;

  if(!node)
    return(node);

  if (depth >= MAX_DEPTH || n_samples <= 1) {
    node->is_leaf = true;
    return node;
  }

  // Generate random normal vector (the 'Extended' part)
  for (j = 0; j < num_features; j++)
    node->normal_vector[j] = rand_range(-1.0, 1.0);

  // Project points to find min/max range for the intercept
  double min_p = 1e15, max_p = -1e15;
  u_int32_t len = n_samples * sizeof(double);
  double *projs = ndpi_malloc(len);

  if(projs != NULL) {
    f->tot_memory += len;
    
    for (i = 0; i < n_samples; i++) {
      projs[i] = 0;

      for (j = 0; j < num_features; j++)
	projs[i] += data[i][j] * node->normal_vector[j];

      if (projs[i] < min_p) min_p = projs[i];
      if (projs[i] > max_p) max_p = projs[i];
    }

    node->intercept = rand_range(min_p, max_p);

    // Count and split data for child nodes
    int l_count = 0, r_count = 0;
    for (i = 0; i < n_samples; i++)
      (projs[i] < node->intercept) ? l_count++ : r_count++;

    u_int32_t l_len = l_count * sizeof(double*);
    double **l_data = ndpi_malloc(l_len);

    if(l_data) {
      u_int32_t r_len = r_count * sizeof(double*);
      double **r_data = ndpi_malloc(r_len);

      if(r_data) {
	int li = 0, ri = 0;

	for (i = 0; i < n_samples; i++)
	  (projs[i] < node->intercept) ? (l_data[li++] = data[i]) : (r_data[ri++] = data[i]);

	node->left = build_tree(f, l_data, l_count, num_features, depth + 1);
	node->right = build_tree(f, r_data, r_count, num_features, depth + 1);

	ndpi_free(r_data);
      }

      ndpi_free(l_data); 
    }
    
    ndpi_free(projs);
  }
  
  return node;
}

static double path_length(Node* node, double *x, u_int16_t num_features) {
  if (node->is_leaf) return (double)node->depth;
  double p = 0;
  u_int32_t j;

  for (j = 0; j < num_features; j++)
    p += x[j] * node->normal_vector[j];

  return (p < node->intercept) ? path_length(node->left, x, num_features) : path_length(node->right, x, num_features);
}

Forest* build_forest(double **data,  u_int32_t n_samples, u_int16_t num_features) {
  Forest *f = (Forest*)ndpi_malloc(sizeof(Forest));
  u_int32_t i;

  if(!f) return(NULL);

  f->num_features = num_features, f->n_samples = n_samples;

  for (i = 0; i < N_TREES; i++)
    f->forest[i] = build_tree(f, data, n_samples, num_features, 0);

#ifdef DEBUG
  printf("[DEBUG] tot_memory=%.1f MB\n", (float)f->tot_memory / (1024. * 1024.));
#endif
  
  return(f);
}

// Harmonic number approximation
static double harmonic(int n) {
  return log(n) + 0.5772156649;
}

// Average path length for 'n' points (the normalizer)
static double c_factor(int n) {
  if (n <= 1) return 0;
  if (n == 2) return 1;
  return 2.0 * harmonic(n - 1) - (2.0 * (n - 1) / n);
}

/* Calculate the final 0.0 - 1.0 score */
static double anomaly_score(double avg_path_length, int n_samples) {
  double c = c_factor(n_samples);
  return pow(2.0, -(avg_path_length / c));
}

double forest_compute_score(Forest *f, double *data) {
  double avg = 0;
  u_int32_t t;

  for (t = 0; t < N_TREES; t++)
    avg += path_length(f->forest[t], data, f->num_features);

  return(anomaly_score(avg / (double)N_TREES, f->n_samples));
}

static void free_node(Node *n) {
  if(n->left)  free_node(n->left);
  if(n->right) free_node(n->right);

  ndpi_free(n->normal_vector);
  ndpi_free(n);
}

void free_forest(Forest *f) {
  u_int32_t i;

  for(i=0; i<N_TREES; i++) {
    Node *n = f->forest[i];

    if(n != NULL)
      free_node(n);
  }

  ndpi_free(f);
}
