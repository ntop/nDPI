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

#include "isolation_forest.h"

#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <assert.h>

/* ────────────────────────────────────────────
   Portable pseudo-random number generator
   (xorshift64 — fast, no global state needed)
   ──────────────────────────────────────────── */

typedef struct { unsigned long long state; } RNG;

static void rng_seed(RNG *r, unsigned int seed) {
  r->state = seed ? (unsigned long long)seed : (unsigned long long)time(NULL);
  if (r->state == 0) r->state = 12345678901234ULL;
}

static unsigned long long rng_next(RNG *r) {
  r->state ^= r->state << 13;
  r->state ^= r->state >> 7;
  r->state ^= r->state << 17;
  return r->state;
}

/* Uniform double in [0, 1) */
static double rng_double(RNG *r) {
  return (double)(rng_next(r) >> 11) / (double)(1ULL << 53);
}

/* Uniform int in [0, n) */
static int rng_int(RNG *r, int n) {
  return (int)(rng_next(r) % (unsigned long long)n);
}

/* Fisher–Yates shuffle on an int array */
static void shuffle(int *arr, int n, RNG *r) {
  for (int i = n - 1; i > 0; i--) {
    int j = rng_int(r, i + 1);
    int tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
  }
}

/* ────────────────────────────────────────────
   Expected path length c(n)
   This is the average path length of an unsuccessful
   search in a Binary Search Tree with n nodes:
   c(n) = 2 * H(n-1) - (2*(n-1)/n)
   where H(k) is the harmonic number ≈ ln(k) + 0.5772
   ──────────────────────────────────────────── */

static double harmonic(double n) {
  /* Accurate for n >= 2; avoid log(0) */
  if (n <= 1.0) return 0.0;
  return log(n) + 0.5772156649;   /* Euler–Mascheroni constant */
}

static double c_factor(int n) {
  if (n <= 1) return 1.0;
  if (n == 2) return 1.0;
  double nd = (double)n;
  return 2.0 * harmonic(nd - 1.0) - 2.0 * (nd - 1.0) / nd;
}

/* ────────────────────────────────────────────
   Tree building (recursive with explicit stack)
   ──────────────────────────────────────────── */

/* Allocate a new node in the tree's pool; returns index */
static int new_node(IFTree *tree) {
  assert(tree->node_count < IF_MAX_NODES);
  int idx = tree->node_count++;
  memset(&tree->nodes[idx], 0, sizeof(IFNode));
  return idx;
}

/* Build one isolation tree.
 *
 * indices[]  subset of row indices (subsample) — we partition in-place.
 * n          length of the active subset [lo, hi)
 * depth      current tree depth
 * max_depth  stop splitting beyond this depth
 * data       full dataset (row-major)
 * n_features number of features
 * rng        random state
 */
static int build_node(IFTree *tree,
                      int    *indices, int lo, int hi,
                      int     depth,  int max_depth,
                      const double *data, int n_features,
                      RNG *rng)
{
  int n = hi - lo;
  int node = new_node(tree);

  /* Stop conditions: single sample or max depth reached */
  if (n <= 1 || depth >= max_depth) {
    tree->nodes[node].is_leaf = 1;
    tree->nodes[node].size    = n;
    return node;
  }

  /* Pick a random feature */
  int feat = rng_int(rng, n_features);

  /* Find min and max of that feature in current subset */
  double fmin = data[indices[lo] * n_features + feat];
  double fmax = fmin;
  for (int i = lo + 1; i < hi; i++) {
    double v = data[indices[i] * n_features + feat];
    if (v < fmin) fmin = v;
    if (v > fmax) fmax = v;
  }

  /* All values identical — make a leaf (can't split) */
  if (fmax - fmin < 1e-12) {
    tree->nodes[node].is_leaf = 1;
    tree->nodes[node].size    = n;
    return node;
  }

  /* Random split threshold in (fmin, fmax) */
  double thr = fmin + rng_double(rng) * (fmax - fmin);

  /* Partition indices around the threshold (stable relative order) */
  int mid = lo;
  for (int i = lo; i < hi; i++) {
    if (data[indices[i] * n_features + feat] < thr) {
      int tmp = indices[mid]; indices[mid] = indices[i]; indices[i] = tmp;
      mid++;
    }
  }

  /* If the partition is degenerate (all went one side), make a leaf */
  if (mid == lo || mid == hi) {
    tree->nodes[node].is_leaf = 1;
    tree->nodes[node].size    = n;
    return node;
  }

  /* Record the split */
  tree->nodes[node].is_leaf   = 0;
  tree->nodes[node].feature   = feat;
  tree->nodes[node].threshold = thr;

  /* Recurse — note: new_node() may move memory if we used realloc,
     but here we use a fixed pool so pointers are stable.            */
  tree->nodes[node].left  = build_node(tree, indices, lo,  mid, depth+1, max_depth, data, n_features, rng);
  tree->nodes[node].right = build_node(tree, indices, mid, hi,  depth+1, max_depth, data, n_features, rng);

  return node;
}

/* ────────────────────────────────────────────
   Path-length traversal
   ──────────────────────────────────────────── */

static double path_length(const IFTree *tree, const double *sample) {
  int node = 0;   /* root is always index 0 */
  double depth = 0.0;

  while (1) {
    const IFNode *n = &tree->nodes[node];
    if (n->is_leaf) {
      /* Add c(size) to account for would-be further splits */
      return depth + c_factor(n->size);
    }
    depth += 1.0;
    if (sample[n->feature] < n->threshold)
      node = n->left;
    else
      node = n->right;
  }
}

/* ────────────────────────────────────────────
   Public API
   ──────────────────────────────────────────── */

IForest *iforest_fit(const double *data,
                     int n_samples,
                     int n_features,
                     int n_trees,
                     int subsample_sz,
                     unsigned int seed)
{
  if (!data || n_samples <= 0 || n_features <= 0 || n_trees <= 0)
    return NULL;

  if (subsample_sz <= 0 || subsample_sz > n_samples)
    subsample_sz = (n_samples < 256) ? n_samples : 256;

  IForest *forest = (IForest *)malloc(sizeof(IForest));
  if (!forest) return NULL;

  forest->trees         = (IFTree *)malloc(sizeof(IFTree) * (size_t)n_trees);
  forest->n_trees       = n_trees;
  forest->n_features    = n_features;
  forest->subsample_size = subsample_sz;
  forest->avg_path_length = c_factor(subsample_sz);

  if (!forest->trees) { free(forest); return NULL; }

  /* Max depth is ceil(log2(subsample_size)) */
  int max_depth = 1;
  while ((1 << max_depth) < subsample_sz) max_depth++;
  if (max_depth > IF_MAX_DEPTH) max_depth = IF_MAX_DEPTH;

  /* Index buffer for subsampling (reused per tree) */
  int *indices = (int *)malloc(sizeof(int) * (size_t)n_samples);
  if (!indices) { free(forest->trees); free(forest); return NULL; }

  RNG rng;
  rng_seed(&rng, seed);

  /* Initialise index array 0..n_samples-1 */
  for (int i = 0; i < n_samples; i++) indices[i] = i;

  for (int t = 0; t < n_trees; t++) {
    IFTree *tree = &forest->trees[t];
    tree->node_count = 0;

    /* Draw subsample_sz rows without replacement via partial shuffle */
    shuffle(indices, n_samples, &rng);

    /* Build the tree on indices[0..subsample_sz) */
    build_node(tree, indices, 0, subsample_sz, 0, max_depth,
	       data, n_features, &rng);
  }

  free(indices);
  return forest;
}

IFResult iforest_score(const IForest *forest,
                       const double  *sample,
                       double         threshold)
{
  IFResult result;
  result.avg_depth  = 0.0;
  result.score      = 0.5;
  result.is_anomaly = 0;

  if (!forest || !sample) return result;

  double total_depth = 0.0;
  for (int t = 0; t < forest->n_trees; t++) {
    total_depth += path_length(&forest->trees[t], sample);
  }
  result.avg_depth = total_depth / (double)forest->n_trees;

  /* Normalised anomaly score: s(x,n) = 2^(-E[h(x)] / c(n)) */
  result.score = pow(2.0, -result.avg_depth / forest->avg_path_length);

  result.is_anomaly = (result.score > threshold) ? 1 : 0;
  return result;
}

void iforest_score_batch(const IForest *forest,
                         const double  *data,
                         int            n_samples,
                         double         threshold,
                         IFResult      *out)
{
  if (!forest || !data || !out) return;
  for (int i = 0; i < n_samples; i++) {
    out[i] = iforest_score(forest,
			   data + (size_t)i * (size_t)forest->n_features,
			   threshold);
  }
}

void iforest_free(IForest *forest) {
  if (!forest) return;
  free(forest->trees);
  free(forest);
}
