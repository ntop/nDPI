/*
 * Isolation Forest Anomaly Detection
 *
 * Copyright (C) 2026 - ntop.org
 *
 */

#ifndef _ISOLATION_FOREST_H
#define _ISOLATION_FOREST_H

#include <stddef.h>

/* ──────────────────────────────────────────────
   Isolation Forest Anomaly Detection
   ──────────────────────────────────────────────
   Anomaly score in [0,1].  Score > 0.5 → anomaly.
   Higher score = more anomalous.
   ────────────────────────────────────────────── */

#define IF_MAX_DEPTH     16   /* max tree depth              */
#define IF_MAX_NODES     4096 /* max nodes per tree          */

/* ── Internal tree node ── */
typedef struct IFNode {
    int    is_leaf;
    int    feature;      /* split feature index            */
    double threshold;    /* split value                    */
    int    left;         /* index into node pool           */
    int    right;
    int    size;         /* samples at this node (leaves)  */
} IFNode;

/* ── A single isolation tree ── */
typedef struct IFTree {
    IFNode nodes[IF_MAX_NODES];
    int    node_count;
} IFTree;

/* ── The forest ── */
typedef struct IForest {
    IFTree  *trees;
    int      n_trees;
    int      n_features;
    int      subsample_size;
    double   avg_path_length; /* E[c(subsample_size)] */
} IForest;

/* ── Result from scoring a single sample ── */
typedef struct IFResult {
    double score;        /* anomaly score in [0,1]         */
    double avg_depth;    /* mean path length across trees  */
    int    is_anomaly;   /* 1 if score > threshold         */
} IFResult;

/* ── API ── */

/**
 * Create and fit a new Isolation Forest.
 *
 * @param data          Row-major matrix [n_samples × n_features]
 * @param n_samples     Number of training samples
 * @param n_features    Number of features per sample
 * @param n_trees       Number of isolation trees (100–500 typical)
 * @param subsample_sz  Subsampling size per tree (256 typical)
 * @param seed          Random seed (0 = use time)
 * @return Heap-allocated IForest (caller must call iforest_free)
 */
IForest *iforest_fit(const double *data,
                     int n_samples,
                     int n_features,
                     int n_trees,
                     int subsample_sz,
                     unsigned int seed);

/**
 * Score a single sample.
 *
 * @param forest    Fitted forest
 * @param sample    Array of n_features doubles
 * @param threshold Anomaly threshold in (0,1); 0.5 is a good default
 * @return          IFResult with score, avg_depth, is_anomaly
 */
IFResult iforest_score(const IForest *forest,
                       const double  *sample,
                       double         threshold);

/**
 * Score an entire dataset.
 *
 * @param forest    Fitted forest
 * @param data      Row-major [n_samples × n_features]
 * @param n_samples Number of samples to score
 * @param threshold Anomaly threshold
 * @param out       Output array of IFResult [n_samples] (caller allocates)
 */
void iforest_score_batch(const IForest *forest,
                         const double  *data,
                         int            n_samples,
                         double         threshold,
                         IFResult      *out);

/**
 * Free all memory allocated by iforest_fit.
 */
void iforest_free(IForest *forest);

#endif /* _ISOLATION_FOREST_H */
