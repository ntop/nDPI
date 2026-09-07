/*
 * ndpi_random_forest.h
 *
 * Copyright (C) 2011-26 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection library.
 */
#ifndef __NDPI_RANDOM_FOREST_H__
#define __NDPI_RANDOM_FOREST_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A node with this feature index is a leaf. */
#define NDPI_RF_LEAF_NODE UINT16_MAX

struct ndpi_random_forest_node {
  uint16_t feature_index;
  float threshold;
  int32_t left;
  int32_t right;
  uint16_t class_id;
};

struct ndpi_random_forest_model {
  const struct ndpi_random_forest_node *nodes;
  uint32_t node_count;
  const int32_t *roots;
  uint32_t tree_count;
  uint16_t class_count;
};

/**
 * Evaluate a caller-owned, immutable Random Forest model.
 *
 * Models are deliberately supplied by the caller: nDPI does not ship a
 * trained classifier or make an accuracy claim without a versioned dataset
 * and feature schema.  Child indexes are zero-based node indexes.  A child
 * index must be in [0, node_count); leaf nodes use class_id and ignore their
 * child indexes.
 *
 * @param model       Validated, immutable forest model.
 * @param features    Feature vector used by the model.
 * @param feature_count Number of values in features.
 * @param scores      Output vote score for each class; may be NULL.
 * @param score_count Number of entries available in scores.
 * @return 0 on success, -1 on invalid input or malformed model.
 */
int ndpi_random_forest_predict(const struct ndpi_random_forest_model *model,
                               const float *features,
                               uint32_t feature_count,
                               float *scores,
                               uint16_t score_count);

#ifdef __cplusplus
}
#endif
#endif /* __NDPI_RANDOM_FOREST_H__ */

/* vim: set ts=2 sw=2 et: */
