/*
 * ndpi_random_forest.c
 *
 * Copyright (C) 2011-26 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection library.
 */
#include <math.h>
#include <stddef.h>
#include "ndpi_random_forest.h"

static int ndpi_random_forest_node_is_leaf(const struct ndpi_random_forest_node *node)
{
  return node->feature_index == NDPI_RF_LEAF_NODE;
}

int ndpi_random_forest_predict(const struct ndpi_random_forest_model *model,
                               const float *features,
                               uint32_t feature_count,
                               float *scores,
                               uint16_t score_count)
{
  uint32_t tree;

  if(model == NULL || features == NULL || model->nodes == NULL ||
     model->roots == NULL || model->node_count == 0 ||
     model->tree_count == 0 || model->class_count == 0 ||
     feature_count == 0 || (scores != NULL && score_count < model->class_count))
    return -1;

  for(tree = 0; tree < feature_count; tree++) {
    if(!isfinite(features[tree]))
      return -1;
  }

  if(scores != NULL) {
    for(tree = 0; tree < model->class_count; tree++)
      scores[tree] = 0.0f;
  }

  for(tree = 0; tree < model->tree_count; tree++) {
    int32_t node_index = model->roots[tree];
    uint32_t steps = 0;
    uint16_t class_id;

    if(node_index < 0 || (uint32_t)node_index >= model->node_count)
      return -1;

    /* A valid tree cannot visit more nodes than the model contains. */
    while(steps++ < model->node_count) {
      const struct ndpi_random_forest_node *node = &model->nodes[node_index];

      if(ndpi_random_forest_node_is_leaf(node)) {
        class_id = node->class_id;
        if(class_id >= model->class_count)
          return -1;
        if(scores != NULL)
          scores[class_id] += 1.0f / (float)model->tree_count;
        break;
      }

      if(node->feature_index >= feature_count ||
         !isfinite(node->threshold))
        return -1;

      node_index = features[node->feature_index] <= node->threshold ?
                   node->left : node->right;
      if(node_index < 0 || (uint32_t)node_index >= model->node_count)
        return -1;
    }

    if(steps > model->node_count)
      return -1;
  }

  return 0;
}

/* vim: set ts=2 sw=2 et: */
