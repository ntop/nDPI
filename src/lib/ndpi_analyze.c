/*
 * ndpi_analyze.c
 *
 * Copyright (C) 2019 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library.
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "ndpi_config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <stdint.h>
#include <math.h>
#include <float.h> /* FLT_EPSILON */
#include "ndpi_api.h"
#include "ndpi_config.h"

/* ********************************************************************************* */

void ndpi_init_data_analysis(struct ndpi_analyze_struct *ret, u_int16_t _max_series_len) {
  u_int32_t len;

  memset(ret, 0, sizeof(struct ndpi_analyze_struct));

  if(_max_series_len > MAX_SERIES_LEN) _max_series_len = MAX_SERIES_LEN;
  ret->num_values_array_len = _max_series_len;

  if(ret->num_values_array_len > 0) {
    len = sizeof(u_int32_t)*ret->num_values_array_len;
    if((ret->values = ndpi_malloc(len)) == NULL) {
      ndpi_free(ret);
      ret = NULL;
    } else
      memset(ret->values, 0, len);
  } else
    ret->values = NULL;
}

/* ********************************************************************************* */

struct ndpi_analyze_struct* ndpi_alloc_data_analysis(u_int16_t _max_series_len) {
  struct ndpi_analyze_struct *ret = ndpi_malloc(sizeof(struct ndpi_analyze_struct));

  if(ret != NULL)
    ndpi_init_data_analysis(ret, _max_series_len);

  return(ret);
}

/* ********************************************************************************* */

void ndpi_free_data_analysis(struct ndpi_analyze_struct *d, u_int8_t free_pointer) {
  if(d->values) ndpi_free(d->values);
  if(free_pointer) ndpi_free(d);
}

/* ********************************************************************************* */

void ndpi_reset_data_analysis(struct ndpi_analyze_struct *d) {
  memset(d, 0, sizeof(struct ndpi_analyze_struct));
  memset(d->values, 0, sizeof(u_int32_t)*d->num_values_array_len);
  d->num_data_entries = 0;
}

/* ********************************************************************************* */

/*
  Add a new point to analyze
 */
void ndpi_data_add_value(struct ndpi_analyze_struct *s, const u_int32_t value) {
  if(s->sum_total == 0)
    s->min_val = s->max_val = value;
  else {
    if(value < s->min_val) s->min_val = value;
    if(value > s->max_val) s->max_val = value;
  }

  s->sum_total += value, s->num_data_entries++;

  if(s->num_values_array_len) {
    s->values[s->next_value_insert_index] = value;

    if(++s->next_value_insert_index == s->num_values_array_len)
      s->next_value_insert_index = 0;
  }

  /*
    Optimized stddev calculation

    https://www.khanacademy.org/math/probability/data-distributions-a1/summarizing-spread-distributions/a/calculating-standard-deviation-step-by-step
    https://math.stackexchange.com/questions/683297/how-to-calculate-standard-deviation-without-detailed-historical-data
    http://mathcentral.uregina.ca/QQ/database/QQ.09.02/carlos1.html
  */
  s->stddev.sum_square_total += (u_int64_t)value * (u_int64_t)value;
}

/* ********************************************************************************* */

/* Compute the average on all values */
float ndpi_data_average(struct ndpi_analyze_struct *s) {
  return((s->num_data_entries == 0) ? 0 : ((float)s->sum_total / (float)s->num_data_entries));
}

/* ********************************************************************************* */

u_int32_t ndpi_data_last(struct ndpi_analyze_struct *s) {
  if((s->num_data_entries == 0) || (s->sum_total == 0))
    return(0);

  if(s->next_value_insert_index == 0)
    return(s->values[s->num_values_array_len-1]);
  else
    return(s->values[s->next_value_insert_index-1]);
}

/* Return min/max on all values */
u_int32_t ndpi_data_min(struct ndpi_analyze_struct *s) { return(s->min_val); }
u_int32_t ndpi_data_max(struct ndpi_analyze_struct *s) { return(s->max_val); }

/* ********************************************************************************* */

/* Compute the variance on all values */
float ndpi_data_variance(struct ndpi_analyze_struct *s) {
  float v = s->num_data_entries ? ((float)s->stddev.sum_square_total - ((float)s->sum_total * (float)s->sum_total / (float)s->num_data_entries)) / (float)s->num_data_entries : 0.0;
  return((v < 0  /* rounding problem */) ? 0 : v);
}

/* ********************************************************************************* */

/*
  See the link below for "Population and sample standard deviation review"
  https://www.khanacademy.org/math/statistics-probability/summarizing-quantitative-data/variance-standard-deviation-sample/a/population-and-sample-standard-deviation-review

  In nDPI we use an approximate stddev calculation to avoid storing all data in memory
*/
/* Compute the standard deviation on all values */
float ndpi_data_stddev(struct ndpi_analyze_struct *s) {
  return(sqrt(ndpi_data_variance(s)));
}

/* ********************************************************************************* */

/* Compute the average only on the sliding window */
float ndpi_data_window_average(struct ndpi_analyze_struct *s) {
  if(s->num_values_array_len) {
    float   sum = 0.0;
    u_int16_t i, n = ndpi_min(s->num_data_entries, s->num_values_array_len);

    if(n == 0)
      return(0);

    for(i=0; i<n; i++)
      sum += s->values[i];

    return((float)sum / (float)n);
  } else
    return(0);
}

/* ********************************************************************************* */

/* Compute the variance only on the sliding window */
float ndpi_data_window_variance(struct ndpi_analyze_struct *s) {
  if(s->num_values_array_len) {
    float   sum = 0.0, avg = ndpi_data_window_average(s);
    u_int16_t i, n = ndpi_min(s->num_data_entries, s->num_values_array_len);

    if(n == 0)
      return(0);

    for(i=0; i<n; i++)
      sum += pow(s->values[i]-avg, 2);

    return((float)sum / (float)n);
  } else
    return(0);
}

/* ********************************************************************************* */

/* Compute the variance only on the sliding window */
float ndpi_data_window_stddev(struct ndpi_analyze_struct *s) {
  return(sqrt(ndpi_data_window_variance(s)));
}

  /* ********************************************************************************* */

/*
  Compute entropy on the last sliding window values
*/
float ndpi_data_entropy(struct ndpi_analyze_struct *s) {
  if(s->num_values_array_len) {
    int i;
    float sum = 0.0, total = 0.0;

    for(i=0; i<s->num_values_array_len; i++)
      total += s->values[i];

    for (i=0; i<s->num_values_array_len; i++) {
      float tmp = (float)s->values[i] / (float)total;

      if(tmp > FLT_EPSILON)
	sum -= tmp * logf(tmp);
    }

    return(sum / logf(2.0));
  } else
    return(0);
}

/* ********************************************************************************* */

void ndpi_data_print_window_values(struct ndpi_analyze_struct *s) {
  if(s->num_values_array_len) {
    u_int16_t i, n = ndpi_min(s->num_data_entries, s->num_values_array_len);

    for(i=0; i<n; i++)
      printf("[%u: %u]", i, s->values[i]);

    printf("\n");
  }
}

/* ********************************************************************************* */

/*
  Upload / download ration

  -1  Download
  0   Mixed
  1   Upload
 */
float ndpi_data_ratio(u_int32_t sent, u_int32_t rcvd) {
  float s = (float)((int64_t)sent +  (int64_t)rcvd);
  float d = (float)((int64_t)sent -  (int64_t)rcvd);

  return((s == 0) ? 0 : (d/s));
}

/* ********************************************************************************* */

const char* ndpi_data_ratio2str(float ratio) {
  if(ratio < -0.2) return("Download");
  else if(ratio > 0.2) return("Upload");
  else return("Mixed");
}

/* ********************************************************************************* */
/* ********************************************************************************* */

#include "third_party/src/hll/hll.c"
#include "third_party/src/hll/MurmurHash3.c"

int ndpi_hll_init(struct ndpi_hll *hll, u_int8_t bits) {
  return(hll_init(hll, bits));
}

void ndpi_hll_destroy(struct ndpi_hll *hll) {
  hll_destroy(hll);
}

void ndpi_hll_reset(struct ndpi_hll *hll) {
  hll_reset(hll);
}

void ndpi_hll_add(struct ndpi_hll *hll, const char *data, size_t data_len) {
  hll_add(hll, (const void *)data, data_len);
}

void ndpi_hll_add_number(struct ndpi_hll *hll, u_int32_t value) {
  hll_add(hll, (const void *)&value, sizeof(value));
}

double ndpi_hll_count(struct ndpi_hll *hll) {
  return(hll_count(hll));
}

/* ********************************************************************************* */
/* ********************************************************************************* */

int ndpi_init_bin(struct ndpi_bin *b, enum ndpi_bin_family f, u_int8_t num_bins) {
  b->num_bins = num_bins, b->family = f, b->is_empty = 1;

  switch(f) {
  case ndpi_bin_family8:
    if((b->u.bins8 = (u_int8_t*)ndpi_calloc(num_bins, sizeof(u_int8_t))) == NULL)
      return(-1);
    break;

  case ndpi_bin_family16:
    if((b->u.bins16 = (u_int16_t*)ndpi_calloc(num_bins, sizeof(u_int16_t))) == NULL)
      return(-1);
    break;

  case ndpi_bin_family32:
    if((b->u.bins32 = (u_int32_t*)ndpi_calloc(num_bins, sizeof(u_int32_t))) == NULL)
      return(-1);
    break;
  }

  return(0);
}

/* ********************************************************************************* */

void ndpi_free_bin(struct ndpi_bin *b) {
  switch(b->family) {
  case ndpi_bin_family8:
    free(b->u.bins8);
    break;
  case ndpi_bin_family16:
    free(b->u.bins16);
    break;
  case ndpi_bin_family32:
    free(b->u.bins32);
    break;
  }
}

/* ********************************************************************************* */

struct ndpi_bin* ndpi_clone_bin(struct ndpi_bin *b) {
  struct ndpi_bin *out = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin));

  if(!out) return(NULL);

  out->num_bins = b->num_bins, out->family = b->family, out->is_empty = b->is_empty;

  switch(out->family) {
  case ndpi_bin_family8:
    if((out->u.bins8 = (u_int8_t*)ndpi_calloc(out->num_bins, sizeof(u_int8_t))) == NULL) {
      free(out);
      return(NULL);
    } else
      memcpy(out->u.bins8, b->u.bins8, out->num_bins*sizeof(u_int8_t));
    break;

  case ndpi_bin_family16:
    if((out->u.bins16 = (u_int16_t*)ndpi_calloc(out->num_bins, sizeof(u_int16_t))) == NULL) {
      free(out);
      return(NULL);
    } else
      memcpy(out->u.bins16, b->u.bins16, out->num_bins*sizeof(u_int16_t));
    break;

  case ndpi_bin_family32:
    if((out->u.bins32 = (u_int32_t*)ndpi_calloc(out->num_bins, sizeof(u_int32_t))) == NULL) {
      free(out);
      return(NULL);
    } else
      memcpy(out->u.bins32, b->u.bins32, out->num_bins*sizeof(u_int32_t));
    break;
  }

  return(out);
}

/* ********************************************************************************* */

void ndpi_set_bin(struct ndpi_bin *b, u_int8_t slot_id, u_int32_t val) {
  if(slot_id >= b->num_bins) slot_id = 0;

  switch(b->family) {
  case ndpi_bin_family8:
    b->u.bins8[slot_id] = (u_int8_t)val;
    break;
  case ndpi_bin_family16:
    b->u.bins16[slot_id] = (u_int16_t)val;
    break;
  case ndpi_bin_family32:
    b->u.bins32[slot_id] = (u_int32_t)val;
    break;
  }
}

/* ********************************************************************************* */

void ndpi_inc_bin(struct ndpi_bin *b, u_int8_t slot_id, u_int32_t val) {
  b->is_empty = 0;

  if(slot_id >= b->num_bins) slot_id = 0;

  switch(b->family) {
  case ndpi_bin_family8:
    b->u.bins8[slot_id] += (u_int8_t)val;
    break;
  case ndpi_bin_family16:
    b->u.bins16[slot_id] += (u_int16_t)val;
    break;
  case ndpi_bin_family32:
    b->u.bins32[slot_id] += (u_int32_t)val;
    break;
  }
}

/* ********************************************************************************* */

u_int32_t ndpi_get_bin_value(struct ndpi_bin *b, u_int8_t slot_id) {
  if(slot_id >= b->num_bins) slot_id = 0;

  switch(b->family) {
  case ndpi_bin_family8:
    return(b->u.bins8[slot_id]);
    break;
  case ndpi_bin_family16:
    return(b->u.bins16[slot_id]);
    break;
  case ndpi_bin_family32:
    return(b->u.bins32[slot_id]);
    break;
  }

  return(0);
}

/* ********************************************************************************* */

void ndpi_reset_bin(struct ndpi_bin *b) {
  b->is_empty = 1;

  switch(b->family) {
  case ndpi_bin_family8:
    memset(b->u.bins8, 0, sizeof(u_int8_t)*b->num_bins);
    break;
  case ndpi_bin_family16:
    memset(b->u.bins16, 0, sizeof(u_int16_t)*b->num_bins);
    break;
  case ndpi_bin_family32:
    memset(b->u.bins32, 0, sizeof(u_int32_t)*b->num_bins);
    break;
  }
}
/* ********************************************************************************* */

/*
  Each bin slot is transformed in a % with respect to the value total
 */
void ndpi_normalize_bin(struct ndpi_bin *b) {
  u_int8_t i;
  u_int32_t tot = 0;

  if(b->is_empty) return;

  switch(b->family) {
  case ndpi_bin_family8:
    for(i=0; i<b->num_bins; i++) tot += b->u.bins8[i];

    if(tot > 0) {
      for(i=0; i<b->num_bins; i++)
	b->u.bins8[i] = (b->u.bins8[i]*100) / tot;
    }
    break;

  case ndpi_bin_family16:
    for(i=0; i<b->num_bins; i++) tot += b->u.bins16[i];

    if(tot > 0) {
      for(i=0; i<b->num_bins; i++)
	b->u.bins16[i] = (b->u.bins16[i]*100) / tot;
    }
    break;

  case ndpi_bin_family32:
    for(i=0; i<b->num_bins; i++) tot += b->u.bins32[i];

    if(tot > 0) {
      for(i=0; i<b->num_bins; i++)
	b->u.bins32[i] = (b->u.bins32[i]*100) / tot;
    }
    break;
  }
}

/* ********************************************************************************* */

char* ndpi_print_bin(struct ndpi_bin *b, u_int8_t normalize_first, char *out_buf, u_int out_buf_len) {
  u_int8_t i;
  u_int len = 0;

  if(!out_buf) return(out_buf); else out_buf[0] = '\0';

  if(normalize_first)
    ndpi_normalize_bin(b);

  switch(b->family) {
  case ndpi_bin_family8:
    for(i=0; i<b->num_bins; i++) {
      int rc = snprintf(&out_buf[len], out_buf_len-len, "%s%u", (i > 0) ? "," : "", b->u.bins8[i]);

      if(rc < 0) break;
      len += rc;
    }
    break;

  case ndpi_bin_family16:
    for(i=0; i<b->num_bins; i++) {
      int rc = snprintf(&out_buf[len], out_buf_len-len, "%s%u", (i > 0) ? "," : "", b->u.bins16[i]);

      if(rc < 0) break;
      len += rc;
    }
    break;

  case ndpi_bin_family32:
    for(i=0; i<b->num_bins; i++) {
      int rc = snprintf(&out_buf[len], out_buf_len-len, "%s%u", (i > 0) ? "," : "", b->u.bins32[i]);

      if(rc < 0) break;
      len += rc;
    }
    break;
  }

  return(out_buf);
}

/* ********************************************************************************* */

// #define COSINE_SIMILARITY

/*
   Determines how similar are two bins

   Cosine Similiarity
   0 = Very differet
   ... (gray zone)
   1 = Alike

   See https://en.wikipedia.org/wiki/Cosine_similarity for more details

   ---
   Euclidean similarity

   0 = alike
   ...
   the higher the more different
*/
float ndpi_bin_similarity(struct ndpi_bin *b1, struct ndpi_bin *b2, u_int8_t normalize_first) {
  u_int8_t i;

  if(
     // (b1->family != b2->family) ||
     (b1->num_bins != b2->num_bins))
    return(-1);

  if(normalize_first)
    ndpi_normalize_bin(b1), ndpi_normalize_bin(b2);

#ifdef COSINE_SIMILARITY
  {
    u_int32_t sumxx = 0, sumxy = 0, sumyy = 0;

    for(i=0; i<b1->num_bins; i++) {
      u_int32_t a = ndpi_get_bin_value(b1, i);
      u_int32_t b = ndpi_get_bin_value(b2, i);

      sumxx += a*a, sumyy += b*b, sumxy += a*b;
    }

    if((sumxx == 0) || (sumyy == 0))
      return(0);
    else
      return((float)sumxy / sqrt((float)(sumxx * sumyy)));
  }
#else
  {
    u_int32_t sum = 0;

    for(i=0; i<b1->num_bins; i++) {
      u_int32_t a = ndpi_get_bin_value(b1, i);
      u_int32_t b = ndpi_get_bin_value(b2, i);
      u_int32_t diff = (a > b) ? (a - b) : (b - a);

      if(a != b) sum += pow(diff, 2);

      // printf("[a: %u][b: %u][sum: %u]\n", a, b, sum);
    }

    /* The lower the more similar */
    return(sqrt(sum));
  }
#endif
}

/* ********************************************************************************* */

#define MAX_NUM_CLUSTERS  128

/*
  Clusters bins into 'num_clusters'
  - (in) bins: a vection 'num_bins' long of bins to cluster
  - (in) 'num_clusters': number of desired clusters 0...(num_clusters-1)
  - (out) 'cluster_ids': a vector 'num_bins' long containing the id's of each clustered bin
  - (out) 'centroids': an optional 'num_clusters' long vector of (centroid) bins
  See
  - https://en.wikipedia.org/wiki/K-means_clustering
 */
int ndpi_cluster_bins(struct ndpi_bin *bins, u_int16_t num_bins,
		      u_int8_t num_clusters, u_int16_t *cluster_ids,
		      struct ndpi_bin *centroids) {
  u_int16_t i, j, max_iterations = 25, num_iterations, num_moves;
  u_int8_t verbose = 0, alloc_centroids = 0;
  char out_buf[256];
  float *bin_score;
  u_int16_t num_cluster_elems[MAX_NUM_CLUSTERS] = { 0 };

  srand(time(NULL));

  if(num_clusters > num_bins)         num_clusters = num_bins;
  if(num_clusters > MAX_NUM_CLUSTERS) num_clusters = MAX_NUM_CLUSTERS;

  if(verbose)
    printf("Distributing %u bins over %u clusters\n", num_bins, num_clusters);

  if((bin_score = (float*)ndpi_calloc(num_bins, sizeof(float))) == NULL)
    return(-2);

  if(centroids == NULL) {
    alloc_centroids = 1;

    if((centroids = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_clusters)) == NULL) {
      ndpi_free(bin_score);
      return(-2);
    } else {
      for(i=0; i<num_clusters; i++)
	ndpi_init_bin(&centroids[i], ndpi_bin_family32 /* Use 32 bit to avoid overlaps */, bins[0].num_bins);
    }
  }

  /* Reset the id's */
  memset(cluster_ids, 0, sizeof(u_int16_t) * num_bins);

  /* Randomly pick a cluster id */
  for(i=0; i<num_bins; i++) {
    u_int cluster_id = rand() % num_clusters;

    cluster_ids[i] = cluster_id;

    if(verbose)
      printf("Initializing cluster %u for bin %u: %s\n",
	     cluster_id, i,
	     ndpi_print_bin(&bins[i], 0, out_buf, sizeof(out_buf)));

    num_cluster_elems[cluster_id]++;
  }

  num_iterations = 0;

  /* Now let's try to find a better arrangement */
  while(num_iterations++ < max_iterations) {

    /* Compute the centroids for each cluster */
    memset(bin_score, 0, num_bins*sizeof(float));

    if(verbose) {
      printf("\nIteration %u\n", num_iterations);

      for(j=0; j<num_clusters; j++)
	printf("Cluster %u: %u bins\n", j, num_cluster_elems[j]);
    }

    for(i=0; i<num_clusters; i++)
      ndpi_reset_bin(&centroids[i]);

    for(i=0; i<num_bins; i++) {
      for(j=0; j<bins[i].num_bins; j++) {
	ndpi_inc_bin(&centroids[cluster_ids[i]], j, ndpi_get_bin_value(&bins[i], j));
      }
    }

    for(i=0; i<num_clusters; i++) {
      ndpi_normalize_bin(&centroids[i]);

      if(verbose)
	printf("Centroid [%u] %s\n", i,
	       ndpi_print_bin(&centroids[i], 0, out_buf, sizeof(out_buf)));
    }

    /* Now let's check if there are bins to move across clusters */
    num_moves = 0;

    for(i=0; i<num_bins; i++) {
      u_int16_t j;
      float best_similarity, current_similarity = 0;
      u_int8_t cluster_id = 0;

      if(verbose)
	printf("Analysing bin %u [cluster: %u]\n",
	       i, cluster_ids[i]);

#ifdef COSINE_SIMILARITY
      best_similarity = -1;
#else
      best_similarity = 99999999999;
#endif

      for(j=0; j<num_clusters; j++) {
	float similarity;

	if(centroids[j].is_empty) continue;

	similarity = ndpi_bin_similarity(&bins[i], &centroids[j], 0);

	if(j == cluster_ids[i])
	  current_similarity = similarity;

	if(verbose)
	  printf("Bin %u / centroid %u [similarity: %f]\n", i, j, similarity);

#ifdef COSINE_SIMILARITY
	if(similarity > best_similarity) {
	  cluster_id = j, best_similarity = similarity;
	}
#else
	if(similarity < best_similarity) {
	  cluster_id = j, best_similarity = similarity;
	}
#endif
      }

      if((best_similarity == current_similarity) && (num_cluster_elems[cluster_ids[i]] > 1)) {
	/*
          In case of identical similarity let's leave things as they are
          this unless this is a cluster with only one element
	*/
	cluster_id = cluster_ids[i];
      }

      bin_score[i] = best_similarity;

      if(cluster_ids[i] != cluster_id) {
	if(verbose)
	  printf("Moved bin %u from cluster %u -> %u [similarity: %f]\n",
		 i, cluster_ids[i], cluster_id, best_similarity);

	num_cluster_elems[cluster_ids[i]]--;
	num_cluster_elems[cluster_id]++;

	cluster_ids[i] = cluster_id;
	num_moves++;
      }
    }

    if(num_moves == 0)
      break;

    if(verbose) {
      for(j=0; j<num_clusters; j++)
	printf("Cluster %u: %u bins\n", j, num_cluster_elems[j]);
    }

#if 0
    for(j=0; j<num_clusters; j++) {
      if(num_cluster_elems[j] == 0) {
	u_int16_t candidate;
	float score;

	if(verbose)
	  printf("\nCluster %u is empty: need to rebalance\n", j);

#ifdef COSINE_SIMILARITY
	score = 99999999999;

	for(i=0; i<num_bins; i++) {
	  if((cluster_ids[i] != j) && (bin_score[i] < score) && (num_cluster_elems[cluster_ids[i]] > 1))
	    score = bin_score[i], candidate = i;
	}
#else
	score = 0;

	for(i=0; i<num_bins; i++) {
	  if((cluster_ids[i] != j) && (bin_score[i] > score) && (num_cluster_elems[cluster_ids[i]] > 1))
	    score = bin_score[i], candidate = i;
	}
#endif

	if(verbose)
	  printf("Rebalance: moving bin %u from cluster %u -> %u [similarity: %f]\n",
		 candidate, cluster_ids[candidate], j, score);

	num_cluster_elems[cluster_ids[candidate]]--;
	num_cluster_elems[j]++;
	cluster_ids[candidate] = j;
      }
    }
#endif
  } /* while(...) */

  if(alloc_centroids) {
    for(i=0; i<num_clusters; i++)
      ndpi_free_bin(&centroids[i]);

    ndpi_free(centroids);
  }

  ndpi_free(bin_score);

  return(0);
}

/* ********************************************************************************* */

/*
   RSI (Relative Strength Index)

   RSI = 100 − [ 100/ (1 + (Average gain/Average loss)) ]

   https://www.investopedia.com/terms/r/rsi.asp
*/

int ndpi_alloc_rsi(struct ndpi_rsi_struct *s, u_int16_t num_learning_values) {
  memset(s, 0, sizeof(struct ndpi_rsi_struct));

  s->empty  = 1, s->num_values = num_learning_values;
  s->gains  = (u_int32_t*)ndpi_calloc(num_learning_values, sizeof(u_int32_t));
  s->losses = (u_int32_t*)ndpi_calloc(num_learning_values, sizeof(u_int32_t));

  if(s->gains && s->losses) {
    s->last_value = 0;
    return(0);
  } else {
    if(s->gains)  free(s->gains);
    if(s->losses) free(s->losses);
    return(-1);
  }
}

/* ************************************* */

void ndpi_free_rsi(struct ndpi_rsi_struct *s) {
  ndpi_free(s->gains), ndpi_free(s->losses);
}

/* ************************************* */

/*
  This function adds a new value and returns the computed RSI, or -1
  if there are too few points (< num_learning_values)

  RSI < 30 (too many losses)
  RSI > 70 (too many gains)
*/
float ndpi_rsi_add_value(struct ndpi_rsi_struct *s, const u_int32_t value) {
  float relative_strength;

  if(!s->empty) {
    u_int32_t val;

    s->total_gains -= s->gains[s->next_index], s->total_losses -= s->losses[s->next_index];

    if(value > s->last_value) {
      val = value - s->last_value;
      s->gains[s->next_index] = val, s->losses[s->next_index] = 0;
      s->total_gains += val;
#ifdef DEBUG_RSI
      printf("Gain: %u\n", val);
#endif
    } else {
      val = s->last_value - value;
      s->losses[s->next_index] = val, s->gains[s->next_index] = 0;
      s->total_losses += val;
#ifdef DEBUG_RSI
      printf("Loss: %u\n", val);
#endif
    }

#ifdef DEBUG_RSI
    printf("[value: %u][total_gains: %u][total_losses: %u][cur_idx: %u]\n", value, s->total_gains, s->total_losses, s->next_index);
#endif
  }

  s->last_value = value, s->next_index = (s->next_index + 1) % s->num_values, s->empty = 0;
  if(s->next_index == 0) s->rsi_ready = 1; /* We have completed one round */

  if(!s->rsi_ready)
    return(-1); /* Too early */
  else if(s->total_losses == 0) /* Avoid division by zero (**) */
    return(100.);
  else {
    relative_strength = (float)s->total_gains / (float)s->total_losses; /* (**) */
#ifdef DEBUG_RSI
    printf("RSI: %f\n", relative_strength);
#endif
    return(100. - (100. / (1. + relative_strength)));
  }
}

/* *********************************************************** */

/* https://www.johndcook.com/blog/cpp_phi_inverse/ */

static double ndpi_rational_approximation(double t) {
  // Abramowitz and Stegun formula 26.2.23.
  // The absolute value of the error should be less than 4.5 e-4.
  double c[] = { 2.515517, 0.802853, 0.010328 };
  double d[] = { 1.432788, 0.189269, 0.001308 };

  return(t - ((c[2]*t + c[1])*t + c[0]) / (((d[2]*t + d[1])*t + d[0])*t + 1.0));
}

static double ndpi_normal_cdf_inverse(double p) {
  if(p <= 0.0 || p >= 1.0)
    return(0); /* Invalid argument: valid range 0 < X < 1 */

  if(p < 0.5) {
    // F^-1(p) = - G^-1(p)
    return -ndpi_rational_approximation( sqrt(-2.0*log(p)) );
  } else {
    // F^-1(p) = G^-1(1-p)
    return ndpi_rational_approximation( sqrt(-2.0*log(1-p)) );
  }
}

double ndpi_avg_inline(u_int32_t *v, u_int num) {
  double avg = 0;
  u_int i;

  for(i=0; i<num; i++)
    avg += v[i];

  return(avg / (u_int32_t)num);
}

/* *********************************************************** */

/*
  Initializes Holt-Winters with Confidence Interval

   Input
   hw:          Datastructure to initialize and that needs tobe freed with ndpi_hw_free()
   num_periods  Number of observations of a season, or in ML-parlance the number of points that are required to make the forecast
   additive     If set to 1 will use the Holt-Winters additive seasonal (should be the default), otherwise the multiplicative seasonal.
   alpha        Level: specifies the coefficient for the level smoothing. Range 0..1. The higher α, the faster the method forgets old values
   beta         Trend: specifies the coefficient for the trend smoothing. Range 0..1.
   gamma        Seasonal: specifies the coefficient for the seasonal smoothing. Range 0..1. With gamma = 0, seaasonal correction is not used.

   significance Significance level for the forecats sed for computing lower and upper bands. Range 0..1. Typical values 0.05 or less.
                See https://en.wikipedia.org/wiki/Statistical_significance

   NOTE (See https://otexts.com/fpp2/holt-winters.html)
   The additive method is preferred when the seasonal variations are roughly constant through the series,
   while the multiplicative method is preferred when the seasonal variations are changing proportional to the level of the series.

   For learning more about timeseries forecasting see
   https://www.real-statistics.com/time-series-analysis/basic-time-series-forecasting/
 */

int ndpi_hw_init(struct ndpi_hw_struct *hw,
		 u_int16_t num_periods, u_int8_t additive_seeasonal,
		 double alpha, double beta, double gamma, float significance) {
  memset(hw, 0, sizeof(struct ndpi_hw_struct));

  hw->params.num_season_periods = num_periods + 1;
  hw->params.alpha      = alpha;
  hw->params.beta       = beta;
  hw->params.gamma      = gamma;
  hw->params.use_hw_additive_seasonal = additive_seeasonal;

  if((significance < 0) || (significance > 1)) significance = 0.05;
  hw->params.ro         = ndpi_normal_cdf_inverse(1 - (significance / 2.));

  hw->params.ro = 1.95996398454005;
  
  if((hw->y = (u_int32_t*)ndpi_calloc(hw->params.num_season_periods, sizeof(u_int32_t))) == NULL)
    return(-1);

  if((hw->s = (double*)ndpi_calloc(hw->params.num_season_periods, sizeof(double))) == NULL) {
    free(hw->y);
    return(-1);
  }

  return(0);
}

/* *********************************************************** */

/* Frees the memory allocated by ndpi_hw_init() */
void ndpi_hw_free(struct ndpi_hw_struct *hw) {
  if(hw->y) ndpi_free(hw->y);
  if(hw->s) ndpi_free(hw->s);
}

/* *********************************************************** */

/*
   Returns the forecast and the band (forecast +/- band are the upper and lower values)

   Input
   hw:          Datastructure previously initialized
   value        The value to add to the measurement

   Output
   forecast         The forecasted value
   confidence_band  The value +/- on which the value should fall is not an anomaly

   Return code
   0                Too early: we're still in the learning phase. Output values are zero.
   1                Normal processing: forecast and confidence_band are meaningful
*/
int ndpi_hw_add_value(struct ndpi_hw_struct *hw, const u_int32_t _value, double *forecast,  double *confidence_band) {
  if(hw->num_values < hw->params.num_season_periods) {
    hw->y[hw->num_values++] = _value;

    *forecast = 0;
    *confidence_band = 0;

    return(0); /* Too early still training... */
  } else {
    u_int idx     = hw->num_values % hw->params.num_season_periods;
    double prev_u, prev_v, prev_s, value  = (double)_value;
    double sq, error;
    
    if(hw->num_values == hw->params.num_season_periods) {
      double avg = ndpi_avg_inline(hw->y, hw->params.num_season_periods);
      u_int i;

      if(avg == 0) avg = 1; /* Avoid divisions by zero */
      
      for(i=0; i<hw->params.num_season_periods; i++)
	hw->s[i] = hw->y[i] / avg;

      i = hw->params.num_season_periods-1;
      if(hw->s[i] == 0)
	hw->u = 0;
      else
	hw->u = _value / hw->s[i];
      
      hw->v = 0;
      ndpi_free(hw->y);
      hw->y = NULL;
    }

    idx     = hw->num_values % hw->params.num_season_periods;
    prev_u = hw->u, prev_v = hw->v, prev_s = hw->s[idx];
     
    if(prev_s != 0)
      hw->u = ((hw->params.alpha * value) / prev_s)  + ( 1 - hw->params.alpha) * (hw->u + hw->v);
    else
      hw->u = 0; /* Avoid divisions by zero */
    
    hw->v = (hw->params.beta   * (hw->u - prev_u)) + ((1 - hw->params.beta ) * hw->v);

    if(hw->u != 0)
      hw->s[idx] = (hw->params.gamma  * (value / hw->u))  + ((1 - hw->params.gamma) * prev_s);
    else
      hw->s[idx] = 0;  /* Avoid divisions by zero */

    if(hw->params.use_hw_additive_seasonal)
      *forecast = (prev_u + prev_v) + prev_s;
    else
      *forecast = (prev_u + prev_v) * prev_s;

    error                 = value - *forecast;
    hw->sum_square_error += error * error;
    sq = sqrt(hw->sum_square_error / (hw->num_values + 2 - hw->params.num_season_periods));
    *confidence_band      = hw->params.ro * sq;

#ifdef HW_DEBUG
    printf("[num_values: %u][u: %.3f][v: %.3f][s: %.3f][error: %.3f][forecast: %.3f][sqe: %.3f][sq: %.3f][confidence_band: %.3f]\n",
	   hw->num_values, hw->u, hw->v, hw->s[idx], error,
	   *forecast, hw->sum_square_error,
	   sq, *confidence_band);
#endif
    
    hw->num_values++, idx = (idx + 1) % hw->params.num_season_periods;

    return(1); /* We're in business: forecast is meaningful now */
  }
}

/* ********************************************************************************* */
/* ********************************************************************************* */

/*
  Jitter calculator
  
  Used to determine how noisy is a signal
*/

int ndpi_jitter_init(struct ndpi_jitter_struct *s, u_int16_t num_learning_values) {
  memset(s, 0, sizeof(struct ndpi_jitter_struct));

  if(num_learning_values < 2) num_learning_values = 2;
  
  s->empty = 1, s->num_values = num_learning_values;
  s->observations = (float*)ndpi_calloc(num_learning_values, sizeof(float));

  if(s->observations) {
    s->last_value = 0;
    return(0);
  } else
    return(-1);  
}

/* ************************************* */

void ndpi_jitter_free(struct ndpi_jitter_struct *s) {
  ndpi_free(s->observations);
}

/* ************************************* */

/*
  This function adds a new value and returns the computed Jitter
*/
float ndpi_jitter_add_value(struct ndpi_jitter_struct *s, const float value) {
  float val = fabsf(value - s->last_value);

  if(s->empty && (s->next_index == 0))
    ; /* Skip the first value as we are unable to calculate the difference */
  else {
    s->jitter_total -= s->observations[s->next_index];
    s->observations[s->next_index] = val;
    s->jitter_total += val;
  }
  
  s->last_value = value, s->next_index = (s->next_index + 1) % s->num_values;
  if(s->next_index == 0) s->jitter_ready = 1; /* We have completed one round */

#ifdef DEBUG_JITTER
  printf("[JITTER] [value: %.3f][diff: %.3f][jitter_total: %.3f] -> %.3f\n",
	 value, val, s->jitter_total,
	 s->jitter_ready ? (s->jitter_total / s->num_values) : -1);
#endif
  
  if(!s->jitter_ready)
    return(-1); /* Too early */
  else 
    return(s->jitter_total / s->num_values);
}

