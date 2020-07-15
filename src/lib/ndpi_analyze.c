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

void ndpi_free_data_analysis(struct ndpi_analyze_struct *d) {
  if(d->values) ndpi_free(d->values);
  ndpi_free(d);
}

/* ********************************************************************************* */

/*
  Add a new point to analyze
 */
void ndpi_data_add_value(struct ndpi_analyze_struct *s, const u_int32_t value) {
  float tmp_mu;

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

  /* Update stddev */
  tmp_mu = s->stddev.mu;
  s->stddev.mu = ((s->stddev.mu * (s->num_data_entries - 1)) + value) / s->num_data_entries;
  s->stddev.q = s->stddev.q + (value - tmp_mu)*(value - s->stddev.mu);
}

/* ********************************************************************************* */

/* Compute the average on all values */
float ndpi_data_average(struct ndpi_analyze_struct *s) {
  return((s->num_data_entries == 0) ? 0 : ((float)s->sum_total / (float)s->num_data_entries));
}

/* ********************************************************************************* */

/* Return min/max on all values */
u_int32_t ndpi_data_min(struct ndpi_analyze_struct *s) { return(s->min_val); }
u_int32_t ndpi_data_max(struct ndpi_analyze_struct *s) { return(s->max_val); }

/* ********************************************************************************* */

/* Compute the variance on all values */
float ndpi_data_variance(struct ndpi_analyze_struct *s) {
  return(s->num_data_entries ? (s->stddev.q / s->num_data_entries) : 0);
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

      sum += pow(a-b, 2);
    }
    
    /* The lower the more similar */
    return(sqrt(sum));
  }
#endif
}

/* ********************************************************************************* */

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

  if(num_clusters > num_bins) num_clusters = num_bins;

  if(verbose)
    printf("Distributing %u bins over %u clusters\n", num_bins, num_clusters);

  if(centroids == NULL) {
    alloc_centroids = 1;

    if((centroids = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_clusters)) == NULL)
      return(-2);
    else {
      for(i=0; i<num_clusters; i++)
	ndpi_init_bin(&centroids[i], ndpi_bin_family32 /* Use 32 bit to avoid overlaps */, bins[0].num_bins);
    }
  }

  /* Reset the id's */
  memset(cluster_ids, 0, sizeof(u_int16_t) * num_bins);

  /* Randomly pick a cluster id */
  for(i=0; i<num_clusters; i++) {
    cluster_ids[i] = i;

    if(verbose)
      printf("Initializing cluster %u: %s\n", i,
	     ndpi_print_bin(&bins[i], 0, out_buf, sizeof(out_buf)));

  }

  /* Assign the remaining bins to the nearest cluster */
  for(i=num_clusters; i<num_bins; i++) {
    u_int16_t j;
    float best_similarity;
    u_int8_t cluster_id = 0;

#ifdef COSINE_SIMILARITY
    best_similarity = -1;
#else
    best_similarity = 99999999999;
#endif

    for(j=0; j<num_clusters; j++) {
      float similarity = ndpi_bin_similarity(&bins[i], &bins[j], 0);

#ifdef COSINE_SIMILARITY
      if(similarity > best_similarity)
#else
	if(similarity < best_similarity)
#endif
	cluster_id = j, best_similarity = similarity;
    }

    if(verbose)
      printf("Assigned bin to cluster %u: %s [score: %f]\n", cluster_id,
	     ndpi_print_bin(&bins[i], 0, out_buf, sizeof(out_buf)), best_similarity);

    cluster_ids[i] = cluster_id;
  }

  num_iterations = 0;

  /* Now let's try to find a better arrangement */
  while(num_iterations++ < max_iterations) {
    /* Find the center of each cluster */

    if(verbose) printf("Iteration %u\n", num_iterations);

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
      float best_similarity;
      u_int8_t cluster_id = 0;

#ifdef COSINE_SIMILARITY
    best_similarity = -1;
#else
    best_similarity = 99999999999;
#endif

      for(j=0; j<num_clusters; j++) {
	float similarity;

	if(centroids[j].is_empty) continue;
	
	similarity = ndpi_bin_similarity(&bins[i], &centroids[j], 0);

	if(verbose)
	  printf("Bin %u / centroid %u [similarity: %f]\n", i, j, similarity);

#ifdef COSINE_SIMILARITY
      if(similarity > best_similarity)
#else
	if(similarity < best_similarity)
#endif 	  
	  cluster_id = j, best_similarity = similarity;
      }

      if(/* (best_similarity > 0) && */ (cluster_ids[i] != cluster_id)) {
	if(verbose)
	  printf("Moved bin %u from cluster %u -> %u [similarity: %f]\n",
		 i, cluster_ids[i], cluster_id, best_similarity);

	cluster_ids[i] = cluster_id;
	num_moves++;
      }
    }

    if(num_moves == 0)
      break;
  }

  if(alloc_centroids) {
    for(i=0; i<num_clusters; i++)
      ndpi_free_bin(&centroids[i]);

    ndpi_free(centroids);
  }

  return(0);
}

/* ********************************************************************************* */
