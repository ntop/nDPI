/*
 * ndpi_analyze.c
 *
 * Copyright (C) 2019-23 - ntop.org and contributors
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

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <float.h> /* FLT_EPSILON */
#include "ndpi_api.h"
#include "ndpi_config.h"
#include "third_party/include/hll.h"
#include "third_party/include/kdtree.h"
#include "third_party/include/ball.h"
#include "ndpi_replace_printf.h"

/* ********************************************************************************* */

void ndpi_init_data_analysis(struct ndpi_analyze_struct *ret, u_int16_t _max_series_len) {
  u_int32_t len;

  memset(ret, 0, sizeof(*ret));

  if(_max_series_len > MAX_SERIES_LEN) _max_series_len = MAX_SERIES_LEN;
  ret->num_values_array_len = _max_series_len;

  if(ret->num_values_array_len > 0) {
    len = sizeof(u_int64_t) * ret->num_values_array_len;
    if((ret->values = ndpi_malloc(len)) != NULL)
      memset(ret->values, 0, len);
    else
      ret->num_values_array_len = 0;
  }
}

/* ********************************************************************************* */

struct ndpi_analyze_struct* ndpi_alloc_data_analysis(u_int16_t _max_series_len) {
  struct ndpi_analyze_struct *ret = ndpi_malloc(sizeof(struct ndpi_analyze_struct));

  if(ret != NULL)
    ndpi_init_data_analysis(ret, _max_series_len);

  return(ret);
}

/* ********************************************************************************* */

struct ndpi_analyze_struct* ndpi_alloc_data_analysis_from_series(const u_int32_t *values, u_int16_t num_values) {
  u_int16_t i;
  struct ndpi_analyze_struct *ret = ndpi_alloc_data_analysis(num_values);

  if(ret == NULL) return(NULL);

  for(i=0; i<num_values; i++)
    ndpi_data_add_value(ret, (const u_int64_t)values[i]);

  return(ret);
}

/* ********************************************************************************* */

void ndpi_free_data_analysis(struct ndpi_analyze_struct *d, u_int8_t free_pointer) {
  if(d && d->values) ndpi_free(d->values);
  if(free_pointer) ndpi_free(d);
}

/* ********************************************************************************* */

void ndpi_reset_data_analysis(struct ndpi_analyze_struct *d) {
  u_int64_t *values_bkp;
  u_int32_t num_values_array_len_bpk;

  if(!d)
    return;

  values_bkp = d->values;
  num_values_array_len_bpk = d->num_values_array_len;

  memset(d, 0, sizeof(struct ndpi_analyze_struct));

  d->values = values_bkp;
  d->num_values_array_len = num_values_array_len_bpk;

  if(d->values)
    memset(d->values, 0, sizeof(u_int64_t)*d->num_values_array_len);
}

/* ********************************************************************************* */

/*
  Add a new point to analyze
 */
void ndpi_data_add_value(struct ndpi_analyze_struct *s, const u_int64_t value) {
  if(!s)
    return;

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
  if((!s) || (s->num_data_entries == 0))
    return(0);

  return((float)s->sum_total / (float)s->num_data_entries);
}

/* ********************************************************************************* */

u_int64_t ndpi_data_last(struct ndpi_analyze_struct *s) {
  if((!s) || (s->num_data_entries == 0) || (s->num_values_array_len == 0))
    return(0);

  if(s->next_value_insert_index == 0)
    return(s->values[s->num_values_array_len-1]);
  else
    return(s->values[s->next_value_insert_index-1]);
}

/* Return min/max on all values */
u_int64_t ndpi_data_min(struct ndpi_analyze_struct *s) { return(s ? s->min_val : 0); }
u_int64_t ndpi_data_max(struct ndpi_analyze_struct *s) { return(s ? s->max_val : 0); }

/* ********************************************************************************* */

/* Compute the variance on all values */
float ndpi_data_variance(struct ndpi_analyze_struct *s) {
  if(!s)
    return(0);
  float v = s->num_data_entries ?
    ((float)s->stddev.sum_square_total - ((float)s->sum_total * (float)s->sum_total / (float)s->num_data_entries)) / (float)s->num_data_entries : 0.0;

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

/*
   Compute the mean on all values
   NOTE: In statistics, there is no difference between the mean and average
*/
float ndpi_data_mean(struct ndpi_analyze_struct *s) {
  return(ndpi_data_average(s));
}

/* ********************************************************************************* */

/* Compute the average only on the sliding window */
float ndpi_data_window_average(struct ndpi_analyze_struct *s) {
  if(s && s->num_values_array_len) {
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
  if(s && s->num_values_array_len) {
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
  if(s && s->num_values_array_len) {
    int i;
    float sum = 0.0, total = 0.0;

    for(i=0; i<s->num_values_array_len; i++)
      total += s->values[i];

    if(fpclassify(total) == FP_ZERO)
      return(0);

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
  if(s && s->num_values_array_len) {
    u_int16_t i, n = ndpi_min(s->num_data_entries, s->num_values_array_len);

    for(i=0; i<n; i++)
      printf("[%u: %" PRIu64 "]", i, s->values[i]);

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

int ndpi_hll_init(struct ndpi_hll *hll, u_int8_t bits) {
  return(hll_init(hll, bits));
}

void ndpi_hll_destroy(struct ndpi_hll *hll) {
  hll_destroy(hll);
}

void ndpi_hll_reset(struct ndpi_hll *hll) {
  hll_reset(hll);
}

int ndpi_hll_add(struct ndpi_hll *hll, const char *data, size_t data_len) {
  return(hll_add(hll, (const void *)data, data_len));
}

/* 1 = rank changed, 0 = no changes in rank */
int ndpi_hll_add_number(struct ndpi_hll *hll, u_int32_t value) {
  return(hll_add(hll, (const void *)&value, sizeof(value)));
}

double ndpi_hll_count(struct ndpi_hll *hll) {
  return(hll_count(hll));
}

/* ********************************************************************************* */
/* ********************************************************************************* */

int ndpi_init_bin(struct ndpi_bin *b, enum ndpi_bin_family f, u_int16_t num_bins) {
  if(!b)
    return(-1);

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

  case ndpi_bin_family64:
    if((b->u.bins64 = (u_int64_t*)ndpi_calloc(num_bins, sizeof(u_int64_t))) == NULL)
      return(-1);
    break;
  }

  return(0);
}

/* ********************************************************************************* */

void ndpi_free_bin(struct ndpi_bin *b) {
  if(!b || !b->u.bins8)
    return;

  switch(b->family) {
  case ndpi_bin_family8:
    ndpi_free(b->u.bins8);
    break;
  case ndpi_bin_family16:
    ndpi_free(b->u.bins16);
    break;
  case ndpi_bin_family32:
    ndpi_free(b->u.bins32);
    break;
  case ndpi_bin_family64:
    ndpi_free(b->u.bins64);
    break;
  }
}

/* ********************************************************************************* */

struct ndpi_bin* ndpi_clone_bin(struct ndpi_bin *b) {
  struct ndpi_bin *out;

  if(!b || !b->u.bins8) return(NULL);

  out = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin));
  if(!out) return(NULL);

  out->num_bins = b->num_bins, out->family = b->family, out->is_empty = b->is_empty;

  switch(out->family) {
  case ndpi_bin_family8:
    if((out->u.bins8 = (u_int8_t*)ndpi_calloc(out->num_bins, sizeof(u_int8_t))) == NULL) {
      ndpi_free(out);
      return(NULL);
    } else
      memcpy(out->u.bins8, b->u.bins8, out->num_bins*sizeof(u_int8_t));
    break;

  case ndpi_bin_family16:
    if((out->u.bins16 = (u_int16_t*)ndpi_calloc(out->num_bins, sizeof(u_int16_t))) == NULL) {
      ndpi_free(out);
      return(NULL);
    } else
      memcpy(out->u.bins16, b->u.bins16, out->num_bins*sizeof(u_int16_t));
    break;

  case ndpi_bin_family32:
    if((out->u.bins32 = (u_int32_t*)ndpi_calloc(out->num_bins, sizeof(u_int32_t))) == NULL) {
      ndpi_free(out);
      return(NULL);
    } else
      memcpy(out->u.bins32, b->u.bins32, out->num_bins*sizeof(u_int32_t));
    break;

  case ndpi_bin_family64:
    if((out->u.bins64 = (u_int64_t*)ndpi_calloc(out->num_bins, sizeof(u_int64_t))) == NULL) {
      ndpi_free(out);
      return(NULL);
    } else
      memcpy(out->u.bins64, b->u.bins64, out->num_bins*sizeof(u_int64_t));
    break;
  }

  return(out);
}

/* ********************************************************************************* */

void ndpi_set_bin(struct ndpi_bin *b, u_int16_t slot_id, u_int64_t val) {
  if(!b || !b->u.bins8 || b->num_bins == 0)
    return;

  if(slot_id >= b->num_bins) slot_id = b->num_bins - 1;

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
  case ndpi_bin_family64:
    b->u.bins64[slot_id] = (u_int64_t)val;
    break;
  }
}

/* ********************************************************************************* */

void ndpi_inc_bin(struct ndpi_bin *b, u_int16_t slot_id, u_int64_t val) {
  if(!b || !b->u.bins8 || b->num_bins == 0)
    return;

  b->is_empty = 0;

  if(slot_id >= b->num_bins) slot_id = b->num_bins - 1;

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
  case ndpi_bin_family64:
    b->u.bins64[slot_id] += (u_int64_t)val;
    break;
  }
}

/* ********************************************************************************* */

u_int64_t ndpi_get_bin_value(struct ndpi_bin *b, u_int16_t slot_id) {
  if(!b || !b->u.bins8 || b->num_bins == 0)
    return(0);

  if(slot_id >= b->num_bins) slot_id = b->num_bins - 1;

  switch(b->family) {
  case ndpi_bin_family8:
    return(b->u.bins8[slot_id]);
  case ndpi_bin_family16:
    return(b->u.bins16[slot_id]);
  case ndpi_bin_family32:
    return(b->u.bins32[slot_id]);
  case ndpi_bin_family64:
    return(b->u.bins64[slot_id]);
  }

  return(0);
}

/* ********************************************************************************* */

void ndpi_reset_bin(struct ndpi_bin *b) {
  if(!b || !b->u.bins8)
    return;

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
  case ndpi_bin_family64:
    memset(b->u.bins64, 0, sizeof(u_int64_t)*b->num_bins);
    break;
  }
}
/* ********************************************************************************* */

/*
  Each bin slot is transformed in a % with respect to the value total
 */
void ndpi_normalize_bin(struct ndpi_bin *b) {
  u_int16_t i;
  u_int32_t tot = 0;

  if(!b || b->is_empty) return;

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

  case ndpi_bin_family64:
    for(i=0; i<b->num_bins; i++) tot += b->u.bins64[i];

    if(tot > 0) {
      for(i=0; i<b->num_bins; i++)
	b->u.bins64[i] = (b->u.bins64[i]*100) / tot;
    }
    break;
  }
}

/* ********************************************************************************* */

char* ndpi_print_bin(struct ndpi_bin *b, u_int8_t normalize_first, char *out_buf, u_int out_buf_len) {
  u_int16_t i;
  u_int len = 0;

  if(!b || !b->u.bins8 || !out_buf) return(out_buf); else out_buf[0] = '\0';

  if(normalize_first)
    ndpi_normalize_bin(b);

  switch(b->family) {
  case ndpi_bin_family8:
    for(i=0; i<b->num_bins; i++) {
      int rc = ndpi_snprintf(&out_buf[len], out_buf_len-len, "%s%u", (i > 0) ? "," : "", b->u.bins8[i]);

      if(rc < 0 || (u_int)rc >= out_buf_len-len) break;
      len += rc;
    }
    break;

  case ndpi_bin_family16:
    for(i=0; i<b->num_bins; i++) {
      int rc = ndpi_snprintf(&out_buf[len], out_buf_len-len, "%s%u", (i > 0) ? "," : "", b->u.bins16[i]);

      if(rc < 0 || (u_int)rc >= out_buf_len-len) break;
      len += rc;
    }
    break;

  case ndpi_bin_family32:
    for(i=0; i<b->num_bins; i++) {
      int rc = ndpi_snprintf(&out_buf[len], out_buf_len-len, "%s%u", (i > 0) ? "," : "", b->u.bins32[i]);

      if(rc < 0 || (u_int)rc >= out_buf_len-len) break;
      len += rc;
    }
    break;

  case ndpi_bin_family64:
    for(i=0; i<b->num_bins; i++) {
      int rc = ndpi_snprintf(&out_buf[len], out_buf_len-len, "%s%llu", (i > 0) ? "," : "", (unsigned long long)b->u.bins64[i]);

      if(rc < 0 || (u_int)rc >= out_buf_len-len) break;
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

   if similarity_max_threshold != 0, we assume that bins arent similar
*/
float ndpi_bin_similarity(struct ndpi_bin *b1, struct ndpi_bin *b2,
			  u_int8_t normalize_first, float similarity_max_threshold) {
  u_int16_t i;
  float threshold = similarity_max_threshold*similarity_max_threshold;

  if(!b1 || !b2)
    return(-1);

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
    double sum = 0;

    for(i=0; i<b1->num_bins; i++) {
      u_int32_t a = ndpi_get_bin_value(b1, i);
      u_int32_t b = ndpi_get_bin_value(b2, i);
      u_int32_t diff = (a > b) ? (a - b) : (b - a);

      if(a != b) sum += pow(diff, 2);

      if(threshold && (sum > threshold))
	return(-2); /* Sorry they are not similar */

      // printf("%u/%u) [a: %u][b: %u][sum: %u]\n", i, b1->num_bins, a, b, sum);
    }

    /* The lower the more similar */
    return(sqrt(sum));
  }
#endif
}

/* ********************************************************************************* */

//#define DEBUG_CLUSTER_BINS
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
  u_int8_t alloc_centroids = 0;
  char out_buf[256];
  float *bin_score;
  u_int16_t num_cluster_elems[MAX_NUM_CLUSTERS] = { 0 };

  (void)out_buf;
  srand(time(NULL));

  if(!bins || num_bins == 0 || !cluster_ids || num_clusters == 0)
    return(-1);

  if(num_clusters > num_bins)         num_clusters = num_bins;
  if(num_clusters > MAX_NUM_CLUSTERS) num_clusters = MAX_NUM_CLUSTERS;

#ifdef DEBUG_CLUSTER_BINS
  printf("Distributing %u bins over %u clusters\n", num_bins, num_clusters);
#endif

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

#ifdef DEBUG_CLUSTER_BINS
    printf("Initializing cluster %u for bin %u: %s\n",
	   cluster_id, i,
	   ndpi_print_bin(&bins[i], 0, out_buf, sizeof(out_buf)));
#endif

    num_cluster_elems[cluster_id]++;
  }

  num_iterations = 0;

  /* Now let's try to find a better arrangement */
  while(num_iterations++ < max_iterations) {

    /* Compute the centroids for each cluster */
    memset(bin_score, 0, num_bins*sizeof(float));

#ifdef DEBUG_CLUSTER_BINS
    printf("\nIteration %u\n", num_iterations);

    for(j=0; j<num_clusters; j++)
      printf("Cluster %u: %u bins\n", j, num_cluster_elems[j]);
#endif

    for(i=0; i<num_clusters; i++)
      ndpi_reset_bin(&centroids[i]);

    for(i=0; i<num_bins; i++) {
      for(j=0; j<bins[i].num_bins; j++) {
	ndpi_inc_bin(&centroids[cluster_ids[i]], j, ndpi_get_bin_value(&bins[i], j));
      }
    }

    for(i=0; i<num_clusters; i++) {
      ndpi_normalize_bin(&centroids[i]);

#ifdef DEBUG_CLUSTER_BINS
      printf("Centroid [%u] %s\n", i,
	     ndpi_print_bin(&centroids[i], 0, out_buf, sizeof(out_buf)));
#endif
    }

    /* Now let's check if there are bins to move across clusters */
    num_moves = 0;

    for(i=0; i<num_bins; i++) {
      u_int16_t j;
      float best_similarity, current_similarity = 0;
      u_int8_t cluster_id = 0;

#ifdef DEBUG_CLUSTER_BINS
      printf("Analysing bin %u [cluster: %u]\n",
	     i, cluster_ids[i]);
#endif

#ifdef COSINE_SIMILARITY
      best_similarity = -1;
#else
      best_similarity = 99999999999.0f;
#endif

      for(j=0; j<num_clusters; j++) {
	float similarity;

	if(centroids[j].is_empty) continue;

	similarity = ndpi_bin_similarity(&bins[i], &centroids[j], 0, 0);

	if(j == cluster_ids[i])
	  current_similarity = similarity;

#ifdef DEBUG_CLUSTER_BINS
	printf("Bin %u / centroid %u [similarity: %f]\n", i, j, similarity);
#endif

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
#ifdef DEBUG_CLUSTER_BINS
	printf("Moved bin %u from cluster %u -> %u [similarity: %f]\n",
	       i, cluster_ids[i], cluster_id, best_similarity);
#endif

	num_cluster_elems[cluster_ids[i]]--;
	num_cluster_elems[cluster_id]++;

	cluster_ids[i] = cluster_id;
	num_moves++;
      }
    }

    if(num_moves == 0)
      break;

#ifdef DEBUG_CLUSTER_BINS
    for(j=0; j<num_clusters; j++)
      printf("Cluster %u: %u bins\n", j, num_cluster_elems[j]);
#endif

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
  if(!s || num_learning_values == 0)
    return(-1);

  memset(s, 0, sizeof(struct ndpi_rsi_struct));

  s->empty  = 1, s->num_values = num_learning_values;
  s->gains  = (u_int32_t*)ndpi_calloc(num_learning_values, sizeof(u_int32_t));
  s->losses = (u_int32_t*)ndpi_calloc(num_learning_values, sizeof(u_int32_t));

  if(s->gains && s->losses) {
    s->last_value = 0;
    return(0);
  } else {
    if(s->gains)  ndpi_free(s->gains);
    if(s->losses) ndpi_free(s->losses);
    return(-1);
  }
}

/* ************************************* */

void ndpi_free_rsi(struct ndpi_rsi_struct *s) {
  ndpi_free(s->gains), ndpi_free(s->losses);
}

/* ************************************* */

// #define DEBUG_RSI

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

double ndpi_avg_inline(u_int64_t *v, u_int num) {
  double avg = 0;
  u_int i;

  for(i=0; i<num; i++)
    avg += v[i];

  return(avg / (u_int32_t)num);
}

/* *********************************************************** */
/* *********************************************************** */

/*
  Initializes Holt-Winters with Confidence Interval

   Input
   hw:          Datastructure to initialize and that needs tobe freed with ndpi_hw_free()
   num_periods  Number of observations of a season, or in ML-parlance the number of points that are required to make the forecast
   additive     If set to 1 will use the Holt-Winters additive seasonal (should be the default), otherwise the multiplicative seasonal.
   alpha        Level: specifies the coefficient for the level smoothing. Range 0..1. The higher α, the faster the method forgets old values
   beta         Trend: specifies the coefficient for the trend smoothing. Range 0..1.
   gamma        Seasonal: specifies the coefficient for the seasonal smoothing. Range 0..1. With gamma = 0, seasonal correction is not used.

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

  if(num_periods == 65535) /* To avoid overflow */
    return(-1);

  hw->params.num_season_periods = num_periods + 1;
  hw->params.alpha      = alpha;
  hw->params.beta       = beta;
  hw->params.gamma      = gamma;
  hw->params.use_hw_additive_seasonal = additive_seeasonal;

  if((significance < 0) || (significance > 1)) significance = 0.05;
  hw->params.ro         = ndpi_normal_cdf_inverse(1 - (significance / 2.));

  if((hw->y = (u_int64_t*)ndpi_calloc(hw->params.num_season_periods, sizeof(u_int64_t))) == NULL)
    return(-1);

  if((hw->s = (double*)ndpi_calloc(hw->params.num_season_periods, sizeof(double))) == NULL) {
    ndpi_free(hw->y);
    hw->y = NULL;
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
int ndpi_hw_add_value(struct ndpi_hw_struct *hw, const u_int64_t _value, double *forecast,  double *confidence_band) {
  if(hw->num_values < hw->params.num_season_periods) {
    hw->y[hw->num_values++] = _value;

    *forecast = 0;
    *confidence_band = 0;

    return(0); /* Too early still training... */
  } else {
    u_int idx     = hw->num_values % hw->params.num_season_periods;
    double prev_u, prev_v, prev_s, value  = (double)_value;
    double sq, error, sq_error;
    u_int observations;

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
    sq_error              =  error * error;
    hw->sum_square_error += sq_error, hw->prev_error.sum_square_error += sq_error;
    observations = (hw->num_values < MAX_SQUARE_ERROR_ITERATIONS) ? hw->num_values : ((hw->num_values % MAX_SQUARE_ERROR_ITERATIONS) + MAX_SQUARE_ERROR_ITERATIONS + 1);
    sq = sqrt(hw->sum_square_error / observations);
    *confidence_band      = hw->params.ro * sq;

#ifdef HW_DEBUG
    printf("[num_values: %u][u: %.3f][v: %.3f][s: %.3f][error: %.3f][forecast: %.3f][sqe: %.3f][sq: %.3f][confidence_band: %.3f]\n",
	   hw->num_values, hw->u, hw->v, hw->s[idx], error,
	   *forecast, hw->sum_square_error,
	   sq, *confidence_band);
#endif

    hw->num_values++, idx = (idx + 1) % hw->params.num_season_periods;

    if(++hw->prev_error.num_values_rollup == MAX_SQUARE_ERROR_ITERATIONS) {
      hw->sum_square_error = hw->prev_error.sum_square_error;
      hw->prev_error.num_values_rollup = 0, hw->prev_error.sum_square_error = 0;
    }

    return(1); /* We're in business: forecast is meaningful now */
  }
}

/* *********************************************************** */

void ndpi_hw_reset(struct ndpi_hw_struct *hw) {
  hw->prev_error.sum_square_error = 0, hw->prev_error.num_values_rollup = 0;
  hw->num_values = 0;
  hw->u = hw->v = hw->sum_square_error = 0;

  if(hw->y)
    memset(hw->y, 0, (hw->params.num_season_periods * sizeof(u_int64_t)));
  if(hw->s)
    memset(hw->s, 0, (hw->params.num_season_periods * sizeof(double)));
}

/* ********************************************************************************* */
/* ********************************************************************************* */

/*
  Jitter calculator

  Used to determine how noisy is a signal
*/

int ndpi_jitter_init(struct ndpi_jitter_struct *s, u_int16_t num_learning_values) {
  if(!s)
    return(-1);

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


/* *********************************************************** */
/* *********************************************************** */

/*
  Single Exponential Smoothing
*/

int ndpi_ses_init(struct ndpi_ses_struct *ses, double alpha, float significance) {
  if(!ses)
    return(-1);

  memset(ses, 0, sizeof(struct ndpi_ses_struct));

  ses->params.alpha = alpha;

  if((significance < 0) || (significance > 1)) significance = 0.05;
  ses->params.ro         = ndpi_normal_cdf_inverse(1 - (significance / 2.));

  return(0);
}

/* *********************************************************** */

/*
   Returns the forecast and the band (forecast +/- band are the upper and lower values)

   Input
   ses:         Datastructure previously initialized
   value        The value to add to the measurement

   Output
   forecast         The forecasted value
   confidence_band  The value +/- on which the value should fall is not an anomaly

   Return code
   0                Too early: we're still in the learning phase. Output values are zero.
   1                Normal processing: forecast and confidence_band are meaningful
*/
int ndpi_ses_add_value(struct ndpi_ses_struct *ses, const double _value, double *forecast, double *confidence_band) {
  double value = (double)_value, error, sq_error;
  int rc;

  if(ses->num_values == 0)
    *forecast = value;
  else
    *forecast = (ses->params.alpha * (ses->last_value - ses->last_forecast)) + ses->last_forecast;

  error  = value - *forecast;
  sq_error =  error * error;
  ses->sum_square_error += sq_error, ses->prev_error.sum_square_error += sq_error;

  if(ses->num_values > 0) {
    u_int observations = (ses->num_values < MAX_SQUARE_ERROR_ITERATIONS) ? (ses->num_values + 1) : ((ses->num_values % MAX_SQUARE_ERROR_ITERATIONS) + MAX_SQUARE_ERROR_ITERATIONS + 1);
    double sq = sqrt(ses->sum_square_error / observations);

    *confidence_band = ses->params.ro * sq;
    rc = 1;
  } else
    *confidence_band = 0, rc = 0;

  ses->num_values++, ses->last_value = value, ses->last_forecast = *forecast;

  if(++ses->prev_error.num_values_rollup == MAX_SQUARE_ERROR_ITERATIONS) {
    ses->sum_square_error = ses->prev_error.sum_square_error;
    ses->prev_error.num_values_rollup = 0, ses->prev_error.sum_square_error = 0;
  }

#ifdef SES_DEBUG
  printf("[num_values: %u][[error: %.3f][forecast: %.3f][sqe: %.3f][sq: %.3f][confidence_band: %.3f]\n",
	   ses->num_values, error, *forecast, ses->sum_square_error, sq_error, *confidence_band);
#endif

  return(rc);
}

/* *********************************************************** */

void ndpi_ses_reset(struct ndpi_ses_struct *ses) {
  ses->prev_error.sum_square_error = 0, ses->prev_error.num_values_rollup = 0;
  ses->num_values = 0;
  ses->sum_square_error = ses->last_forecast = ses->last_value = 0;
}

/* *********************************************************** */

/*
  Computes the best alpha value using the specified values used for training
*/
void ndpi_ses_fitting(double *values, u_int32_t num_values, float *ret_alpha) {
  u_int i;
  float alpha, best_alpha;
  double sse, lowest_sse;

  if(!values || num_values == 0) {
    *ret_alpha = 0;
    return;
  }

  lowest_sse = 0, best_alpha = 0;

  for(alpha=0.1; alpha<0.99; alpha += 0.05) {
    struct ndpi_ses_struct ses;

    ndpi_ses_init(&ses, alpha, 0.05);

#ifdef SES_DEBUG
    printf("\nDouble Exponential Smoothing [alpha: %.2f]\n", alpha);
#endif

    sse = 0;

    for(i=0; i<num_values; i++) {
      double prediction, confidence_band;
      double diff;

      if(ndpi_ses_add_value(&ses, values[i], &prediction, &confidence_band) != 0) {
	diff = fabs(prediction-values[i]);

#ifdef SES_DEBUG
	printf("%2u)\t%12.3f\t%.3f\t%.3f\n", i, values[i], prediction, diff);
#endif

	sse += diff*diff;
      }
    }

    if(lowest_sse == 0)
      lowest_sse = sse, best_alpha = alpha; /* first run */
    else {
      if(sse <= lowest_sse)
	lowest_sse = sse, best_alpha = alpha;
    }

#ifdef SES_DEBUG
    printf("[alpha: %.2f] - SSE: %.2f [BEST: alpha: %.2f/SSE: %.2f]\n", alpha, sse,
	   best_alpha, lowest_sse);
#endif
  } /* for (alpha) */

#ifdef SES_DEBUG
  printf("BEST [alpha: %.2f][SSE: %.2f]\n", best_alpha, lowest_sse);
#endif

  *ret_alpha = best_alpha;
}

/* *********************************************************** */
/* *********************************************************** */

/*
  Double Exponential Smoothing
*/

int ndpi_des_init(struct ndpi_des_struct *des, double alpha, double beta, float significance) {
  if(!des)
    return(-1);

  memset(des, 0, sizeof(struct ndpi_des_struct));

  des->params.alpha = alpha;
  des->params.beta = beta;

  if((significance < 0) || (significance > 1)) significance = 0.05;
  des->params.ro         = ndpi_normal_cdf_inverse(1 - (significance / 2.));

  return(0);
}

/* *********************************************************** */

void ndpi_des_reset(struct ndpi_des_struct *des) {
  des->prev_error.sum_square_error = 0, des->prev_error.num_values_rollup = 0;
  des->num_values = 0;
  des->sum_square_error = des->last_forecast = des->last_trend = des->last_value = 0;
}

/* *********************************************************** */

/*
   Returns the forecast and the band (forecast +/- band are the upper and lower values)

   Input
   des:         Datastructure previously initialized
   value        The value to add to the measurement

   Output
   forecast         The forecasted value
   confidence_band  The value +/- on which the value should fall is not an anomaly

   Return code
   0                Too early: we're still in the learning phase. Output values are zero.
   1                Normal processing: forecast and confidence_band are meaningful
*/
int ndpi_des_add_value(struct ndpi_des_struct *des, const double _value, double *forecast, double *confidence_band) {
  double value = (double)_value, error, sq_error;
  int rc;

  if(des->num_values == 0)
    *forecast = value, des->last_trend = 0;
  else {
    *forecast = (des->params.alpha * value) + ((1 - des->params.alpha) * (des->last_forecast + des->last_trend));
    des->last_trend = (des->params.beta * (*forecast - des->last_forecast)) + ((1 - des->params.beta) * des->last_trend);
  }

  error  = value - *forecast;
  sq_error =  error * error;
  des->sum_square_error += sq_error, des->prev_error.sum_square_error += sq_error;

  if(des->num_values > 0) {
    u_int observations = (des->num_values < MAX_SQUARE_ERROR_ITERATIONS) ? (des->num_values + 1) : ((des->num_values % MAX_SQUARE_ERROR_ITERATIONS) + MAX_SQUARE_ERROR_ITERATIONS + 1);
    double sq = sqrt(des->sum_square_error / observations);

    *confidence_band = des->params.ro * sq;
    rc = 1;
  } else
    *confidence_band = 0, rc = 0;

  des->num_values++, des->last_value = value, des->last_forecast = *forecast;

  if(++des->prev_error.num_values_rollup == MAX_SQUARE_ERROR_ITERATIONS) {
    des->sum_square_error = des->prev_error.sum_square_error;
    des->prev_error.num_values_rollup = 0, des->prev_error.sum_square_error = 0;
  }

#ifdef DES_DEBUG
  printf("[num_values: %u][[error: %.3f][forecast: %.3f][trend: %.3f[sqe: %.3f][sq: %.3f][confidence_band: %.3f]\n",
	 des->num_values, error, *forecast, des->last_trend, des->sum_square_error, sq, *confidence_band);
#endif

  return(rc);
}

/* *********************************************************** */

/*
  Computes the best alpha and beta values using the specified values used for training
*/
void ndpi_des_fitting(double *values, u_int32_t num_values, float *ret_alpha, float *ret_beta) {
  u_int i;
  float alpha, best_alpha, best_beta, beta = 0;
  double sse, lowest_sse;

  if(!values || num_values == 0) {
    *ret_alpha = 0;
    *ret_beta = 0;
    return;
  }

  lowest_sse = 0, best_alpha = 0, best_beta = 0;

  for(beta=0.1; beta<0.99; beta += 0.05) {
    for(alpha=0.1; alpha<0.99; alpha += 0.05) {
      struct ndpi_des_struct des;

      ndpi_des_init(&des, alpha, beta, 0.05);

#ifdef DES_DEBUG
      printf("\nDouble Exponential Smoothing [alpha: %.2f][beta: %.2f]\n", alpha, beta);
#endif

      sse = 0;

      for(i=0; i<num_values; i++) {
	double prediction, confidence_band;
	double diff;

	if(ndpi_des_add_value(&des, values[i], &prediction, &confidence_band) != 0) {
	  diff = fabs(prediction-values[i]);

#ifdef DES_DEBUG
	  printf("%2u)\t%12.3f\t%.3f\t%.3f\n", i, values[i], prediction, diff);
#endif

	  sse += diff*diff;
	}
      }

      if(lowest_sse == 0)
	lowest_sse = sse, best_alpha = alpha, best_beta = beta; /* first run */
      else {
	if(sse <= lowest_sse)
	  lowest_sse = sse, best_alpha = alpha, best_beta = beta;
      }

#ifdef DES_DEBUG
      printf("[alpha: %.2f][beta: %.2f] - SSE: %.2f [BEST: alpha: %.2f/beta: %.2f/SSE: %.2f]\n", alpha, beta, sse,
	     best_alpha, best_beta, lowest_sse);
#endif
    } /* for (alpha) */
  } /* for (beta) */

#ifdef DES_DEBUG
  printf("BEST [alpha: %.2f][beta: %.2f][SSE: %.2f]\n", best_alpha, best_beta, lowest_sse);
#endif

  *ret_alpha = best_alpha, *ret_beta = best_beta;
}

/* *********************************************************** */

/* Z-Score = (Value - Mean) / StdDev */
u_int ndpi_find_outliers(u_int32_t *values, bool *outliers, u_int32_t num_values) {
  u_int i, ret = 0;
  float mean, stddev, low_threshold = -2.5, high_threshold = 2.5;
  struct ndpi_analyze_struct a;

  if(!values || !outliers || num_values == 0)
    return(ret);

  ndpi_init_data_analysis(&a, 3 /* this is the window so we do not need to store values and 3 is enough */);

  /* Add values */
  for(i=0; i<num_values; i++)
    ndpi_data_add_value(&a, values[i]);

  mean    = ndpi_data_mean(&a);
  stddev  = ndpi_data_stddev(&a);

  if(fpclassify(stddev) == FP_ZERO) {
    ndpi_free_data_analysis(&a, 0);
    return(ret);
  }

  /* Process values */
  for(i=0; i<num_values; i++) {
    float z_score = (((float)values[i]) - mean) / stddev;
    bool is_outlier = ((z_score < low_threshold) || (z_score > high_threshold)) ? true : false;

    if(is_outlier) ret++;
    outliers[i] = is_outlier;
  }

  ndpi_free_data_analysis(&a, 0);

  return(ret);
}

/* *********************************************************** */

/* Check if the specified value is an outlier with respect to the past values */
bool ndpi_is_outlier(u_int32_t *past_values, u_int32_t num_past_values,
		     u_int32_t value_to_check, float threshold,
		     float *lower, float *upper) {
  struct ndpi_analyze_struct *data = ndpi_alloc_data_analysis_from_series(past_values, num_past_values);
  float mean, stddev, v;

  if(!data) return(false);

  mean   = ndpi_data_mean(data);
  stddev = ndpi_data_stddev(data);

  /* The mimimum threshold is 1 (i.e. the value of the stddev) */
  if(threshold < 1.) threshold = 1.;

  v = threshold * stddev;
  *lower = mean - v, *upper = mean + v;

  ndpi_free_data_analysis(data, 1 /* free memory */);

  return(((value_to_check < *lower) || (value_to_check > *upper)) ? true : false);
}

/* ********************************************************************************* */

/*
  Simple Linear regression [https://en.wikipedia.org/wiki/Simple_linear_regression]
  https://www.tutorialspoint.com/c-program-to-compute-linear-regression
*/
int ndpi_predict_linear(u_int32_t *values, u_int32_t num_values,
			u_int32_t predict_periods, u_int32_t *prediction) {
  u_int i;
  float m, c, d;
  float sumx = 0, sumx_square = 0, sumy = 0, sumxy = 0;

  for(i = 0; i < num_values; i++) {
    float y = values[i];
    float x = i + 1;

    sumx   = sumx+x;
    sumx_square = sumx_square + (x * x);
    sumy   = sumy + y;
    sumxy  = sumxy + (x * y);
  }

  d = (num_values * sumx_square) - (sumx * sumx);

  if(d == 0) return(-1);

  m = ((num_values * sumxy) - (sumx * sumy))  / d; /* beta  */
  c = ((sumy * sumx_square) - (sumx * sumxy)) / d; /* alpha */

  *prediction = c + (m * (predict_periods + num_values - 1));

  return(0);
}

/* ********************************************************************************* */

double ndpi_pearson_correlation(u_int32_t *values_a, u_int32_t *values_b, u_int16_t num_values) {
  double sum_a = 0, sum_b = 0, sum_squared_diff_a = 0, sum_squared_diff_b = 0, sum_product_diff = 0;
  u_int16_t i;
  double mean_a, mean_b, variance_a, variance_b, covariance;

  if(num_values == 0) return(0.0);

  for(i = 0; i < num_values; i++)
    sum_a += values_a[i], sum_b += values_b[i];

  mean_a = sum_a / num_values, mean_b = sum_b / num_values;

  for(i = 0; i < num_values; i++)
    sum_squared_diff_a += pow(values_a[i] - mean_a, 2),
      sum_squared_diff_b += pow(values_b[i] - mean_b, 2),
      sum_product_diff += (values_a[i] - mean_a) * (values_b[i] - mean_b);

  variance_a = sum_squared_diff_a / (double)num_values, variance_b = sum_squared_diff_b / (double)num_values;
  covariance = sum_product_diff / (double)num_values;

  if(variance_a == 0.0 || variance_b == 0.0)
    return(0.0);

  return(covariance / sqrt(variance_a * variance_b));
}

/* ********************************************************************************* */
/* ********************************************************************************* */

static const u_int16_t crc16_ccitt_table[256] = {
	0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
	0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
	0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
	0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
	0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
	0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
	0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
	0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
	0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
	0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
	0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
	0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
	0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
	0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
	0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
	0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
	0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
	0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
	0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
	0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
	0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
	0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
	0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
	0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
	0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
	0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
	0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
	0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
	0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
	0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
	0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
	0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
};

static const u_int16_t crc16_ccitt_false_table[256] = {
  0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
  0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
  0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
  0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
  0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
  0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
  0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
  0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
  0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
  0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
  0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
  0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
  0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
  0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
  0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
  0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
  0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
  0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
  0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
  0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
  0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
  0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
  0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
  0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
  0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
  0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
  0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
  0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
  0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
  0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
  0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
  0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

static inline u_int16_t __crc16(u_int16_t crc, const void *data, size_t n_bytes) {
  u_int8_t* b = (u_int8_t*)data;
  while (n_bytes--) {
    crc = (crc << 8) ^ crc16_ccitt_false_table[(crc >> 8) ^ *b++];
  }
  return crc;
}

u_int16_t ndpi_crc16_ccit(const void* data, size_t n_bytes) {
  u_int16_t crc = 0;
  u_int8_t* b = (u_int8_t*)data;
  while (n_bytes--) {
    crc = (crc >> 8) ^ crc16_ccitt_table[(crc ^ *b++) & 0xFF];
  }
  return crc;
}

u_int16_t ndpi_crc16_ccit_false(const void *data, size_t n_bytes) {
  return __crc16(0xFFFF, data, n_bytes);
}

u_int16_t ndpi_crc16_xmodem(const void *data, size_t n_bytes) {
  return __crc16(0, data, n_bytes);
}

u_int16_t ndpi_crc16_x25(const void* data, size_t n_bytes) {
  u_int16_t crc = 0xFFFF;
  u_int8_t* b = (u_int8_t*)data;
  while (n_bytes--) {
    crc = (crc >> 8) ^ crc16_ccitt_table[(crc ^ *b++) & 0xFF];
  }
  return (crc ^ 0xFFFF);
}

/* ********************************************************************************* */

static const u_int32_t crc32_ieee_table[256] =
{
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
  0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
  0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
  0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
  0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
  0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
  0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
  0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
  0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
  0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
  0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
  0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
  0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
  0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
  0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
  0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
  0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
  0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
  0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
  0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
  0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
  0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
  0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
  0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
  0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
  0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
  0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
  0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
  0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
  0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
  0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
  0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
  0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
  0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
  0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
  0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
  0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
  0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
  0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
  0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
  0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
  0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
  0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

u_int32_t ndpi_crc32(const void *data, size_t length, u_int32_t crc)
{
  const u_int8_t *p = (const u_int8_t*)data;
  crc = ~crc;

  while (length--)
  {
    crc = crc32_ieee_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
  }

  return ~crc;
}

/* ********************************************************************************* */

/*
  Count-Min Sketch: Memory Usage

  https://florian.github.io/count-min-sketch/
  https://medium.com/@nehasingh18.9/count-min-sketch-for-beginners-f1e441bbe7a4
  https://sites.google.com/site/countminsketch/code

  [Depth: 8][Total memory: 1040]
  [Depth: 16][Total memory: 2064]
  [Depth: 32][Total memory: 4112]
  [Depth: 64][Total memory: 8208]
  [Depth: 256][Total memory: 32784]
  [Depth: 512][Total memory: 65552]
  [Depth: 1024][Total memory: 131088]
  [Depth: 2048][Total memory: 262160]
  [Depth: 4096][Total memory: 524304]
  [Depth: 8192][Total memory: 1048592]
*/

#define NDPI_COUNT_MIN_SKETCH_NUM_BUCKETS  1024

// #define DEBUG

struct ndpi_cm_sketch *ndpi_cm_sketch_init(u_int16_t num_hashes) {
#ifdef DEBUG
  u_int32_t tot_mem;
#endif
  u_int32_t len;
  struct ndpi_cm_sketch *sketch;

  len = sizeof(struct ndpi_cm_sketch);
  sketch = (struct ndpi_cm_sketch*)ndpi_malloc(len);

  if(!sketch)
    return(NULL);

#ifdef DEBUG
    tot_mem = len;
#endif

  if(num_hashes < 2) num_hashes = 2;
  num_hashes = ndpi_nearest_power_of_two(num_hashes);

  sketch->num_hashes = num_hashes;
  sketch->num_hash_buckets = num_hashes * NDPI_COUNT_MIN_SKETCH_NUM_BUCKETS;
  sketch->num_hash_buckets = ndpi_nearest_power_of_two(sketch->num_hash_buckets)-1,

  len = num_hashes * NDPI_COUNT_MIN_SKETCH_NUM_BUCKETS * sizeof(u_int32_t);
  sketch->tables = (u_int32_t*)ndpi_calloc(num_hashes, NDPI_COUNT_MIN_SKETCH_NUM_BUCKETS * sizeof(u_int32_t));

#ifdef DEBUG
  tot_mem += len;
#endif

#ifdef DEBUG
  printf("[Num_Hashes: %u][Total memory: %u]\n", num_hashes, tot_mem);
#endif

  if(!sketch->tables) {
    ndpi_free(sketch);
    return(NULL);
  }

  return(sketch);
}

/* ********************************************************************************* */

#define ndpi_simple_hash(value, seed) (value * seed)

/* ********************************************************************************* */

void ndpi_cm_sketch_add(struct ndpi_cm_sketch *sketch, u_int32_t element) {
  u_int32_t idx;

  for(idx = 1; idx <= sketch->num_hashes; idx++) {
    u_int32_t hashval = ndpi_simple_hash(element, idx) & sketch->num_hash_buckets;

    sketch->tables[hashval]++;

#ifdef DEBUG
    printf("ndpi_add_sketch_add() [hash: %d][num_hash_buckets: %u][hashval: %d][value: %d]\n",
	   idx, sketch->num_hash_buckets, hashval, sketch->tables[hashval]);
#endif
  }
}

/* ********************************************************************************* */

u_int32_t ndpi_cm_sketch_count(struct ndpi_cm_sketch *sketch, u_int32_t element) {
  u_int32_t min_value = INT_MAX, idx;

  for(idx = 1; idx <= sketch->num_hashes; idx++) {
    u_int32_t hashval = ndpi_simple_hash(element, idx) & sketch->num_hash_buckets;

#ifdef DEBUG
    printf("ndpi_add_sketch_add() [hash: %d][num_hash_buckets: %u][hashval: %d][value: %d]\n",
	   idx, sketch->num_hash_buckets, hashval, sketch->tables[hashval]);
#endif

    min_value = ndpi_min(min_value, sketch->tables[hashval]);
  }

  return(min_value);
}

/* ********************************************************************************* */

void ndpi_cm_sketch_destroy(struct ndpi_cm_sketch *sketch) {
  ndpi_free(sketch->tables);
  ndpi_free(sketch);
}

/* ********************************************************************************* */
/* ********************************************************************************* */

/* Popcount, short for "population count," is a computer programming term that refers to
   the number of set bits (bits with a value of 1) in a binary representation of a given
   data word or integer. In other words, it is the count of all the 1s present in the
   binary representation of a number.
   For example, consider the number 45, which is represented in binary as 101101.
   The popcount of 45 would be 4 because there are four 1s in its binary representation.
*/

int ndpi_popcount_init(struct ndpi_popcount *h)
{
  if(h) {
    memset(h, '\0', sizeof(*h));
    return 0;
  }
  return -1;
}

/* ********************************************************************************* */

void ndpi_popcount_count(struct ndpi_popcount *h, const u_int8_t *buf, u_int32_t buf_len)
{
  u_int32_t i;

  if(!h)
    return;

  /* Trivial alg. TODO: there are lots of better, more performant algorithms */

  for(i = 0; i < buf_len / 4; i++)
    h->pop_count += __builtin_popcount(*(u_int32_t *)(buf + i * 4));
  for(i = 0; i < buf_len % 4; i++)
    h->pop_count += __builtin_popcount(buf[buf_len - (buf_len % 4) + i]);

  h->tot_bytes_count += buf_len;
}

/* ********************************************************************************* */
/* ********************************************************************************* */

ndpi_kd_tree* ndpi_kd_create(u_int num_dimensions) { return(kd_create((int)num_dimensions)); }

void ndpi_kd_free(ndpi_kd_tree *tree) { kd_free((struct kdtree *)tree); }

void ndpi_kd_clear(ndpi_kd_tree *tree) { kd_clear((struct kdtree *)tree); }

bool ndpi_kd_insert(ndpi_kd_tree *tree, const double *data_vector, void *user_data) {
  return(kd_insert((struct kdtree *)tree, data_vector, user_data) == 0 ? true : false);
}

ndpi_kd_tree_result *ndpi_kd_nearest(ndpi_kd_tree *tree, const double *data_vector) {
  return(kd_nearest((struct kdtree *)tree, data_vector));
}

u_int32_t ndpi_kd_num_results(ndpi_kd_tree_result *res) { return((u_int32_t)kd_res_size((struct kdres*)res)); }

double* ndpi_kd_result_get_item(ndpi_kd_tree_result *res, double **user_data) {
  return(kd_res_item((struct kdres*)res, user_data));
}

void ndpi_kd_result_free(ndpi_kd_tree_result *res) { kd_res_free((struct kdres *)res); }

double ndpi_kd_distance(double *a1, double *a2, u_int num_dimensions) {
  double dist_sq = 0, diff;
  u_int i;

  for(i=0; i<num_dimensions; i++) {
    diff = a1[i] - a2[i];

#if 0
    if(diff != 0) {
      printf("Difference %.3f at position %u\n", diff, pos);
    }
#endif
    dist_sq += diff*diff;
  }

  return(dist_sq);
}

/* ********************************************************************************* */
/* ********************************************************************************* */

ndpi_btree* ndpi_btree_init(double **data, u_int32_t n_rows, u_int32_t n_columns) {
  return((ndpi_btree*)btree_init(data, (int)n_rows, (int)n_columns, 30));
}

ndpi_knn ndpi_btree_query(ndpi_btree *b, double **query_data,
			  u_int32_t query_data_num_rows, u_int32_t query_data_num_columns,
			  u_int32_t max_num_results) {
  return(btree_query((t_btree*)b, query_data, (int)query_data_num_rows,
		     (int)query_data_num_columns, (int)max_num_results));
}

void ndpi_free_knn(ndpi_knn knn) { free_knn(knn, knn.n_samples); }

void ndpi_free_btree(ndpi_btree *b) { free_tree((t_btree*)b); }

/* ********************************************************************************* */

/* It provides the Mahalanobis distance (https://en.wikipedia.org/wiki/Mahalanobis_distance)
   between a point x and a distribution with mean u and inverted covariant matrix i_s.
   Parameters:
    x: input array (with dimension "size")
    u: means array (with dimension "size")
    i_s: inverted covariant matrix (with dimension "size" * "size")

   Bottom line: distance = sqrt([x - u] * [i_s] * [x - u]^T)
*/
float ndpi_mahalanobis_distance(const u_int32_t *x, u_int32_t size, const float *u, const float *i_s)
{
  float md = 0;
  float *diff; /* [x - u] */
  float *tmp;  /* Result of [x - u] * [i_s] */
  u_int32_t i, j;

  /* Could we get rid of these allocations? */
  diff = ndpi_calloc(sizeof(float), size);
  tmp = ndpi_calloc(sizeof(float), size);
  if(diff && tmp) {
    for (i = 0; i < size; i++)
      diff[i] = x[i] - u[i];

    /* Naive implementation of matrix multiplication(s) */
    for(i = 0; i < size; i++) {
      for(j = 0; j < size; j++) {
        tmp[i] += diff[j] * i_s[size * j + i];
      }
    }
    for(i = 0; i < size; i++)
      md += tmp[i] * diff[i];
  }
  ndpi_free(diff);
  ndpi_free(tmp);

  return sqrt(md);
}
