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
  b->num_bins = num_bins, b->family = f, b->num_incs = 0;

  switch(f) {
  case ndpi_bin_family8:
    if((b->u.bins8 = (u_int8_t*)calloc(num_bins, sizeof(u_int8_t))) == NULL)
      return(-1);
    break;
    
  case ndpi_bin_family16:
    if((b->u.bins16 = (u_int16_t*)calloc(num_bins, sizeof(u_int16_t))) == NULL)
      return(-1);
    break;
    
  case ndpi_bin_family32:
    if((b->u.bins32 = (u_int32_t*)calloc(num_bins, sizeof(u_int32_t))) == NULL)
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

void ndpi_inc_bin(struct ndpi_bin *b, u_int8_t slot_id) {
  if(slot_id >= b->num_bins) slot_id = 0;

  b->num_incs += 1;
  
  switch(b->family) {
  case ndpi_bin_family8:
    b->u.bins8[slot_id]++;
    break;
  case ndpi_bin_family16:
    b->u.bins16[slot_id]++;
    break;
  case ndpi_bin_family32:
    b->u.bins32[slot_id]++;
    break;
  }
}

/* ********************************************************************************* */

/*
  Each bin slot is transformed in a % with respect to the value total
 */
void ndpi_normalize_bin(struct ndpi_bin *b) {
  u_int8_t i;

  if(b->num_incs == 0) return;
  
  switch(b->family) {
  case ndpi_bin_family8:
    for(i=0; i<b->num_bins; i++)
      b->u.bins8[i] = (b->u.bins8[i]*100) / b->num_incs;
    break;
  case ndpi_bin_family16:
    for(i=0; i<b->num_bins; i++)
      b->u.bins16[i] = (b->u.bins16[i]*100) / b->num_incs;
    break;
  case ndpi_bin_family32:
    for(i=0; i<b->num_bins; i++)
      b->u.bins32[i] = (b->u.bins32[i]*100) / b->num_incs;
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

/* 
   Determines how similar are two bins

   0 = Very differet
   ... (gray zone)
   1 = Alike

   See https://en.wikipedia.org/wiki/Cosine_similarity for more details
*/
float ndpi_bin_similarity(struct ndpi_bin *b1, struct ndpi_bin *b2, u_int8_t normalize_first) {
  u_int8_t i;
  u_int32_t sumxx = 0, sumxy = 0, sumyy = 0;
    
  if((b1->num_incs == 0) || (b2->num_incs == 0)
     || (b1->family != b2->family) || (b1->num_bins != b2->num_bins))
    return(0);

  if(normalize_first)
    ndpi_normalize_bin(b1), ndpi_normalize_bin(b2);
  
  switch(b1->family) {
  case ndpi_bin_family8:
    for(i=0; i<b1->num_bins; i++)
      sumxx += b1->u.bins8[i] * b1->u.bins8[i], sumyy += b2->u.bins8[i] * b2->u.bins8[i], sumxy += b1->u.bins8[i] * b2->u.bins8[i];
    break;
  case ndpi_bin_family16:
    for(i=0; i<b1->num_bins; i++)
      sumxx += b1->u.bins16[i] * b1->u.bins16[i], sumyy += b2->u.bins16[i] * b2->u.bins16[i], sumxy += b1->u.bins16[i] * b2->u.bins16[i];
    break;
  case ndpi_bin_family32:
    for(i=0; i<b1->num_bins; i++)
      sumxx += b1->u.bins32[i] * b1->u.bins32[i], sumyy += b2->u.bins32[i] * b2->u.bins32[i], sumxy += b1->u.bins32[i] * b2->u.bins32[i];
    break;
  }

  return((float)sumxy / sqrt((float)(sumxx * sumyy)));
}
  
/* ********************************************************************************* */
