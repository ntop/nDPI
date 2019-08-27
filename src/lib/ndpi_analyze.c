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

struct ndpi_analyze_struct* ndpi_init_data_analysis(u_int16_t _max_series_len) {
  struct ndpi_analyze_struct *ret = ndpi_malloc(sizeof(struct ndpi_analyze_struct));
  u_int32_t len;

  if(ret == NULL)
    return(ret);
  else
    memset(ret, 0, sizeof(struct ndpi_analyze_struct));
  
  if(_max_series_len > MAX_SERIES_LEN) _max_series_len = MAX_SERIES_LEN;
  if(_max_series_len == 0)             _max_series_len = 1; /* At least 1 element */
  ret->num_values_array_len = _max_series_len;

  len = sizeof(u_int32_t)*ret->num_values_array_len;
  if((ret->values = ndpi_malloc(len)) == NULL) {
    ndpi_free(ret);
    ret = NULL;
  } else
    memset(ret->values, 0, len);
  
  return(ret);
}

/* ********************************************************************************* */

void ndpi_free_data_analysis(struct ndpi_analyze_struct *d) {
  ndpi_free(d->values);
  ndpi_free(d);
}

/* ********************************************************************************* */

/*
  Add a new point to analyze
 */
void ndpi_data_add_value(struct ndpi_analyze_struct *s, const u_int32_t value) {
  s->sum_total += value, s->num_data_entries++, s->values[s->next_value_insert_index] = value;
  if(++s->next_value_insert_index == s->num_values_array_len)
    s->next_value_insert_index = 0;
}

/* ********************************************************************************* */

/* Compute the average on all value */
float ndpi_data_average(struct ndpi_analyze_struct *s) {
  return((float)s->sum_total / (float)s->num_data_entries);
}

/* ********************************************************************************* */

/* Compute the average only on the sliding window */
float ndpi_data_window_average(struct ndpi_analyze_struct *s) {
  float   sum = 0.0;
  u_int16_t i, n = ndpi_min(s->num_data_entries, s->num_values_array_len);
    
  for(i=0; i<n; i++)
    sum += s->values[i];

  return((float)sum / (float)n);
}

/* ********************************************************************************* */

/*
  Compute entropy on the last sliding window values
*/
float ndpi_entropy(struct ndpi_analyze_struct *s) {
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
}

/* ********************************************************************************* */

void ndpi_data_print_window_values(struct ndpi_analyze_struct *s) {
  u_int16_t i, n = ndpi_min(s->num_data_entries, s->num_values_array_len);
  
  for(i=0; i<n; i++)
    printf("[%u: %u]", i, s->values[i]);

  printf("\n");
}
