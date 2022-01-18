/*
 * Copyright (C) 2011-22 - ntop.org
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <math.h>

#include "ndpi_api.h"

u_int64_t timeval2usec(const struct timeval *tv) {
  return(tv->tv_sec*1000000+tv->tv_usec);
}

float tdiff2sec(const struct timeval *begin, const struct timeval *end) {
  u_int64_t b = timeval2usec(begin);
  u_int64_t e = timeval2usec(end);
  u_int64_t diff = e - b;
  
  return((float)diff / 1000000.);
}


int main(int argc, char *argv[]) {
  const char* top_file = "top-1m.csv";
  FILE *fd = fopen(top_file, "r");
  void *automa = ndpi_init_automa();
  char * line = NULL;
  size_t len = 0;
  u_int32_t num = 0, num_search = 100, i;
  ssize_t read;
  struct timeval search, begin, end;
  u_int64_t tdiff;
  
  if(fd == NULL) {
    printf("Unable to open file %s\n", top_file);
    return(-1);
  }
  assert(automa);

  printf("Building the automa...\n");

  gettimeofday(&begin, NULL);
  
  while ((read = getline(&line, &len, fd)) != -1) {
    char *t = strtok(line, ",");

    if(t) t =  strtok(NULL, "\n");

    if(t != NULL) {
      u_int len = strlen(t);
      
      t[len] = '\0';

      assert(ndpi_add_string_to_automa(automa, ndpi_strdup(t)) == 0);
      num++;

      if(num == 100000) break;
    }
  }
  
  fclose(fd);

  ndpi_finalize_automa(automa);

  gettimeofday(&search, NULL);
  
  printf("Automa with %u words built successfully in %.1f sec [%.1f MB]\n",
	 num, tdiff2sec(&begin, &search),
	 (float)ndpi_get_tot_allocated_memory()/(float)(1024*1024));

  gettimeofday(&search, NULL);
  for(i=0; i<num_search; i++)
    assert(ndpi_match_string(automa, "github.com") == 1);
  gettimeofday(&end, NULL);
  
  printf("String searched in %.2f usec\n",
	 (float)(timeval2usec(&end) - timeval2usec(&search))/(float)num_search);
  
  ndpi_free_automa(automa);

  return(0);
}
