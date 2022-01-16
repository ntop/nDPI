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
  const char* top_file = "blacklist-ip.txt";
  FILE *fd = fopen(top_file, "r");
  ndpi_patricia_tree_t *p_v4;
  char * line = NULL;
  size_t len = 0;
  u_int32_t num = 0, num_search = 100, i;
  ssize_t read;
  struct timeval search, begin, end;
  u_int64_t tdiff;
  ndpi_prefix_t prefix;
  struct in_addr a;
  u_int16_t maxbits = 32; /* use 128 for IPv6 */   
  
  if(fd == NULL) {
    printf("Unable to open file %s\n", top_file);
    return(-1);
  }

  assert(p_v4 = ndpi_patricia_new(32));

  printf("Building the patricia tree...\n");

  gettimeofday(&begin, NULL);
  
  while ((read = getline(&line, &len, fd)) != -1) {
    ndpi_patricia_node_t *node;
    u_int len = strlen(line);
      
    line[len] = '\0'; /* Remove trailer \n */

    a.s_addr = inet_addr(line);
    ndpi_fill_prefix_v4(&prefix, &a, 32, maxbits);
    assert(ndpi_patricia_lookup(p_v4, &prefix) != NULL /* node added */);
    num++;
  }
  
  fclose(fd);

  gettimeofday(&search, NULL);
  
  printf("Patricia tree (IPv4) with %u IP prefixes built successfully in %.2f sec [%.1f MB]\n",
	 num, tdiff2sec(&begin, &search),
	 (float)ndpi_get_tot_allocated_memory()/(float)(1024*1024));

  gettimeofday(&search, NULL);

#if !defined(SEARCH_LAST_IP_ADDED)
  /* Nothing to do */
#else
  a.s_addr = inet_addr("1.2.3.4");
  ndpi_fill_prefix_v4(&prefix, &a, 32, maxbits);
#endif
  
  for(i=0; i<num_search; i++)
    assert(ndpi_patricia_search_best(p_v4, &prefix));
  gettimeofday(&end, NULL);
  
  printf("String searched in %.2f usec\n",
	 (float)(timeval2usec(&end) - timeval2usec(&search))/(float)num_search);
  
  ndpi_patricia_destroy(p_v4, NULL);

  return(0);
}
