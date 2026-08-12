/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-26 - ntop.org
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

#include "ndpi_api.h"
#include <assert.h>

/* *********************************************** */

int main(int argc, char *argv[]) {
  struct ndpi_detection_module_struct *ndpi_str;
  const char *lists_path = "../lists/public_suffix_list.dat";
  FILE *fd;
  char line[512];

  if(argc != 2) {
    printf("Usage: hosts2domains <filename>\n");
    return(0);
  }

  fd = fopen(argv[1], "r");
  if(fd == NULL) {
    printf("Unable to open %s\n", argv[1]);
    return(-1);
  }
  
  assert(ndpi_str = ndpi_init_detection_module(NULL, NDPI_LICENSE_NON_COMMERCIAL_LGPL));
  assert(ndpi_load_domain_suffixes(ndpi_str, (char*)lists_path) == 0);
  
  while (fgets(line, sizeof(line), fd) != NULL) {
    int len = strlen(line);

    if(len > 0) {
      if(line[len-1] == '\n')
	line[len-1] = '\0';
      
      printf("%s\n", ndpi_get_host_domain(ndpi_str, line));
    }
  }
  
  fclose(fd);
    
  ndpi_exit_detection_module(ndpi_str);

  return(0);
}
