/*
 * dga.c
 *
 * Copyright (C) 2019-20 - ntop.org
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

#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include "ndpi_config.h"


void help() {
  printf("dga_evaluate <file name>\n");
  exit(0);
}


/* *********************************************** */

int main(int argc, char **argv) {
  FILE *fd;
  char buffer[512];

  if(argc != 2) help();
  fd = fopen(argv[1], "r");

  if(fd == NULL) {
    printf("Unable to open file %s\n", argv[1]);
    exit(0);
  }

  if (ndpi_get_api_version() != NDPI_API_VERSION) {
    printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
    return -1;
  }

  /* Initialize nDPI detection module*/
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(ndpi_no_prefs);
  assert(ndpi_str != NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
  ndpi_finalize_initalization(ndpi_str);
  assert(ndpi_str != NULL);
  int num_detections = 0;


  while(fgets(buffer, sizeof(buffer), fd) != NULL) {
    char *hostname;
    hostname = strtok(buffer, "\n");
    if (ndpi_check_dga_name(ndpi_str, NULL, hostname, 1)) num_detections++;
  }

  fclose(fd);
  ndpi_exit_detection_module(ndpi_str);
  printf("%i", num_detections);
  return 0;
}

