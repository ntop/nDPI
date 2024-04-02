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
  printf("dga_evaluate <file name> [<verbose>]\n");
  exit(0);
}

/* *********************************************** */

static int verbose_dga_detection = 0;

static void ndpi_dbg_fn(u_int32_t protocol,
                        struct ndpi_detection_module_struct *module_struct,
                        ndpi_log_level_t log_level, const char *file,
                        const char *func, unsigned line,
                        const char *format, ...)
{
  assert(protocol == NDPI_PROTOCOL_UNKNOWN);
  assert(module_struct != NULL);
  /* While this program always logs at NDPI_LOG_DEBUG_EXTRA level, the
     initialization of the library may log at any level */

  (void)log_level;
  (void)file;
  (void)func;
  (void)line;

  if (verbose_dga_detection) {
    va_list vl;

    va_start(vl, format);
    vprintf(format, vl);
    va_end(vl);
  }
}

int main(int argc, char **argv) {
  FILE *fd;
  char buffer[512];
  int verbose = 0;
  int num_detections = 0;
  
  if(argc < 2) help();
  fd = fopen(argv[1], "r");
  
  if(fd == NULL) {
    printf("Unable to open file %s\n", argv[1]);
    exit(0);
  }

  if(argv[2] != NULL) {
    verbose = 1;
    
    if(argv[3] != NULL)
      verbose_dga_detection = 1;
  }
  
  if (ndpi_get_api_version() != NDPI_API_VERSION) {
    printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
    return -1;
  }

  /* Initialize nDPI detection module*/
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
  assert(ndpi_str != NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
  ndpi_set_config(ndpi_str, NULL, "log.level", "3"); /* NDPI_LOG_DEBUG_EXTRA */
  set_ndpi_debug_function(ndpi_str, ndpi_dbg_fn);
  ndpi_finalize_initialization(ndpi_str);
  assert(ndpi_str != NULL);


  while(fgets(buffer, sizeof(buffer), fd) != NULL) {
    char *hostname = strtok(buffer, "\n");
    
    if(ndpi_check_dga_name(ndpi_str, NULL, hostname, 1, 1)) {
      if(verbose)
	printf("%10s\t%s\n", "[DGA]", hostname);
	       
      num_detections++;
    } else {
      if(verbose)
	printf("%10s\t%s\n", "[NON DGA]", hostname);
    }
  }

  fclose(fd);
  ndpi_exit_detection_module(ndpi_str);
  printf("%i", num_detections);
  return 0;
}

