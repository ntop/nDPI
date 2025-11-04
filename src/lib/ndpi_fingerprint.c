/*
 * ndpi_fingerprint.c
 *
 * Copyright (C) 2011-25 - ntop.org and contributors
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
#include <math.h>
#include <sys/types.h>

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_private.h"

#include "ndpi_os_fingerprint.c.inc"


/* ************************************************************** */

void ndpi_load_tcp_fingerprints(struct ndpi_detection_module_struct *ndpi_str) {

  if(ndpi_str->tcp_fingerprint_hashmap ||
     ndpi_hash_init(&ndpi_str->tcp_fingerprint_hashmap) == 0) {
    u_int i;
    
    for(i=0; tcp_fps[i].fingerprint != NULL; i++)
      ndpi_add_tcp_fingerprint(ndpi_str, (char*)tcp_fps[i].fingerprint, tcp_fps[i].os);
  }
}

/* ************************************************************** */

ndpi_os ndpi_get_os_from_tcp_fingerprint(struct ndpi_detection_module_struct *ndpi_str,
					 char *tcp_fingerprint) {  
  if(tcp_fingerprint && (ndpi_str->tcp_fingerprint_hashmap != NULL)) {
    u_int64_t ret;
    
    if(ndpi_hash_find_entry(ndpi_str->tcp_fingerprint_hashmap,
			    tcp_fingerprint, strlen(tcp_fingerprint), &ret) == 0)
      return(ret);
  }

  return(ndpi_os_unknown);
}

/* ************************************************************** */

/*
  Add a new TCP fingerprint

  Return code:
  0   OK
  -1  Duplicated fingerprint
  -2  Unable to add a new entry
 */
int ndpi_add_tcp_fingerprint(struct ndpi_detection_module_struct *ndpi_str,
			     char *fingerprint, ndpi_os os) {
  u_int len;
  u_int64_t ret;

  len = strlen(fingerprint);

  if((ndpi_str->tcp_fingerprint_hashmap != NULL)
     && (ndpi_hash_find_entry(ndpi_str->tcp_fingerprint_hashmap, fingerprint, len, &ret) == 0)) {
    /* Duplicate fingerprint found */
    return(-1);
  } else {
    if(ndpi_hash_add_entry(&ndpi_str->tcp_fingerprint_hashmap, fingerprint, len,
			   (u_int64_t)os) == 0) {
      return(0);
    } else
      return(-2);
  }
}

/* ******************************************************************** */

/*
 * Format:
 *
 * <TCP fingerprint>,<numeric OS>
 * Example: 2_64_14600_8c07a80cc645,3
 *
 */
int ndpi_load_tcp_fingerprint_file(struct ndpi_detection_module_struct *ndpi_str, const char *path)
{
  int rc;
  FILE *fd;

  if(!ndpi_str || !path)
    return(-1);

  fd = fopen(path, "r");
  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return -1;
  }

  rc = load_tcp_fingerprint_file_fd(ndpi_str, fd);

  fclose(fd);

  return rc;
}

/* ******************************************************************** */

int load_tcp_fingerprint_file_fd(struct ndpi_detection_module_struct *ndpi_str, FILE *fd) {
  char buffer[128];
  int num = 0;

  if(!ndpi_str || !fd)
    return(-1);

  if(ndpi_str->tcp_fingerprint_hashmap == NULL
     && ndpi_hash_init(&ndpi_str->tcp_fingerprint_hashmap) != 0)
    return(-1);

  while (fgets(buffer, sizeof(buffer), fd) != NULL) {
    char *fingerprint, *os, *tmp;
    ndpi_os os_num;
    size_t len = strlen(buffer);

    if(len <= 1 || buffer[0] == '#')
      continue;

    fingerprint = strtok_r(buffer, "\t", &tmp);
    if(!fingerprint) continue;

    os = strtok_r(NULL, "\t", &tmp);
    if(!os) continue; else os_num = (ndpi_os)atoi(os);

    if(os_num >= ndpi_os_MAX_OS) continue;

    if(ndpi_add_tcp_fingerprint(ndpi_str, fingerprint, os_num) == 0)
      num++;
  }

  return num;
}



