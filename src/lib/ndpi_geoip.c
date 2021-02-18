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

int ndpi_load_geeoip(struct ndpi_detection_module_struct *ndpi_str,
		     const char *ip_city_data, const char *ip_as_data) {
#ifdef HAVE_MAXMINDDB
  int status;
    
  /* Open the MMDB files */
  if((status = MMDB_open(ip_city_data, MMDB_MODE_MMAP, &ndpi_str->mmdb_city)) != MMDB_SUCCESS)
    return(-1);  
  else
    ndpi_str->mmdb_city_loaded = 1;
    
  if((status = MMDB_open(ip_as_data, MMDB_MODE_MMAP, &ndpi_str->mmdb_as)) != MMDB_SUCCESS)
    return(-2);
  else
    ndpi_str->mmdb_as_loaded = 1;
    
  return(0);
#else
  return(-1);
#endif
}

/* ********************************************************************************* */

int ndpi_free_geeoip(struct ndpi_detection_module_struct *ndpi_str) {
#ifdef HAVE_MAXMINDDB
  if(ndpi_str->mmdb_city_loaded) MMDB_close(&ndpi_str->mmdb_city);
  if(ndpi_str->mmdb_as_loaded)   MMDB_close(&ndpi_str->mmdb_as);    
#endif
}
