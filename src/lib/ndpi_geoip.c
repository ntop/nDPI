/*
 * ndpi_geoip.c
 *
 * Copyright (C) 2021 - ntop.org
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

#include "ndpi_api.h"
#include "ndpi_config.h"

#ifdef HAVE_MAXMINDDB
#include <maxminddb.h>
#endif

/* ********************************************************************************* */

int ndpi_load_geoip(struct ndpi_detection_module_struct *ndpi_str,
		     const char *ip_city_data, const char *ip_as_data) {
#ifdef HAVE_MAXMINDDB
  int status;

  ndpi_str->mmdb_city = (void*)ndpi_malloc(sizeof(MMDB_s));
  ndpi_str->mmdb_as   = (void*)ndpi_malloc(sizeof(MMDB_s));
  
  if((ndpi_str->mmdb_city == NULL) || (ndpi_str->mmdb_as == NULL))
    return(-1);
  
  /* Open the MMDB files */
  if((status = MMDB_open(ip_city_data, MMDB_MODE_MMAP, (MMDB_s*)ndpi_str->mmdb_city)) != MMDB_SUCCESS)
    return(-1);
  else
    ndpi_str->mmdb_city_loaded = 1;

  if((status = MMDB_open(ip_as_data, MMDB_MODE_MMAP, (MMDB_s*)ndpi_str->mmdb_as)) != MMDB_SUCCESS)
    return(-2);
  else
    ndpi_str->mmdb_as_loaded = 1;

  return(0);
#else
  return(-3);
#endif
}

/* ********************************************************************************* */

void ndpi_free_geoip(struct ndpi_detection_module_struct *ndpi_str) {
#ifdef HAVE_MAXMINDDB
  if(ndpi_str->mmdb_city_loaded) MMDB_close((MMDB_s*)ndpi_str->mmdb_city);
  if(ndpi_str->mmdb_as_loaded)   MMDB_close((MMDB_s*)ndpi_str->mmdb_as);

  ndpi_free(ndpi_str->mmdb_city);
  ndpi_free(ndpi_str->mmdb_as);
#endif
}

/* ********************************************************************************* */

int ndpi_get_geoip_asn(struct ndpi_detection_module_struct *ndpi_str, char *ip, u_int32_t *asn) {
#ifdef HAVE_MAXMINDDB
  int gai_error, mmdb_error, status;
  MMDB_lookup_result_s result;
  MMDB_entry_data_s entry_data;

  if(ndpi_str->mmdb_as_loaded) {
    result = MMDB_lookup_string((MMDB_s*)ndpi_str->mmdb_as, ip, &gai_error, &mmdb_error);

    if((gai_error != 0)
       || (mmdb_error != MMDB_SUCCESS)
       || (!result.found_entry))
      *asn = 0;
    else {
      /* Get the ASN */
      if((status = MMDB_get_value(&result.entry, &entry_data, "autonomous_system_number", NULL)) == MMDB_SUCCESS) {
	if(entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32)
	  *asn = entry_data.uint32;
	else
	  *asn = 0;
      }
    }

    return(0);
  }
#endif

  return(-2);
}
    
/* ********************************************************************************* */

int ndpi_get_geoip_country_continent(struct ndpi_detection_module_struct *ndpi_str, char *ip,
				     char *country_code, u_int8_t country_code_len,
				     char *continent, u_int8_t continent_len) {
#ifdef HAVE_MAXMINDDB
  int gai_error, mmdb_error;
  MMDB_lookup_result_s result;
  MMDB_entry_data_s entry_data;

     
  if(ndpi_str->mmdb_city_loaded) {
    int status;

    result = MMDB_lookup_string((MMDB_s*)ndpi_str->mmdb_city, ip, &gai_error, &mmdb_error);

    if((gai_error != 0)
       || (mmdb_error != MMDB_SUCCESS)
       || (!result.found_entry))
      country_code[0] = '\0';
    else {
      if(country_code_len > 0) {
	status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
	
	if((status != MMDB_SUCCESS) || (!entry_data.has_data))
	  country_code[0] = '\0';
	else {
	  int str_len = ndpi_min(entry_data.data_size, country_code_len);
	  
	  memcpy(country_code, entry_data.utf8_string, str_len);
	  country_code[str_len] = '\0';
	}
      }

      if(continent_len > 0) {
	status = MMDB_get_value(&result.entry, &entry_data, "continent", "names", "en", NULL);
	
	if((status != MMDB_SUCCESS) || (!entry_data.has_data))
	  continent[0] = '\0';
	else {
	  int str_len = ndpi_min(entry_data.data_size, continent_len);
	  
	  memcpy(continent, entry_data.utf8_string, str_len);
	  continent[str_len] = '\0';
	}
      }
    }

    return(0);
  }
#endif

  return(-2);
}
