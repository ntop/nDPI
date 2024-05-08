/*
 * ndpi_domains.c
 *
 * Copyright (C) 2011-24 - ntop.org and contributors
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

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"
#include "ndpi_private.h"

/* ******************************* */

int ndpi_load_domain_suffixes(struct ndpi_detection_module_struct *ndpi_str,
			      char *public_suffix_list_path) {
  char buf[256], *line;
  FILE *fd;
  u_int16_t domain_id = 1;

  if(ndpi_str == NULL || public_suffix_list_path == NULL)
    return(-1);

  if((fd = fopen(public_suffix_list_path, "r")) == NULL)
    return(-2);

  if(ndpi_str->public_domain_suffixes != NULL) {
    /* An existing license was aleady loaded: free it and start over */
    ndpi_hash_free(&ndpi_str->public_domain_suffixes);
  }

  if(ndpi_hash_init(&ndpi_str->public_domain_suffixes) != 0)
    return(-3);

  while((line = fgets(buf, sizeof(buf), fd)) != NULL) {
    u_int offset, len;
    
    /* Skip private domains */
    if(strstr(line, "// ===END ICANN DOMAINS==="))
      break;

    /* Skip empty lines or comments */
    if((line[0] == '\0') || (line[0] == '/') || (line[0] == '\n') || (line[0] == '\r'))
      continue;

    if((line[0] == '*') && (line[1] == '.') && (line[2] != '\0'))
      offset = 2;
    else
      offset = 0;

    len = strlen(line) - 1;
    while((len > 0) && (line[len] == '\n'))
      line[len--] = '\0';

    if(ndpi_hash_add_entry(&ndpi_str->public_domain_suffixes,
			   &line[offset], strlen(&line[offset]), domain_id) != 0) {

      NDPI_LOG_ERR(ndpi_str, "Error while processing domain %s\n", &line[offset]);
    } else
      domain_id++;
  }

  fclose(fd);

  if(domain_id > 0)
    NDPI_LOG_DBG(ndpi_str, "Loaded %u domains\n", domain_id-1);

  return(0);
}

/* ******************************* */

/*
  Example
  - www.ntop.org -> org
  - www.bbc.co.uk -> co.uk
*/

const char* ndpi_get_host_domain_suffix(struct ndpi_detection_module_struct *ndpi_str,
					const char *hostname,
					u_int16_t *domain_id /* out */) {
  char *dot, *prev_dot;

  if(!ndpi_str || !hostname || !domain_id)
    return NULL;

  *domain_id = 0;

  if(ndpi_str->public_domain_suffixes == NULL)
    return(hostname);

  prev_dot = dot = strrchr(hostname, '.');

  while(dot != NULL) {
    while((dot != hostname) && (dot[0] != '.'))
      dot--;
    
    if((dot == hostname)
       || (ndpi_hash_find_entry(ndpi_str->public_domain_suffixes,
				&dot[1], strlen(&dot[1]), domain_id) != 0)) {
      /* Not found: end of search */
      return(&prev_dot[1]);
    }
    
    prev_dot = dot;
    dot--;
  }

  return(hostname);
}

/* ******************************* */

/*
  Example
  - www.ntop.org -> ntop.org
  - www.bbc.co.uk -> bbc.co.uk
*/
const char* ndpi_get_host_domain(struct ndpi_detection_module_struct *ndpi_str,
				 const char *hostname) {
  const char *ret;
  char *dot;
  u_int16_t domain_id;
  
  if(!ndpi_str)
    return NULL;

  if(ndpi_str->public_domain_suffixes == NULL)
    return(hostname);
  
  ret = ndpi_get_host_domain_suffix(ndpi_str, hostname, &domain_id);

  if((ret == NULL) || (ret == hostname))
    return(hostname);

  dot = strstr(hostname, ret);

  if(dot == NULL || dot == hostname)
    return(hostname);

  dot--;
  while(dot != hostname) {
    dot--;

    if(dot[0] == '.')
      return(&dot[1]);
  }
      
  return(hostname);
}
