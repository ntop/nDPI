/*
 * ndpi_rules.c
 *
 * Copyright (C) 2020 - ntop.org
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

#ifdef HAVE_JSON_H
#include "json.h" /* JSON-C */
#include <errno.h>

//#define DEBUG_RULES

/* ******************************************************* */

static u_int8_t ndpi_l4string2value(const char *c) {
  if(strcasecmp(c, "tcp") == 0)       return(6);
  else if(strcasecmp(c, "udp") == 0)  return(17);
  else if(strcasecmp(c, "icmp") == 0) return(1);
  else return(0);
}

/* ******************************************************* */

int ndpi_parse_rule_peer(ndpi_rule_peer *p, json_object *def) {
  char *slash, numeric_ip[64];
  u_int8_t cidr = 0;
  json_object *obj;

  if(json_object_object_get_ex(def, "ip", &obj)) {
    const char *ip = json_object_get_string(obj);
    snprintf(numeric_ip, sizeof(numeric_ip), "%s", ip);
  } else
    return(-1);

  if(json_object_object_get_ex(def, "port", &obj))
    p->l4_port = (u_int16_t)json_object_get_int(obj);
  else
    return(-2);

  if((slash = strchr(numeric_ip, '/')) != NULL) {
    slash[0] = '\0';
    cidr = atoi(&slash[1]);
  }

  if(strchr(numeric_ip, '.') != NULL) {
    p->ip.ipv4 = inet_addr(numeric_ip); /* IPv4 */
    if(cidr == 0) cidr = 32;
  } else if(strchr(numeric_ip, ':') != NULL) {
    if(inet_pton(AF_INET6, numeric_ip, &p->ip.ipv6) != 1)
      return(-3);

    if(cidr == 0) cidr = 128;
    p->ip_v6 = 1;
  } else
    return(-4);

  p->cidr = cidr;
  return(0);
}

/* ******************************************************* */

static int ndpi_parse_line(struct ndpi_detection_module_struct *ndpi_str,
			   ndpi_rules *rules, u_int line_id, char *line) {
  enum json_tokener_error jerr = json_tokener_success;
  json_object *obj, *p = json_tokener_parse_verbose(line, &jerr);
  ndpi_rule *r;
  int rc = 0;

  if(!p) {
#ifdef DEBUG_RULES
    printf("[JSON Error @ line %u][%s] %s\n", line_id, json_tokener_error_desc(jerr), line);
#endif
    return(-1);
  }

  if((r = (ndpi_rule*)calloc(1, sizeof(ndpi_rule))) == NULL) {
    rc = -2;
    goto parse_error;
  }

  /* **************************** */

  if(json_object_object_get_ex(p, "rule", &obj)) {
    json_object *def = obj;

    if(json_object_object_get_ex(def, "id", &obj)) {
      r->id = (u_int16_t)json_object_get_int(obj);
    } else {
#ifdef DEBUG_RULES
      printf("[JSON Error @ line %u] %s\n", line_id, "Missing rule / id");
#endif
      rc = -3;
      goto parse_error;
    }

    if(json_object_object_get_ex(def, "description", &obj)) {
      r->description = strdup(json_object_get_string(obj));
    } else {
#ifdef DEBUG_RULES
      printf("[JSON Error @ line %u] %s\n", line_id, "Missing rule / description");
#endif
      rc = -4;
      goto parse_error;
    }
  }

  /* **************************** */

  if(json_object_object_get_ex(p, "network", &obj)) {
    json_object *def = obj;

    if(json_object_object_get_ex(def, "transport", &obj)) {
      if(json_object_get_type(obj) == json_type_int)
	r->l4_proto = (u_int8_t)json_object_get_int(obj);
      else if(json_object_get_type(obj) == json_type_string) {
	if((r->l4_proto = ndpi_l4string2value(json_object_get_string(obj))) == 0) {
	  rc = -5;
	  goto parse_error;
	}
      }
    }

    if(json_object_object_get_ex(def, "protocol", &obj)) {
      if(json_object_get_type(obj) == json_type_int)
	r->l7_proto = (u_int16_t)json_object_get_int(obj);
      else if(json_object_get_type(obj) == json_type_string)
	r->l7_proto = ndpi_get_protocol_id(ndpi_str,
					   (char*)json_object_get_string(obj));
      else {
	rc = -7;
	goto parse_error;
      }

      if((r->l7_proto == 0) || (r->l7_proto > NDPI_LAST_IMPLEMENTED_PROTOCOL)) {
	rc = -8;
	goto parse_error;
      }
    }
  }

  /* **************************** */

  if(json_object_object_get_ex(p, "client", &obj)) {
    if(ndpi_parse_rule_peer(&r->client, obj) != 0) {
      rc = -9;
      goto parse_error;
    }
  }

  /* **************************** */

  if(json_object_object_get_ex(p, "server", &obj)) {
    if(ndpi_parse_rule_peer(&r->server, obj) != 0) {
      rc = -10;
      goto parse_error;
    }
  }

  /* **************************** */

  if(json_object_object_get_ex(p, "server", &obj)) {
    if(ndpi_parse_rule_peer(&r->server, obj) != 0) {
      rc = -9;
      goto parse_error;
    }
  }

#ifdef DEBUG_RULES
  printf("[JSON %3u] %s [rc: %u]\n", line_id, line, rc);
#endif
  rules->num_rules++;

 parse_error:
  json_object_put(p); /* Free memory */

  return(rc);
}

/* ******************************************************* */

ndpi_rules* ndpi_parse_rules(struct ndpi_detection_module_struct *ndpi_str,
			     char *path) {
  FILE *fd = fopen(path, "r");
  char line[1024];
  u_int line_id = 0;
  ndpi_rules *rules;

#ifdef DEBUG_RULES

  if(!fd)
    printf("Unable to open file %s [%u/%s]\n", path, errno, strerror(errno));
#endif

  if((!fd) || ((rules = (ndpi_rules*)calloc(1, sizeof(ndpi_rules))) == NULL))
    return(NULL);

  while(fgets(line, sizeof(line), fd) != NULL) {
    u_int len = strlen(line);
    int rc;

    line_id++;

    if(len > 0) {
      len--;
      if(line[len] == '\n')
	line[len] = '\0';
    }

    if((rc = ndpi_parse_line(ndpi_str, rules, line_id, line)) != 0) {
#ifdef DEBUG_RULES
      printf("Invalid parsing of line %u [rc: %d]\n", line_id, rc);
#endif
    }
  }

  fclose(fd);
  return(rules);
}

/* ******************************************************* */

#endif /* HAVE_JSON_H */
