
#ifndef _DNS_UTILS_H
#define _DNS_UTILS_H

#include "ndpi_typedefs.h"

extern char* prot4L(char *ret, size_t len, int protCode);

/* from dns.c */
extern void clear_all_dns_list(struct ndpi_flow_struct *flow);

#endif
