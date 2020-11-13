
#ifndef _DNS_UTILS_H
#define _DNS_UTILS_H

#include "ndpi_typedefs.h"

extern char* prot4L(char *ret, size_t len, int protCode);
extern char* dnsRespCode(char *ret, size_t len, enum DnsResponseCode respCode);
extern char* dnsClass(char *ret, size_t len, enum DnsClass classIndex);
extern char* dnsType(char *ret, size_t len, enum DnsType typeCode);
extern char *dnsRData(char *ret, size_t len, struct dnsRR_t *rr );

/* from dns.c */
extern void clear_all_dns_list(struct ndpi_flow_struct *flow);

extern void ndpi_patchIPv6Address(char *str);

#endif
