
#ifndef _DNS_UTILS_H
#define _DNS_UTILS_H

#include "ndpi_typedefs.h"

 char* prot4L(char *ret, int protCode);
 char* dnsRespCode(char *ret, enum DnsResponseCode respCode);
 char* dnsClass(char *ret, enum DnsClass classIndex);
 char* dnsType(char *ret, enum DnsType typeCode);
 char* dnsRData(char *ret, struct dnsRR_t *rr );

 void ndpi_patchIPv6Address(char *str);

#endif
