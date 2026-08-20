#ifndef __NDPI_CATEGORY_HOST_NORM_H__
#define __NDPI_CATEGORY_HOST_NORM_H__

#include <stddef.h>

/* 0 = success (out is NUL-terminated normalized hostname), -1 = empty/invalid for .ndb */
int ndpi_category_normalize_host_for_ndb(const char *input, char *out, size_t out_sz);

/* 1 = reject as isolated public-TLD-style label (generator), 0 = ok */
int ndpi_category_hostname_is_isolated_tld(const char *normalized_host);

/* 1 = valid ASCII LDH labels, 0 = invalid */
int ndpi_category_hostname_labels_valid_ascii(const char *host);

#endif
