/*
 * Shared hostname normalization for .ndb generator and runtime.
 */
#include "ndpi_category_host_norm.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>
#if defined(_MSC_VER) && !defined(strncasecmp)
#define strncasecmp _strnicmp
#else
#include <strings.h>
#endif

static int count_colons(const char *s) {
  int n = 0;
  for(; *s; s++)
    if(*s == ':') n++;
  return n;
}

static void strip_scheme(char *s) {
  static const char *schemes[] = {"http://", "https://", NULL};
  for(int i = 0; schemes[i]; i++) {
    size_t len = strlen(schemes[i]);
    if(strncasecmp(s, schemes[i], len) == 0) {
      memmove(s, s + len, strlen(s + len) + 1);
      return;
    }
  }
}

static void strip_leading_wildcard(char *s) {
  while(strncmp(s, "*.", 2) == 0)
    memmove(s, s + 2, strlen(s + 2) + 1);
}

int ndpi_category_hostname_is_isolated_tld(const char *h) {
  static const char *tlds[] = {
    "com", "net", "org", "edu", "gov", "mil", "int", "arpa",
    "info", "biz", "name", "pro", "aero", "coop", "museum", "jobs", "mobi", "travel",
    "asia", "cat", "tel", "xxx", "post", "geo", "onion",
    NULL
  };

  if(!h || !*h || strchr(h, '.') != NULL)
    return 0;

  for(int i = 0; tlds[i]; i++) {
    if(strcmp(h, tlds[i]) == 0)
      return 1;
  }
  return 0;
}

int ndpi_category_hostname_labels_valid_ascii(const char *host) {
  const char *p;
  size_t total_len, lablen = 0;

  if(!host || !*host)
    return 0;

  total_len = strlen(host);
  if(total_len > 253)
    return 0;

  if(host[0] == '.' || host[total_len - 1] == '.')
    return 0;

  for(p = host; *p; ++p) {
    unsigned char c = (unsigned char)*p;

    if(c == '.') {
      if(lablen == 0 || lablen > 63)
        return 0;
      if(*(p - 1) == '-')
        return 0;
      lablen = 0;
      continue;
    }

    if(!(islower(c) || isdigit(c) || c == '-'))
      return 0;
    if(c == '-' && lablen == 0)
      return 0;
    lablen++;
    if(lablen > 63)
      return 0;
  }

  if(lablen == 0 || lablen > 63)
    return 0;
  if(host[total_len - 1] == '-')
    return 0;

  return 1;
}

int ndpi_category_normalize_host_for_ndb(const char *input, char *out, size_t out_sz) {
  size_t i = 0;

  if(!input || !out || out_sz < 2)
    return -1;

  while(*input && isspace((unsigned char)*input))
    input++;

  for(; *input && i + 1 < out_sz; ++input) {
    char c = *input;

    out[i++] = (char)tolower((unsigned char)c);
  }
  out[i] = '\0';

  if(out[0] == '\0')
    return -1;

  strip_scheme(out);

  if(out[0] == '\0')
    return -1;

  {
    char *p = strpbrk(out, "/?#");

    if(p)
      *p = '\0';
  }

  if(out[0] == '\0')
    return -1;

  {
    int colons = count_colons(out);
    if(colons > 1)
      return -1;
    if(colons == 1) {
      char *colon = strchr(out, ':');
      if(!colon)
        return -1;
      for(char *q = colon + 1; *q; q++) {
        if(!isdigit((unsigned char)*q))
          return -1;
      }
      *colon = '\0';
    }
  }

  {
    size_t len = strlen(out);
    while(len > 0 && out[len - 1] == '.') {
      out[len - 1] = '\0';
      len--;
    }
  }

  strip_leading_wildcard(out);

  if(out[0] == '\0')
    return -1;

  if(!ndpi_category_hostname_labels_valid_ascii(out))
    return -1;

  return 0;
}
