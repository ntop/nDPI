/*
 * ndpi_utils.c
 *
 * Copyright (C) 2011-24 - ntop.org and contributors
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "ndpi_api.h"
#include "ndpi_replace_printf.h"

static inline int ndpi_is_other_char(char c) {
  return((c == '.')
      || (c == ' ')
      || (c == '@')
      || (c == '/')
      );
}

static int _ndpi_is_valid_char(char c) {
  if(ndpi_ispunct(c) && (!ndpi_is_other_char(c)))
    return(0);
  else
    return(ndpi_isdigit(c)
        || ndpi_isalpha(c)
        || ndpi_is_other_char(c));
}
static char ndpi_is_valid_char_tbl[256],ndpi_is_valid_char_tbl_init=0;

static void _ndpi_is_valid_char_init(void) {
  int c;
  for(c=0; c < 256; c++) ndpi_is_valid_char_tbl[c] = _ndpi_is_valid_char(c);
  ndpi_is_valid_char_tbl_init = 1;
}

static inline int ndpi_is_valid_char(char c) {
  if(!ndpi_is_valid_char_tbl_init)
    _ndpi_is_valid_char_init();
  return ndpi_is_valid_char_tbl[(unsigned char)c];
}

static int ndpi_find_non_eng_bigrams(char *str) {
  char s[3];

  if((ndpi_isdigit(str[0]) && ndpi_isdigit(str[1]))
      || ndpi_is_other_char(str[0])
      || ndpi_is_other_char(str[1])
    )
    return(1);

  s[0] = tolower(str[0]), s[1] = tolower(str[1]), s[2] = '\0';

  return(ndpi_match_bigram(s));
}

/* #define PRINT_STRINGS 1 */

/**
 * @brief Detects human-readable strings in a binary buffer.
 *
 * This function scans a given buffer to identify and extract human-readable strings
 * based on ASCII character validation and bigram checks. If a valid string is found
 * with a length greater than or equal to `min_string_match_len`, it is stored in the
 * output buffer `outbuf`.
 *
 * @param buffer Pointer to the input buffer containing the data to be analyzed.
 * @param buffer_size Size of the input buffer in bytes.
 * @param min_string_match_len Minimum length for a string to be considered readable.
 * @param outbuf Pointer to the output buffer where the detected string will be stored.
 * @param outbuf_len Maximum size of the output buffer, including space for null termination.
 * @return Returns 1 if a human-readable string meeting the criteria is found and stored in `outbuf`,
 *         otherwise returns 0 if no such string is detected.
 *
 * @note The function modifies `outbuf` only if a valid string is found. The output buffer is
 *       null-terminated. The function stops scanning once a matching string is found.
 *
 * @warning Ensure `outbuf` has enough space (at least `outbuf_len` bytes) to store the detected string.
 */
int ndpi_has_human_readeable_string(char *buffer, u_int buffer_size,
    u_int8_t min_string_match_len,
    char *outbuf, u_int outbuf_len) {
  u_int ret = 0, i, do_cr = 0, len = 0, o_idx = 0, being_o_idx = 0;

  if(buffer_size <= 0)
    return(0);

  outbuf_len--;
  outbuf[outbuf_len] = '\0';

  for(i=0; i<buffer_size-2; i++) {
    if(ndpi_is_valid_char(buffer[i])
        && ndpi_is_valid_char(buffer[i+1])
        && ndpi_find_non_eng_bigrams(&buffer[i])) {
#ifdef PRINT_STRINGS
      printf("%c%c", buffer[i], buffer[i+1]);
#endif
      if(o_idx < outbuf_len) outbuf[o_idx++] = buffer[i];
      if(o_idx < outbuf_len) outbuf[o_idx++] = buffer[i+1];
      do_cr = 1, i += 1, len += 2;
    } else {
      if(ndpi_is_valid_char(buffer[i]) && do_cr) {
#ifdef PRINT_STRINGS
        printf("%c", buffer[i]);
#endif
        if(o_idx < outbuf_len) outbuf[o_idx++] = buffer[i];
        len += 1;
      }

      // printf("->> %c%c\n", ndpi_isprint(buffer[i]) ? buffer[i] : '.', ndpi_isprint(buffer[i+1]) ? buffer[i+1] : '.');
      if(do_cr) {
        if(len > min_string_match_len)
          ret = 1;
        else {
          o_idx = being_o_idx;
          being_o_idx = o_idx;
          outbuf[o_idx] = '\0';
        }

#ifdef PRINT_STRINGS
        printf(" [len: %u]%s\n", len, ret ? "<-- HIT" : "");
#endif

        if(ret)
          break;

        do_cr = 0, len = 0;
      }
    }
  }

#ifdef PRINT_STRINGS
  printf("=======>> Found string: %u\n", ret);
#endif

  return(ret);
}

 /* ******************************************************************* */

#define MAX_EXTRACTION_SIZE 1024

/**
 * @brief Creates a new string list with a specified initial capacity.
 *
 * This function allocates and initializes a string_list_t structure, allowing dynamic
 * addition of strings.
 *
 * @param initial_capacity The initial capacity of the string list.
 * @return A pointer to the newly allocated string_list_t structure, or NULL on failure.
 */
static string_list_t *string_list_create(size_t initial_capacity) {
  string_list_t *list = calloc(1, sizeof(string_list_t));
  if (!list)
    return NULL;

  list->capacity = (initial_capacity > 0) ? initial_capacity : 8;
  list->items = calloc(list->capacity, sizeof(char *));
  return list;
}

/**
 * @brief Frees the memory allocated for a string list.
 *
 * This function releases all allocated memory associated with the given string list,
 * including stored strings.
 *
 * @param list Pointer to the string list to be freed.
 */
void string_list_free(string_list_t *list) {
  if (!list)
    return;

  for (size_t i = 0; i < list->count; i++) {
    free(list->items[i]);
  }
  free(list->items);
  free(list);
}

/**
 * @brief Adds a string to the string list.
 *
 * This function appends a copy of the given string to the string list. If needed,
 * the list is automatically resized to accommodate more entries.
 *
 * @param list Pointer to the string list.
 * @param str The string to be added.
 * @return true if the string was added successfully, false on allocation failure.
 */
static bool string_list_add(string_list_t *list, const char *str) {
  if (!list || !str) return false;

  if (list->count == list->capacity) {// Relocate if necessary
    size_t new_capacity = list->capacity * 2;
    char **new_items = realloc(list->items, new_capacity * sizeof(char *));
    if (!new_items) return false;
    list->items = new_items;
    list->capacity = new_capacity;
  }

  list->items[list->count] = strdup(str);
  if (!list->items[list->count])
    return false;

  list->count++;
  return true;
}

/**
 * @brief Extracts readable strings from a binary buffer.
 *
 * This function scans a given binary buffer for readable strings based on the minimum
 * length and an optional filtering function. Extracted strings are stored in a
 * dynamically allocated string list.
 *
 * @param buffer Pointer to the input buffer.
 * @param buffer_len Size of the input buffer.
 * @param min_len Minimum length of readable strings to be extracted.
 * @param list_limit Maximum number of strings to store in the list.
 * @param filter_func A filtering function that determines whether a string should be included.
 * @return A pointer to a string_list_t containing the extracted strings, or NULL on failure.
 */
string_list_t* extract_readable_strings(const unsigned char *buffer, size_t buffer_len, size_t min_len,
    size_t list_limit, bool (*filter_func)(char *)) {

  if (!buffer || buffer_len == 0)
    return NULL;

  // Create a string list with an initial capacity of 5.
  string_list_t *result = string_list_create(5);
  if (!result)
    return NULL;

  char temp[MAX_EXTRACTION_SIZE + 1];
  size_t temp_idx = 0;

  // Simple "state machine": we assemble blocks of printable characters
  for (size_t i = 0; i < buffer_len; i++) {
    unsigned char c = buffer[i];

    // Check if it is printable ASCII (32..126) or something you want to accept
    // Adjust as needed (e.g.: allow Latin accents, UTF-8, etc.)
    if (c >= 32 && c < 127) {
      if (temp_idx < MAX_EXTRACTION_SIZE) {
        temp[temp_idx++] = (char)c;
      }
    } else {
      // Encountered non-printable character -> end of a block
      if (temp_idx > 0) {
        temp[temp_idx] = '\0';
        // Check minimum size
        if (temp_idx >= min_len) {
          // If there is a filter, call it here
          bool ok = true;
          if (filter_func) {
            ok = filter_func(temp);
          }
          if (ok) {
            string_list_add(result, temp);
          }
        }
        temp_idx = 0;
      }
    }

    if (result->count >= list_limit && temp_idx == 0)
      break;
  }

  // If you end the loop with temp_idx > 0, end the last block
  if (temp_idx > 0) {
    temp[temp_idx] = '\0';
    if (temp_idx >= min_len) {
      bool ok = true;
      if (filter_func) {
        ok = filter_func(temp);
      }
      if (ok) {
        string_list_add(result, temp);
      }
    }
    temp_idx = 0;
  }

  return result;
}