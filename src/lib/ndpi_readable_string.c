/*
 * ndpi_readable_string.c
 *
 * Copyright (C) 2025 - ntop.org and contributors
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

#define MAX_EXTRACTION_SIZE 1024

/**
 * @brief Creates a new string list with a specified initial capacity.
 *
 * This function allocates and initializes a ndpi_string_list_t structure, allowing dynamic
 * addition of strings.
 *
 * @param initial_capacity The initial number of elements that can be stored in the list.
 *                         If zero, the default value of 8 is used.
 * @return A pointer to the newly allocated ndpi_string_list_t structure, or NULL on failure.
 *
 * @note The caller is responsible for freeing the allocated memory using `ndpi_string_list_free()`
 *       or equivalent deallocation logic to prevent memory leaks.
 */
static ndpi_string_list_t *string_list_create(size_t initial_capacity) {
  ndpi_string_list_t *list = (ndpi_string_list_t *) ndpi_malloc(sizeof(ndpi_string_list_t));
  if (!list)
    return NULL;

  list->capacity = (initial_capacity > 0) ? initial_capacity : 8;
  list->count = 0;
  list->items = (char **) ndpi_malloc(list->capacity * sizeof(char *));

  if (!list->items) {
    ndpi_free(list);
    return NULL;
  }

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
void ndpi_string_list_free(ndpi_string_list_t *list) {
  if (!list)
    return;

  for (size_t i = 0; i < list->count; i++) {
    ndpi_free(list->items[i]);
  }
  ndpi_free(list->items);
  ndpi_free(list);
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
static bool string_list_add(ndpi_string_list_t *list, const char *str) {
  if (!list || !str) return false;

  if (list->count == list->capacity) { // Resize if needed
    size_t new_capacity = list->capacity * 2;
    char **new_items = (char **) ndpi_malloc(new_capacity * sizeof(char *));
    if (!new_items) return false;

    // Copy existing data to the new allocated block
    memcpy(new_items, list->items, list->count * sizeof(char *));
    ndpi_free(list->items);

    list->items = new_items;
    list->capacity = new_capacity;
  }

  list->items[list->count] = ndpi_strdup(str);
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
 * @return A pointer to a ndpi_string_list_t containing the extracted strings, or NULL on failure.
 */
ndpi_string_list_t* ndpi_extract_readable_strings(const unsigned char *buffer, size_t buffer_len, size_t min_len,
    size_t list_limit, bool (*filter_func)(char *)) {

  if (!buffer || buffer_len == 0)
    return NULL;

  // Create a string list with an initial capacity of 5.
  ndpi_string_list_t *result = string_list_create(5);
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
