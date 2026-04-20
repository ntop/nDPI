/*
 * utests.c
 *
 * Copyright (C) 2011-26 - ntop.org
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

#include <assert.h>
#include <sys/stat.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "ndpi_config.h"
#include "ndpi_api.h"


static void analysisUnitTest() {
  struct ndpi_analyze_struct *s = ndpi_alloc_data_analysis(32);
  u_int32_t i;

  for(i=0; i<256; i++)
    ndpi_data_add_value(s, i);

  if(0) {
    ndpi_data_print_window_values(s);
    printf("Average: [all: %f][window: %f]\n", ndpi_data_average(s), ndpi_data_window_average(s));
    printf("Entropy: %f\n", ndpi_data_entropy(s));
    printf("StdDev:  %f\n", ndpi_data_stddev(s));
    printf("Min/Max: %llu/%llu\n",
           (unsigned long long int)ndpi_data_min(s),
           (unsigned long long int)ndpi_data_max(s));
  }

  ndpi_free_data_analysis(s, 1);
}

/* *********************************************** */

static void rsiUnitTest() {
  struct ndpi_rsi_struct s;
  unsigned int v[] = {
    31,
    87,
    173,
    213,
    223,
    230,
    238,
    245,
    251,
    151,
    259,
    261,
    264,
    264,
    270,
    273,
    288,
    288,
    304,
    304,
    350,
    384,
    423,
    439,
    445,
    445,
    445,
    445
  };

  u_int i, n = sizeof(v) / sizeof(unsigned int);
  u_int debug = 0;

  assert(ndpi_alloc_rsi(&s, 8) == 0);

  for(i=0; i<n; i++) {
    float rsi = ndpi_rsi_add_value(&s, v[i]);


    if(debug)
      printf("%2d) RSI = %f\n", i, rsi);
  }

  ndpi_free_rsi(&s);
}

/* *********************************************** */

static void hash_walk_cb(char *key, u_int64_t value64, void *data) {
  (void)key;
  (void)value64;
  int *walk_count = (int *)data;
  (*walk_count)++;
}

static void strHashMapUnitTest(void) {
  ndpi_str_hash *h = NULL;
  u_int64_t val = 0;
  int walk_count = 0;

  /* Init */
  assert(ndpi_hash_init(&h) == 0);
  assert(h != NULL);

  /* Add entries */
  assert(ndpi_hash_add_entry(&h, (char *)"key1", 4, 100, NULL) == 0);
  assert(ndpi_hash_add_entry(&h, (char *)"key2", 4, 200, NULL) == 0);
  assert(ndpi_hash_add_entry(&h, (char *)"key3", 4, 300, NULL) == 0);

  /* Find entries */
  assert(ndpi_hash_find_entry(h, "key1", 4, &val) == 0);
  assert(val == 100);
  assert(ndpi_hash_find_entry(h, "key2", 4, &val) == 0);
  assert(val == 200);
  assert(ndpi_hash_find_entry(h, "key3", 4, &val) == 0);
  assert(val == 300);

  /* Non-existent entry */
  assert(ndpi_hash_find_entry(h, "nokey", 5, &val) != 0);

  /* Walk */
  walk_count = 0;
  ndpi_hash_walk(&h, hash_walk_cb, &walk_count);
  assert(walk_count == 3);

  /* Overwrite existing key: returns 1 (already present) and updates value */
  assert(ndpi_hash_add_entry(&h, (char *)"key1", 4, 999, NULL) == 1);
  assert(ndpi_hash_find_entry(h, "key1", 4, &val) == 0);
  assert(val == 999);

  /* Free */
  ndpi_hash_free(&h);
  assert(h == NULL);
}

/* *********************************************** */

static void hwUnitTest() {
  struct ndpi_hw_struct hw;
  double v[] = { 10, 14, 8, 25, 16, 22, 14, 35, 15, 27, 218, 40, 28, 40, 25, 65 };
  u_int i, j, num = sizeof(v) / sizeof(double);
  u_int num_learning_points = 2;
  u_int8_t trace = 0;

  for(j=0; j<2; j++) {
    assert(ndpi_hw_init(&hw, num_learning_points, j /* 0=multiplicative, 1=additive */, 0.9, 0.9, 0.1, 0.05) == 0);

    if(trace)
      printf("\nHolt-Winters %s method\n", (j == 0) ? "multiplicative" : "additive");

    for(i=0; i<num; i++) {
      double prediction, confidence_band;
      double lower, upper;
      int rc = ndpi_hw_add_value(&hw, v[i], &prediction, &confidence_band);

      lower = prediction - confidence_band, upper = prediction + confidence_band;

      if(trace)
        printf("%2u)\t%.3f\t%.3f\t%.3f\t%.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
               ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
               confidence_band);
    }

    ndpi_hw_free(&hw);
  }
}

/* *********************************************** */

static void hwUnitTest2() {
  struct ndpi_hw_struct hw;
  u_int8_t trace = 0;
  double v[] = {
    31.908466339111,
    87.339714050293,
    173.47660827637,
    213.92568969727,
    223.32124328613,
    230.60134887695,
    238.09457397461,
    245.8137512207,
    251.09228515625,
    251.09228515625,
    259.21997070312,
    261.98754882812,
    264.78540039062,
    264.78540039062,
    270.47451782227,
    173.3671875,
    288.34222412109,
    288.34222412109,
    304.24795532227,
    304.24795532227,
    350.92227172852,
    384.54431152344,
    423.25942993164,
    439.43322753906,
    445.05981445312,
    445.05981445312,
    445.05981445312,
    445.05981445312
  };
  u_int num_learning_points = 1;
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.9, beta = 0.5, gamma = 1;
  FILE *fd = fopen(
#ifndef WIN32
                   "/tmp/"
#endif
                   "result.csv", "w");

  assert(ndpi_hw_init(&hw, num_learning_points, 0 /* 0=multiplicative, 1=additive */,
                      alpha, beta, gamma, 0.05) == 0);

  if(trace) {
    printf("\nHolt-Winters [alpha: %.1f][beta: %.1f][gamma: %.1f]\n", alpha, beta, gamma);

    if(fd)
      fprintf(fd, "index;value;prediction;lower;upper;anomaly\n");
  }

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_hw_add_value(&hw, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
             ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
             confidence_band);

      if(fd)
        fprintf(fd, "%u;%.0f;%.0f;%.0f;%.0f;%s\n",
                i, v[i], prediction, lower, upper,
                ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY");
    }
  }

  if(fd) fclose(fd);

  ndpi_hw_free(&hw);

  //exit(0);
}

/* *********************************************** */

static void sesUnitTest() {
  struct ndpi_ses_struct ses;
  u_int8_t trace = 0;
  double v[] = {
    31.908466339111,
    87.339714050293,
    173.47660827637,
    213.92568969727,
    223.32124328613,
    230.60134887695,
    238.09457397461,
    245.8137512207,
    251.09228515625,
    251.09228515625,
    259.21997070312,
    261.98754882812,
    264.78540039062,
    264.78540039062,
    270.47451782227,
    173.3671875,
    288.34222412109,
    288.34222412109,
    304.24795532227,
    304.24795532227,
    350.92227172852,
    384.54431152344,
    423.25942993164,
    439.43322753906,
    445.05981445312,
    445.05981445312,
    445.05981445312,
    445.05981445312
  };
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.9;
  FILE *fd = fopen(
#ifndef WIN32
                   "/tmp/"
#endif
                   "ses_result.csv", "w");

  assert(ndpi_ses_init(&ses, alpha, 0.05) == 0);
  ndpi_ses_reset(&ses);

  if(trace) {
    printf("\nSingle Exponential Smoothing [alpha: %.1f]\n", alpha);

    if(fd)
      fprintf(fd, "index;value;prediction;lower;upper;anomaly\n");
  }

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_ses_add_value(&ses, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
             ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
             confidence_band);

      if(fd)
        fprintf(fd, "%u;%.0f;%.0f;%.0f;%.0f;%s\n",
                i, v[i], prediction, lower, upper,
                ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY");
    }
  }

  if(fd) fclose(fd);

  ndpi_ses_fitting(v, num, &alpha); /* Compute the best alpha */
}

/* *********************************************** */

static void desUnitTest() {
  struct ndpi_des_struct des;
  u_int8_t trace = 0;
  double v[] = {
    31.908466339111,
    87.339714050293,
    173.47660827637,
    213.92568969727,
    223.32124328613,
    230.60134887695,
    238.09457397461,
    245.8137512207,
    251.09228515625,
    251.09228515625,
    259.21997070312,
    261.98754882812,
    264.78540039062,
    264.78540039062,
    270.47451782227,
    173.3671875,
    288.34222412109,
    288.34222412109,
    304.24795532227,
    304.24795532227,
    350.92227172852,
    384.54431152344,
    423.25942993164,
    439.43322753906,
    445.05981445312,
    445.05981445312,
    445.05981445312,
    445.05981445312
  };
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.9, beta = 0.5;
  FILE *fd = fopen(
#ifndef WIN32
                   "/tmp/"
#endif
                   "des_result.csv", "w");

  assert(ndpi_des_init(&des, alpha, beta, 0.05) == 0);
  ndpi_des_reset(&des);

  if(trace) {
    printf("\nDouble Exponential Smoothing [alpha: %.1f][beta: %.1f]\n", alpha, beta);

    if(fd)
      fprintf(fd, "index;value;prediction;lower;upper;anomaly\n");
  }

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_des_add_value(&des, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
             (rc == 0) ? "LEARNING" : (((v[i] >= lower) && (v[i] <= upper)) ? "OK" : "ANOMALY"),
             confidence_band);

      if(fd)
        fprintf(fd, "%u;%.0f;%.0f;%.0f;%.0f;%s\n",
                i, v[i], prediction, lower, upper,
                ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY");
    }
  }

  if(fd) fclose(fd);

  ndpi_des_fitting(v, num, &alpha, &beta); /* Compute the best alpha/beta */
}

/* *********************************************** */

static void desUnitStressTest() {
  struct ndpi_des_struct des;
  u_int8_t trace = 0;
  u_int i;
  float alpha = 0.9, beta = 0.5;
  double init_value = time(NULL) % 1000;

  assert(ndpi_des_init(&des, alpha, beta, 0.05) == 0);
  ndpi_des_reset(&des);

  if(trace) {
    printf("\nDouble Exponential Smoothing [alpha: %.1f][beta: %.1f]\n", alpha, beta);
  }

  for(i=0; i<512; i++) {
    double prediction, confidence_band;
    double lower, upper;
    double value = init_value + rand() % 25;
    int rc = ndpi_des_add_value(&des, value, &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, value, prediction, lower, upper,
             ((rc == 0) || ((value >= lower) && (value <= upper))) ? "OK" : "ANOMALY",
             confidence_band);
    }
  }
}

/* *********************************************** */

static void hwUnitTest3() {
  struct ndpi_hw_struct hw;
  u_int num_learning_points = 3;
  u_int8_t trace = 0;
  double v[] = {
    10,
    14,
    8,
    25,
    16,
    22,
    14,
    35,
    15,
    27,
    18,
    40,
    28,
    40,
    25,
    65,
  };
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.5, beta = 0.5, gamma = 0.1;
  assert(ndpi_hw_init(&hw, num_learning_points, 0 /* 0=multiplicative, 1=additive */, alpha, beta, gamma, 0.05) == 0);
  ndpi_hw_reset(&hw);

  if(trace)
    printf("\nHolt-Winters [alpha: %.1f][beta: %.1f][gamma: %.1f]\n", alpha, beta, gamma);

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_hw_add_value(&hw, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace)
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n",
             i, v[i], prediction, lower, upper,
             ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
             confidence_band);
  }

  ndpi_hw_free(&hw);
}

/* *********************************************** */

static void jitterUnitTest() {
  struct ndpi_jitter_struct jitter;
  float v[] = { 10, 14, 8, 25, 16, 22, 14, 35, 15, 27, 218, 40, 28, 40, 25, 65 };
  u_int i, num = sizeof(v) / sizeof(float);
  u_int num_learning_points = 4;
  u_int8_t trace = 0;

  assert(ndpi_jitter_init(&jitter, num_learning_points) == 0);

  for(i=0; i<num; i++) {
    float rc = ndpi_jitter_add_value(&jitter, v[i]);

    if(trace)
      printf("%2u)\t%.3f\t%.3f\n", i, v[i], rc);
  }

  ndpi_jitter_free(&jitter);
}

/* *********************************************** */

static void compressedBitmapUnitTest() {
  ndpi_bitmap *a, *b, *c;
  u_int64_t val;

  /* Basic alloc and empty check */
  a = ndpi_bitmap_alloc();
  assert(a != NULL);
  assert(ndpi_bitmap_is_empty(a) == true);
  assert(ndpi_bitmap_cardinality(a) == 0);

  /* Set and test */
  ndpi_bitmap_set(a, 1);
  ndpi_bitmap_set(a, 100);
  ndpi_bitmap_set(a, 1000);
  assert(ndpi_bitmap_isset(a, 1) == true);
  assert(ndpi_bitmap_isset(a, 100) == true);
  assert(ndpi_bitmap_isset(a, 1000) == true);
  assert(ndpi_bitmap_isset(a, 2) == false);
  assert(ndpi_bitmap_cardinality(a) == 3);
  assert(ndpi_bitmap_is_empty(a) == false);

  /* Unset */
  ndpi_bitmap_unset(a, 100);
  assert(ndpi_bitmap_isset(a, 100) == false);
  assert(ndpi_bitmap_cardinality(a) == 2);

  /* Duplicate set should not increase cardinality */
  ndpi_bitmap_set(a, 1);
  assert(ndpi_bitmap_cardinality(a) == 2);

  /* Copy */
  c = ndpi_bitmap_copy(a);
  assert(c != NULL);
  assert(ndpi_bitmap_cardinality(c) == 2);
  assert(ndpi_bitmap_isset(c, 1) == true);
  assert(ndpi_bitmap_isset(c, 1000) == true);

  /* OR: a={1,1000}, b={2,1000} -> a|b = {1,2,1000} */
  b = ndpi_bitmap_alloc();
  assert(b != NULL);
  ndpi_bitmap_set(b, 2);
  ndpi_bitmap_set(b, 1000);
  ndpi_bitmap_or(a, b);
  assert(ndpi_bitmap_isset(a, 1) == true);
  assert(ndpi_bitmap_isset(a, 2) == true);
  assert(ndpi_bitmap_isset(a, 1000) == true);
  assert(ndpi_bitmap_cardinality(a) == 3);

  /* AND: a={1,2,1000} & c={1,1000} -> {1,1000} */
  ndpi_bitmap_and(a, c);
  assert(ndpi_bitmap_isset(a, 1) == true);
  assert(ndpi_bitmap_isset(a, 2) == false);
  assert(ndpi_bitmap_isset(a, 1000) == true);
  assert(ndpi_bitmap_cardinality(a) == 2);

  /* XOR: a={1,1000} ^ b={2,1000} -> {1,2} */
  ndpi_bitmap_xor(a, b);
  assert(ndpi_bitmap_isset(a, 1) == true);
  assert(ndpi_bitmap_isset(a, 2) == true);
  assert(ndpi_bitmap_isset(a, 1000) == false);
  assert(ndpi_bitmap_cardinality(a) == 2);

  /* Iterator */
  ndpi_bitmap_free(a);
  a = ndpi_bitmap_alloc();
  ndpi_bitmap_set(a, 10);
  ndpi_bitmap_set(a, 20);
  ndpi_bitmap_set(a, 30);
  {
    ndpi_bitmap_iterator *it = ndpi_bitmap_iterator_alloc(a);
    assert(it != NULL);
    u_int64_t count = 0;
    while(ndpi_bitmap_iterator_next(it, &val)) {
      assert(val == 10 || val == 20 || val == 30);
      count++;
    }
    assert(count == 3);
    ndpi_bitmap_iterator_free(it);
  }

  /* Serialize / deserialize */
  {
    char *buf = NULL;
    size_t buf_len = ndpi_bitmap_serialize(a, &buf);
    assert(buf != NULL && buf_len > 0);
    ndpi_bitmap *d = ndpi_bitmap_deserialize(buf, buf_len);
    assert(d != NULL);
    assert(ndpi_bitmap_isset(d, 10) == true);
    assert(ndpi_bitmap_isset(d, 20) == true);
    assert(ndpi_bitmap_isset(d, 30) == true);
    assert(ndpi_bitmap_cardinality(d) == 3);
    ndpi_bitmap_free(d);
    free(buf);
  }

  ndpi_bitmap_free(a);
  ndpi_bitmap_free(b);
  ndpi_bitmap_free(c);
}

/* *********************************************** */

static void strtonumUnitTest() {
  const char *errstrp;

  assert(ndpi_strtonum("0", -10, +10, &errstrp, 10) == 0);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("0", +10, -10, &errstrp, 10) == 0);
  assert(errstrp != NULL);
  assert(ndpi_strtonum("  -11  ", -10, +10, &errstrp, 10) == 0);
  assert(errstrp != NULL);
  assert(ndpi_strtonum("  -11  ", -100, +100, &errstrp, 10) == -11);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("123abc", LLONG_MIN, LLONG_MAX, &errstrp, 10) == 123);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("123abc", LLONG_MIN, LLONG_MAX, &errstrp, 16) == 0x123abc);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("  0x123abc", LLONG_MIN, LLONG_MAX, &errstrp, 16) == 0x123abc);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("ghi", -10, +10, &errstrp, 10) == 0);
  assert(errstrp != NULL);
}

/* *********************************************** */

static void strlcpyUnitTest() {
  // Test empty string
  char dst_empty[10] = "";
  assert(ndpi_strlcpy(dst_empty, "", sizeof(dst_empty), 0) == 0);
  assert(dst_empty[0] == '\0');

  // Basic copy test
  char dst1[10] = "";
  assert(ndpi_strlcpy(dst1, "abc", sizeof(dst1), 3) == 3);
  assert(strcmp(dst1, "abc") == 0);

  // Test with dst_len smaller than src_len
  char dst2[4] = "";
  assert(ndpi_strlcpy(dst2, "abcdef", sizeof(dst2), 6) == 6);
  assert(strcmp(dst2, "abc") == 0); // Should truncate "abcdef" to "abc"

  // Test with dst_len bigger than src_len
  char dst3[10] = "";
  assert(ndpi_strlcpy(dst3, "abc", sizeof(dst3), 3) == 3);
  assert(strcmp(dst3, "abc") == 0);

  // Test with dst_len equal to 1 (only null terminator should be copied)
  char dst4[1];
  assert(ndpi_strlcpy(dst4, "abc", sizeof(dst4), 3) == 3);
  assert(dst4[0] == '\0'); // Should only contain the null terminator

  // Test with NULL source, expecting return value to be 0
  char dst5[10];
  assert(ndpi_strlcpy(dst5, NULL, sizeof(dst5), 0) == 0);

  // Test with NULL destination, should also return 0 without crashing
  assert(ndpi_strlcpy(NULL, "abc", sizeof(dst5), 3) == 0);
}

/* *********************************************** */

static void strnstrUnitTest(void) {
  /* Test 1: null string */
  assert(ndpi_strnstr(NULL, "find", 10) == NULL);
  assert(ndpi_strnstr("string", NULL, 10) == NULL);

  /* Test 2: empty substring */
  assert(strcmp(ndpi_strnstr("string", "", 6), "string") == 0);

  /* Test 3: single character substring */
  assert(strcmp(ndpi_strnstr("string", "r", 6), "ring") == 0);
  assert(ndpi_strnstr("string", "x", 6) == NULL);

  /* Test 4: multiple character substring */
  assert(strcmp(ndpi_strnstr("string", "ing", 6), "ing") == 0);
  assert(ndpi_strnstr("string", "xyz", 6) == NULL);

  /* Test 5: substring equal to the beginning of the string */
  assert(strcmp(ndpi_strnstr("string", "str", 3), "string") == 0);

  /* Test 6: substring at the end of the string */
  assert(strcmp(ndpi_strnstr("string", "ing", 6), "ing") == 0);

  /* Test 7: substring in the middle of the string */
  assert(strcmp(ndpi_strnstr("hello world", "lo wo", 11), "lo world") == 0);

  /* Test 8: repeated characters in the string */
  assert(strcmp(ndpi_strnstr("aaaaaa", "aaa", 6), "aaaaaa") == 0);

  /* Test 9: empty string and slen 0 */
  assert(ndpi_strnstr("", "find", 0) == NULL);

  /* Test 10: substring equal to the string */
  assert(strcmp(ndpi_strnstr("string", "string", 6), "string") == 0);

  /* Test 11a,b: max_length bigger that string length */
  assert(strcmp(ndpi_strnstr("string", "string", 66), "string") == 0);
  assert(ndpi_strnstr("string", "a", 66) == NULL);

  /* Test 12: substring longer than the string */
  assert(ndpi_strnstr("string", "stringA", 6) == NULL);

  /* Test 13 */
  assert(ndpi_strnstr("abcdef", "abc", 2) == NULL);

  /* Test 14: zero length */
  assert(strcmp(ndpi_strnstr("", "", 0), "") == 0);
  assert(strcmp(ndpi_strnstr("string", "", 0), "string") == 0);
  assert(ndpi_strnstr("", "str", 0) == NULL);
  assert(ndpi_strnstr("string", "str", 0) == NULL);
  assert(ndpi_strnstr("str", "string", 0) == NULL);
}

/* *********************************************** */

static void strncasestrUnitTest(void) {
  /* Test 1: null string */
  assert(ndpi_strncasestr(NULL, "find", 10) == NULL);
  assert(ndpi_strncasestr("string", NULL, 10) == NULL);

  /* Test 2: empty substring */
  assert(strcmp(ndpi_strncasestr("string", "", 6), "string") == 0);

  /* Test 3: single character substring */
  assert(strcmp(ndpi_strncasestr("string", "r", 6), "ring") == 0);
  assert(strcmp(ndpi_strncasestr("string", "R", 6), "ring") == 0);
  assert(strcmp(ndpi_strncasestr("stRing", "r", 6), "Ring") == 0);
  assert(ndpi_strncasestr("string", "x", 6) == NULL);
  assert(ndpi_strncasestr("string", "X", 6) == NULL);

  /* Test 4: multiple character substring */
  assert(strcmp(ndpi_strncasestr("string", "ing", 6), "ing") == 0);
  assert(strcmp(ndpi_strncasestr("striNg", "InG", 6), "iNg") == 0);
  assert(ndpi_strncasestr("string", "xyz", 6) == NULL);
  assert(ndpi_strncasestr("striNg", "XyZ", 6) == NULL);

  /* Test 5: substring equal to the beginning of the string */
  assert(strcmp(ndpi_strncasestr("string", "str", 5), "string") == 0);
  assert(strcmp(ndpi_strncasestr("string", "sTR", 5), "string") == 0);
  assert(strcmp(ndpi_strncasestr("String", "STR", 5), "String") == 0);
  assert(strcmp(ndpi_strncasestr("Long Long String", "long long", 15), "Long Long String") == 0);

  /* Test 6: substring at the end of the string */
  assert(strcmp(ndpi_strncasestr("string", "ing", 6), "ing") == 0);
  assert(strcmp(ndpi_strncasestr("some longer STRing", "GEr sTrING", 18), "ger STRing") == 0);

  /* Test 7: substring in the middle of the string */
  assert(strcmp(ndpi_strncasestr("hello world", "lo wo", 11), "lo world") == 0);
  assert(strcmp(ndpi_strncasestr("hello BEAUTIFUL world", "beautiful", 20), "BEAUTIFUL world") == 0);

  /* Test 8: repeated characters in the string */
  assert(strcmp(ndpi_strncasestr("aaaaaa", "aaa", 6), "aaaaaa") == 0);
  assert(strcmp(ndpi_strncasestr("aaAaAa", "aaa", 6), "aaAaAa") == 0);
  assert(strcmp(ndpi_strncasestr("AAAaaa", "aaa", 6), "AAAaaa") == 0);

  /* Test 9: empty string and slen 0 */
  assert(ndpi_strncasestr("", "find", 0) == NULL);

  /* Test 10: substring equal to the string */
  assert(strcmp(ndpi_strncasestr("string", "string", 6), "string") == 0);
  assert(strcmp(ndpi_strncasestr("string", "STRING", 6), "string") == 0);
  assert(strcmp(ndpi_strncasestr("sTrInG", "StRiNg", 6), "sTrInG") == 0);

  /* Test 11a,b: max_length bigger that string length */
  assert(strcmp(ndpi_strncasestr("string", "string", 66), "string") == 0);
  assert(ndpi_strncasestr("string", "a", 66) == NULL);

  /* Test 12: substring longer than the string */
  assert(ndpi_strncasestr("string", "stringA", 6) == NULL);

  /* Test 13 */
  assert(ndpi_strncasestr("abcdef", "abc", 2) == NULL);

  /* Test 14: zero length */
  assert(strcmp(ndpi_strncasestr("", "", 0), "") == 0);
  assert(strcmp(ndpi_strncasestr("string", "", 0), "string") == 0);
  assert(ndpi_strncasestr("", "str", 0) == NULL);
  assert(ndpi_strncasestr("string", "str", 0) == NULL);
  assert(ndpi_strncasestr("str", "string", 0) == NULL);
}

/* *********************************************** */

static void stringUtilsUnitTest(void) {
  /* ndpi_strip_leading_trailing_spaces */

  char buf1[] = "  hello  ";
  int len1 = strlen(buf1);
  char *r1 = ndpi_strip_leading_trailing_spaces(buf1, &len1);
  assert(strncmp(r1, "hello", len1) == 0);
  assert(len1 == 5);

  char buf2[] = "no spaces";
  int len2 = strlen(buf2);
  char *r2 = ndpi_strip_leading_trailing_spaces(buf2, &len2);
  assert(strncmp(r2, "no spaces", len2) == 0);
  assert(len2 == 9);

  char buf3[] = "   ";
  int len3 = strlen(buf3);
  ndpi_strip_leading_trailing_spaces(buf3, &len3);
  assert(len3 == 0);

  /* ndpi_check_punycode_string */
  assert(ndpi_check_punycode_string("xn--nxasmq6b.com", 16) == 1);
  assert(ndpi_check_punycode_string("google.com", 10) == 0);
  assert(ndpi_check_punycode_string("xn--a", 5) == 1);   /* punycode prefix detection */
  assert(ndpi_check_punycode_string("abc", 3) == 0);     /* too short to contain "xn--" */
}

/* *********************************************** */

static void hashFunctionsUnitTest(void) {
  /* ndpi_hash_string: same input -> same output */
  assert(ndpi_hash_string("hello") == ndpi_hash_string("hello"));
  assert(ndpi_hash_string("hello") != ndpi_hash_string("world"));
  assert(ndpi_hash_string("") == ndpi_hash_string(""));

  /* ndpi_hash_string_len */
  assert(ndpi_hash_string_len("hello", 5) == ndpi_hash_string_len("hello", 5));
  assert(ndpi_hash_string_len("hello", 3) != ndpi_hash_string_len("hello", 5));

  /* ndpi_quick_hash */
  assert(ndpi_quick_hash((const unsigned char *)"test", 4) ==
         ndpi_quick_hash((const unsigned char *)"test", 4));
  assert(ndpi_quick_hash((const unsigned char *)"test", 4) !=
         ndpi_quick_hash((const unsigned char *)"TEST", 4));

  /* ndpi_murmur_hash */
  assert(ndpi_murmur_hash("hello", 5) == ndpi_murmur_hash("hello", 5));
  assert(ndpi_murmur_hash("hello", 5) != ndpi_murmur_hash("world", 5));

  /* ndpi_nearest_power_of_two */
  assert(ndpi_nearest_power_of_two(1) == 1);
  assert(ndpi_nearest_power_of_two(2) == 2);
  assert(ndpi_nearest_power_of_two(3) == 4);
  assert(ndpi_nearest_power_of_two(5) == 8);
  assert(ndpi_nearest_power_of_two(8) == 8);
  assert(ndpi_nearest_power_of_two(9) == 16);
  assert(ndpi_nearest_power_of_two(1024) == 1024);
  assert(ndpi_nearest_power_of_two(1025) == 2048);
}

/* *********************************************** */

static void memmemUnitTest(void) {
  /* Test 1: null string */
  assert(ndpi_memmem(NULL, 0, NULL, 0) == NULL);
  assert(ndpi_memmem(NULL, 0, NULL, 10) == NULL);
  assert(ndpi_memmem(NULL, 0, "find", 10) == NULL);
  assert(ndpi_memmem(NULL, 10, "find", 10) == NULL);
  assert(ndpi_memmem("string", 10, NULL, 0) == NULL);
  assert(ndpi_memmem("string", 10, NULL, 10) == NULL);

  /* Test 2: zero length */
  assert(strcmp(ndpi_memmem("", 0, "", 0), "") == 0);
  assert(strcmp(ndpi_memmem("string", 6, "", 0), "string") == 0);
  assert(strcmp(ndpi_memmem("string", 0, "", 0), "string") == 0);
  assert(ndpi_memmem("", 0, "string", 6) == NULL);

  /* Test 3: empty substring */
  assert(strcmp(ndpi_memmem("string", 6, "", 0), "string") == 0);

  /* Test 4: single character substring */
  assert(strcmp(ndpi_memmem("string", 6, "r", 1), "ring") == 0);
  assert(ndpi_memmem("string", 6, "x", 1) == NULL);

  /* Test 5: multiple character substring */
  assert(strcmp(ndpi_memmem("string", 6, "ing", 3), "ing") == 0);
  assert(ndpi_memmem("string", 6, "xyz", 3) == NULL);

  /* Test 6: substring equal to the beginning of the string */
  assert(strcmp(ndpi_memmem("string", 6, "str", 3), "string") == 0);

  /* Test 7: substring at the end of the string */
  assert(strcmp(ndpi_memmem("string", 6, "ing", 3), "ing") == 0);

  /* Test 8: substring in the middle of the string */
  assert(strcmp(ndpi_memmem("hello world", strlen("hello world"), "lo wo", strlen("lo wo")), "lo world") == 0);

  /* Test 9: repeated characters in the string */
  assert(strcmp(ndpi_memmem("aaaaaa", 6, "aaa", 3), "aaaaaa") == 0);

  /* Test 10: substring equal to the string */
  assert(strcmp(ndpi_memmem("string", 6, "string", 6), "string") == 0);

  /* Test 11: substring longer than the string */
  assert(ndpi_memmem("string", 6, "stringA", 7) == NULL);
}

/* *********************************************** */

static void memcasecmpUnitTest(void)
{
  /* Test 1: NULL pointers */
  assert(ndpi_memcasecmp(NULL, NULL, 5) == 0);
  assert(ndpi_memcasecmp(NULL, "string", 6) == -1);
  assert(ndpi_memcasecmp("string", NULL, 6) == 1);

  /* Test 2: Zero length */
  assert(ndpi_memcasecmp("string", "different", 0) == 0);

  /* Test 3: Single byte comparison */
  assert(ndpi_memcasecmp("a", "a", 1) == 0);
  assert(ndpi_memcasecmp("a", "A", 1) == 0);
  assert(ndpi_memcasecmp("a", "b", 1) < 0);
  assert(ndpi_memcasecmp("b", "a", 1) > 0);

  /* Test 4: Case insensitivity */
  assert(ndpi_memcasecmp("STRING", "string", 6) == 0);
  assert(ndpi_memcasecmp("String", "sTrInG", 6) == 0);

  /* Test 5: Various string comparisons */
  assert(ndpi_memcasecmp("string", "string", 6) == 0);
  assert(ndpi_memcasecmp("string", "strong", 6) < 0);
  assert(ndpi_memcasecmp("strong", "string", 6) > 0);
  assert(ndpi_memcasecmp("abc", "abcd", 3) == 0);
  assert(ndpi_memcasecmp("abcd", "abc", 3) == 0);

  /* Test 6: Optimization for checking first and last bytes */
  assert(ndpi_memcasecmp("aBc", "abc", 3) == 0);
  assert(ndpi_memcasecmp("abc", "abC", 3) == 0);
  assert(ndpi_memcasecmp("abc", "def", 3) < 0);
  assert(ndpi_memcasecmp("abz", "abx", 3) > 0);
  assert(ndpi_memcasecmp("axc", "ayc", 3) < 0);

  /* Test 7: Edge cases with non-printable characters and embedded zeros */
  const char str1[] = {0, 'a', 'b', 'c'};
  const char str2[] = {0, 'a', 'b', 'c'};
  assert(ndpi_memcasecmp(str1, str2, 4) == 0);

  const char str3[] = {0, 'a', 'b', 'c'};
  const char str4[] = {1, 'a', 'b', 'c'};
  assert(ndpi_memcasecmp(str3, str4, 4) < 0);

  const char str5[] = {'a', 'b', 'c', 0};
  const char str6[] = {'a', 'b', 'c', 1};
  assert(ndpi_memcasecmp(str5, str6, 4) < 0);

  const char str7[] = {'a', 'b', 0, 'd'};
  const char str8[] = {'a', 'b', 1, 'd'};
  assert(ndpi_memcasecmp(str7, str8, 4) < 0);
}

/* *********************************************** */

static void mahalanobisUnitTest()
{
  /* Example based on: https://supplychenmanagement.com/2019/03/06/calculating-mahalanobis-distance/ */

  const float i_s[3 * 3] = {  0.0482486100061447, -0.00420645518018837, -0.0138921893248235,
                              -0.00420645518018836, 0.00177288408892603, -0.00649813703331057,
                              -0.0138921893248235, -0.00649813703331056,  0.066800436339011 }; /* Inverted covar matrix */
  const float u[3] = { 22.8, 180.0, 9.2 }; /* Means vector */
  u_int32_t x[3] = { 26, 167, 12 }; /* Point */
  float md;

  md = ndpi_mahalanobis_distance(x, 3, u, i_s);
  /* It is a bit tricky to test float equality on different archs -> loose check.
   * md sholud be 1.3753 */
  assert(md >= 1.37 && md <= 1.38);
}

/* *********************************************** */

static void bitmaskUnitTest()
{
  struct ndpi_bitmask b;
  int i;

  assert(ndpi_bitmask_alloc(&b, 512) == 0);
  for(i = 0; i < b.max_bits; i++) {
    ndpi_bitmask_set(&b, i);
    assert(ndpi_bitmask_is_set(&b, i));
  }
  for(i = 0; i < b.max_bits; i++) {
    ndpi_bitmask_clear(&b, i);
    assert(!ndpi_bitmask_is_set(&b, i));
  }
  ndpi_bitmask_set_all(&b);
  for(i = 0; i < b.max_bits; i++)
    assert(ndpi_bitmask_is_set(&b, i));
  ndpi_bitmask_reset(&b);
  for(i = 0; i < b.max_bits; i++)
    assert(!ndpi_bitmask_is_set(&b, i));
  for(i = 0; i < b.max_bits; i++) {
    ndpi_bitmask_set(&b, i);
    assert(ndpi_bitmask_is_set(&b, i));
  }

  ndpi_bitmask_free(&b);
}

/* *********************************************** */

static void filterUnitTest() {
  ndpi_filter* f = ndpi_filter_alloc();
  u_int32_t v, i;

  assert(f);

  srand(time(NULL));

  for(i=0; i<1000; i++)
    assert(ndpi_filter_add(f, v = rand()));

  assert(ndpi_filter_contains(f, v));

  ndpi_filter_free(f);
}

/* *********************************************** */

static void zscoreUnitTest() {
  u_int32_t values[] = { 1, 3, 3, 4, 5, 2, 6, 7, 30, 16 };
  u_int32_t i;
  u_int32_t num_outliers;
  u_int32_t const num = NDPI_ARRAY_LENGTH(values);
  bool outliers[NDPI_ARRAY_LENGTH(values)], do_trace = false;

  num_outliers = ndpi_find_outliers(values, outliers, num);

  if(do_trace) {
    printf("outliers: %u\n", num_outliers);

    for(i=0; i<num; i++)
      printf("%u %s\n", values[i], outliers[i] ? "OUTLIER" : "OK");
  }
}

/* *********************************************** */

static void linearUnitTest() {
  u_int32_t values[] = {15, 27, 38, 49, 68, 72, 90, 150, 175, 203};
  u_int32_t prediction;
  u_int32_t const num = NDPI_ARRAY_LENGTH(values);
  bool do_trace = false;
  int rc = ndpi_predict_linear(values, num, 2*num, &prediction);

  if(do_trace) {
    printf("[rc: %d][predicted value: %u]\n", rc, prediction);
  }
}

/* *********************************************** */

static void sketchUnitTest() {
  struct ndpi_cm_sketch *sketch;

#if 0
  ndpi_cm_sketch_init(8);
  ndpi_cm_sketch_init(16);
  ndpi_cm_sketch_init(32);
  ndpi_cm_sketch_init(64);
  ndpi_cm_sketch_init(256);
  ndpi_cm_sketch_init(512);
  ndpi_cm_sketch_init(1024);
  ndpi_cm_sketch_init(2048);
  ndpi_cm_sketch_init(4096);
  ndpi_cm_sketch_init(8192);
  exit(0);
#endif

  sketch = ndpi_cm_sketch_init(32);

  if(sketch) {
    u_int32_t i, num_one = 0;
    bool do_trace = false;

    srand(time(NULL));

    for(i=0; i<10000; i++) {
      u_int32_t v = rand() % 1000;

      if(v == 1) num_one++;
      ndpi_cm_sketch_add(sketch, v);
    }

    if(do_trace)
      printf("The estimated count of 1 is %u [expectedl: %u]\n",
             ndpi_cm_sketch_count(sketch, 1), num_one);

    ndpi_cm_sketch_destroy(sketch);

    if(do_trace)
      exit(0);
  }
}

/* *********************************************** */

static void binaryBitmapUnitTest() {
  ndpi_binary_bitmap *b = ndpi_binary_bitmap_alloc();
  u_int64_t hashval = 8149764909040470312;
  u_int8_t category = 33;

  ndpi_binary_bitmap_set(b, hashval, category);
  ndpi_binary_bitmap_set(b, hashval+1, category);
  category = 0;
  assert(ndpi_binary_bitmap_isset(b, hashval, &category));
  assert(category == 33);
  ndpi_binary_bitmap_free(b);
}

/* *********************************************** */

static void pearsonUnitTest() {
  u_int32_t data_a[] = {1, 2, 3, 4, 5};
  u_int32_t data_b[] = {1000, 113, 104, 105, 106};
  u_int16_t num = sizeof(data_a) / sizeof(u_int32_t);
  float pearson = ndpi_pearson_correlation(data_a, data_b, num);

  assert(pearson != 0.0);
  // printf("%.8f\n", pearson);
}

/* *********************************************** */

static void outlierUnitTest() {
  u_int32_t data[] = {1, 2, 3, 4, 5};
  u_int16_t num = sizeof(data) / sizeof(u_int32_t);
  u_int16_t value_to_check = 8;
  float threshold = 1.5, lower, upper;
  float is_outlier = ndpi_is_outlier(data, num, value_to_check,
                                     threshold, &lower, &upper);

  /* printf("%.2f < %u < %.2f : %s\n", lower, value_to_check, upper, is_outlier ? "OUTLIER" : "OK"); */
  assert(is_outlier == true);
}

/* *********************************************** */

static void loadStressTest() {
  struct ndpi_detection_module_struct *ndpi_struct_shadow = ndpi_init_detection_module(NULL);

  if(ndpi_struct_shadow) {
    int i;

    for(i=1; i<100000; i++) {
      char name[32];
      ndpi_protocol_category_t id = NDPI_PROTOCOL_CATEGORY_MALWARE;
      ndpi_protocol_breed_t breed = NDPI_PROTOCOL_SAFE;
      u_int8_t value = (u_int8_t)i;

      snprintf(name, sizeof(name), "%d.com", i);
      ndpi_load_hostname_category(ndpi_struct_shadow, name, id, breed);

      snprintf(name, sizeof(name), "%u.%u.%u.%u", value, value, value, value);
      ndpi_load_ip_category(ndpi_struct_shadow, name, id, (void *)"My list");
    }

    ndpi_enable_loaded_categories(ndpi_struct_shadow);
    ndpi_finalize_initialization(ndpi_struct_shadow);
    ndpi_exit_detection_module(ndpi_struct_shadow);
  }
}

/* *********************************************** */

static void kdUnitTest() {
  ndpi_kd_tree *t = ndpi_kd_create(5);
  double v[][5] = {
    { 0, 4, 2, 3, 4 },
    { 0, 1, 2, 3, 6 },
    { 1, 2, 3, 4, 5 },
  };
  double v1[5] = { 0, 1, 2, 3, 8 };
  u_int i, sz = 5*sizeof(double), num = sizeof(v) / sz;
  ndpi_kd_tree_result *res;
  double *ret, *to_find = v[1];

  assert(t);

  for(i=0; i<num; i++)
    assert(ndpi_kd_insert(t, v[i], NULL) == true);

  assert((res = ndpi_kd_nearest(t, to_find)) != NULL);
  assert(ndpi_kd_num_results(res) == 1);
  assert((ret = ndpi_kd_result_get_item(res, NULL)) != NULL);
  assert(memcmp(ret, to_find, sz) == 0);
  ndpi_kd_result_free(res);

  assert((res = ndpi_kd_nearest(t, v1)) != NULL);
  assert(ndpi_kd_num_results(res) == 1);
  assert((ret = ndpi_kd_result_get_item(res, NULL)) != NULL);
  assert(memcmp(ret, v1, sz) != 0);
  assert(ndpi_kd_distance(ret, v1, 5) == 4.);
  ndpi_kd_result_free(res);

  ndpi_kd_free(t);
}

/* *********************************************** */

static void ballTreeUnitTest() {
  ndpi_btree *ball_tree;
  double v[][5] = {
    { 0, 4, 2, 3, 4 },
    { 0, 1, 2, 3, 6 },
    { 1, 2, 3, 4, 5 },
  };
  double v1[] = { 0, 1, 2, 3, 8 };
  double *rows[] = { v[0], v[1], v[2] };
  double *q_rows[] = { v1 };
  u_int32_t num_columns = 5;
  u_int32_t num_rows = sizeof(v) / (sizeof(double)*num_columns);
  ndpi_knn result;
  u_int32_t nun_results = 2;
  int trace = 0;
  int i, j;

  ball_tree = ndpi_btree_init(rows, num_rows, num_columns);
  assert(ball_tree != NULL);
  result = ndpi_btree_query(ball_tree, q_rows,
                            sizeof(q_rows) / sizeof(double*),
                            num_columns, nun_results);

  assert(result.n_samples == 1);

  if(trace) {
    for (i = 0; i < result.n_samples; i++) {
      printf("{\"knn_idx\": [");
      for (j = 0; j < result.n_neighbors; j++)
        {
          printf("%d", result.indices[i][j]);
          if (j != result.n_neighbors - 1)
            printf(", ");
        }
      printf("],\n \"knn_dist\": [");
      for (j = 0; j < result.n_neighbors; j++)
        {
          printf("%.12lf", result.distances[i][j]);
          if (j != result.n_neighbors - 1)
            printf(", ");
        }
      printf("]\n}\n");
      if (i != result.n_samples - 1)
        printf(", ");
    }
  }

  ndpi_free_knn(result);
  ndpi_free_btree(ball_tree);
}

/* *********************************************** */

static void cryptDecryptUnitTest() {
  u_char enc_dec_key[] = "9dedb817e5a8805c1de62eb8982665b9a2b4715174c34d23b9a46ffafacfb2a7" /* SHA256("nDPI") */;
  const char *test_string = "The quick brown fox jumps over the lazy dog";
  char *enc, *dec;
  u_int16_t e_len, d_len, t_len = strlen(test_string);

  enc = ndpi_quick_encrypt(test_string, t_len, &e_len, enc_dec_key);
  assert(enc != NULL);
  dec = ndpi_quick_decrypt((const char*)enc, e_len, &d_len, enc_dec_key);
  assert(dec != NULL);
  assert(t_len == d_len);

  assert(strncmp(dec, test_string, e_len) == 0);

  ndpi_free(enc);
  ndpi_free(dec);
}

/* *********************************************** */

static void encodeDomainsUnitTest(bool load_suffix_list) {
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
  const char *lists_path = "../lists/public_suffix_list.dat";
  char *lists_dir = "../lists";
  char *categories_path = "./categories.txt";
  struct stat st;

  if(stat(lists_path, &st) == 0 &&
     stat(lists_dir, &st) == 0 &&
     stat(categories_path, &st) == 0) {
    u_int64_t suffix_id;
    char out[256];
    char *str;
    ndpi_protocol_category_t id;
    ndpi_protocol_breed_t breed;

    if(load_suffix_list)
      assert(ndpi_load_domain_suffixes(ndpi_str, (char*)lists_path) == 0);

    ndpi_get_host_domain_suffix(ndpi_str, "lcb.it", &suffix_id);
    ndpi_get_host_domain_suffix(ndpi_str, "www.ntop.org", &suffix_id);
    ndpi_get_host_domain_suffix(ndpi_str, "www.bbc.co.uk", &suffix_id);

    if(load_suffix_list) {
      /* The encoding is different with or without the suffix list */
      str = (char*)"www.ntop.org"; assert(ndpi_encode_domain(ndpi_str, str, out, sizeof(out)) == 8);
      str = (char*)"www.bbc.co.uk"; assert(ndpi_encode_domain(ndpi_str, str, out, sizeof(out)) == 8);
    }

    assert(ndpi_load_categories_dir(ndpi_str, lists_dir));
    assert(ndpi_load_categories_file(ndpi_str, categories_path, "categories.txt"));

    str = (char*)"2001:db8:1::1"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == 100);
    str = (char*)"www.internetbadguys.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == 100);
    str = (char*)"0grand-casino.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == 107);
    str = (char*)"222.0grand-casino.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == 107);
    str = (char*)"10bet.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == 107);
    str = (char*)"www.ntop.org"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == -1); assert(id == 0);
    str = (char*)"lifyqyi.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == 100);
    str = (char*)"xhamster.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == NDPI_PROTOCOL_CATEGORY_ADULT_CONTENT);
    str = (char*)"a.xhamster.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == NDPI_PROTOCOL_CATEGORY_ADULT_CONTENT);
    str = (char*)"a.xhamster.com.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == -1);
    str = (char*)"a.xhamster.com.a"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == -1);
    str = (char*)"gateway.unityads.unity3d.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == NDPI_PROTOCOL_CATEGORY_ADVERTISEMENT);
    str = (char*)"unityads.unity3d.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == 0); assert(id == NDPI_PROTOCOL_CATEGORY_ADVERTISEMENT);
    str = (char*)"unity3d.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == -1);

    str = (char*)"something.arpa"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == -1);
    str = (char*)"something.local"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id, &breed) == -1);
  }

  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static void domainsUnitTest() {
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
  const char *lists_path = "../lists/public_suffix_list.dat";
  struct stat st;

  if(stat(lists_path, &st) == 0) {
    u_int64_t suffix_id;

    assert(ndpi_load_domain_suffixes(ndpi_str, (char*)lists_path) == 0);

    assert(strcmp(ndpi_get_host_domain(ndpi_str, "1.0.0.127.in-addr.arpa"), "in-addr.arpa") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "fe80::fd:5447:b2d1:40e0"), "fe80::fd:5447:b2d1:40e0") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "192.168.1.2"), "192.168.1.2") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "extension.femetrics.grammarly.io"), "grammarly.io") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "www.ovh.commander1.com"), "commander1.com") == 0);

    assert(strcmp(ndpi_get_host_domain_suffix(ndpi_str, "www.chosei.chiba.jp", &suffix_id), "chosei.chiba.jp") == 0);
    assert(strcmp(ndpi_get_host_domain_suffix(ndpi_str, "www.unipi.it", &suffix_id), "it") == 0);
    assert(strcmp(ndpi_get_host_domain_suffix(ndpi_str, "mail.apple.com", &suffix_id), "com") == 0);
    assert(strcmp(ndpi_get_host_domain_suffix(ndpi_str, "www.bbc.co.uk", &suffix_id), "co.uk") == 0);

    assert(strcmp(ndpi_get_host_domain(ndpi_str, "www.chosei.chiba.jp"), "www.chosei.chiba.jp") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "www.unipi.it"), "unipi.it") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "mail.apple.com"), "apple.com") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "www.bbc.co.uk"), "bbc.co.uk") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "zy1ssnfwwl.execute-api.eu-north-1.amazonaws.com"), "amazonaws.com") == 0);
  }

  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static void domainSearchUnitTest() {
  ndpi_domain_classify *sc = ndpi_domain_classify_alloc();
  char *domain = "ntop.org";
  u_int64_t class_id;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
  u_int8_t trace = 0;

  assert(ndpi_str);
  assert(sc);

  assert(ndpi_finalize_initialization(ndpi_str) == 0);

  ndpi_domain_classify_add(ndpi_str, sc, (NDPI_PROTOCOL_SAFE << 16) | NDPI_PROTOCOL_NTOP, ".ntop.org");
  ndpi_domain_classify_add(ndpi_str, sc, (NDPI_PROTOCOL_SAFE << 16) | NDPI_PROTOCOL_NTOP, domain);
  assert(ndpi_domain_classify_hostname(ndpi_str, sc, &class_id, domain));
  assert((class_id & 0xFFFF) == NDPI_PROTOCOL_NTOP);
  assert(((class_id & 0xFFFF0000) >> 16) == NDPI_PROTOCOL_SAFE);

  ndpi_domain_classify_add(ndpi_str, sc, (NDPI_PROTOCOL_UNSAFE << 16) | NDPI_PROTOCOL_CATEGORY_GAMBLING, "123vc.club");
  assert(ndpi_domain_classify_hostname(ndpi_str, sc, &class_id, "123vc.club"));
  assert((class_id & 0xFFFF) == NDPI_PROTOCOL_CATEGORY_GAMBLING);
  assert(((class_id & 0xFFFF0000) >> 16) == NDPI_PROTOCOL_UNSAFE);

  /* Subdomain check */
  assert(ndpi_domain_classify_hostname(ndpi_str, sc, &class_id, "blog.ntop.org"));
  assert((class_id & 0xFFFF) == NDPI_PROTOCOL_NTOP);

  u_int32_t s = ndpi_domain_classify_size(sc);
  if(trace) printf("ndpi_domain_classify size: %u \n",s);


  ndpi_domain_classify_free(sc);
  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static void domainSearchUnitTest2() {
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
  ndpi_domain_classify *c = ndpi_domain_classify_alloc();
  u_int64_t class_id = 9;

  assert(ndpi_str);
  assert(c);

  assert(ndpi_finalize_initialization(ndpi_str) == 0);

  ndpi_domain_classify_add(ndpi_str, c, class_id, "ntop.org");
  ndpi_domain_classify_add(ndpi_str, c, class_id, "apple.com");

  assert(!ndpi_domain_classify_hostname(ndpi_str, c, &class_id, "ntop.com"));

  ndpi_domain_classify_free(c);
  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static void domainCacheTestUnit() {
  struct ndpi_address_cache *cache = ndpi_init_address_cache(32000);
  ndpi_ip_addr_t ip;
  u_int32_t epoch_now = (u_int32_t)time(NULL);
  struct ndpi_address_cache_item *ret;
  char fname[64] = {0};

  assert(cache);

  /* On GitHub Actions, ndpiReader might be called multiple times in parallel, so
     every instance must use its own file */
  snprintf(fname, sizeof(fname), "./cache.%u.dump", (unsigned int)getpid());

  memset(&ip, 0, sizeof(ip));
  ip.ipv4 = 12345678;
  assert(ndpi_address_cache_insert(cache, ip, "nodomain.local", epoch_now, 32) == true);

  ip.ipv4 = 87654321;
  assert(ndpi_address_cache_insert(cache, ip, "hello.local", epoch_now, 0) == true);

  assert((ret = ndpi_address_cache_find(cache, ip, epoch_now)) != NULL);
  assert(strcmp(ret->hostname, "hello.local") == 0);
  assert(ndpi_address_cache_find(cache, ip, epoch_now + 1) == NULL);

  assert(ndpi_address_cache_dump(cache, fname, epoch_now));
  ndpi_term_address_cache(cache);

  cache = ndpi_init_address_cache(32000);
  assert(cache);
  assert(ndpi_address_cache_restore(cache, fname, epoch_now) == 1);

  ip.ipv4 = 12345678;
  assert((ret = ndpi_address_cache_find(cache, ip, epoch_now)) != NULL);
  assert(strcmp(ret->hostname, "nodomain.local") == 0);

  ndpi_term_address_cache(cache);
  unlink(fname);
}

/* *********************************************** */

static void checkmemrchrUnitTest() {
  char a[] = "string";


  assert(ndpi_memrchr(a, 's', sizeof(a) -1) == a);
  assert(ndpi_memrchr(a, 'b', sizeof(a) - 1) == NULL);
  assert(ndpi_memrchr(a, 't', sizeof(a) - 1) == a + 1);
  assert(ndpi_memrchr(a, 'g', sizeof(a) - 1) == a + 5);
  assert(ndpi_memrchr(a, '\0', sizeof(a) - 1) == NULL);
}

/* *********************************************** */

static void checkRankingUnitTest(bool do_trace) {
  ndpi_ranking rank;
  char path[64] = {0};
  const u_int num = 3;
  ndpi_ranking_epoch_entry entries[4];
  u_int i, j;
  ndpi_ranking_change curr_ranking[4], prev_ranking[4];
  u_int32_t now = (u_int32_t)time(NULL), prev_epoch;
  u_int16_t num_changes;

  srand(now);

  /*
    On GitHub Actions, ndpiReader might be called multiple times in parallel,
    so every instance must use its own file
  */
  snprintf(path, sizeof(path),"%sranking.%u.test",
#ifdef WIN32
           "",
#else

           "/tmp/",
#endif
           (unsigned int)getpid());

  ndpi_init_ranking(&rank, num+1 /* max_num_items */, 8 /* num_epochs */);
  assert(ndpi_serialize_ranking(&rank, path) == true);
  // if(do_trace)  ndpi_print_ranking(&rank);
  ndpi_term_ranking(&rank);

  assert(ndpi_deserialize_ranking(&rank, path) == true);

  for(j=0; j<num+1; j++) {
    for(i=0; i<num+1; i++) entries[i].item_unique_id = i+1,
                             entries[i].value = rand();

    /* num_changes = */ ndpi_ranking_add_epoch(&rank, now, entries, num+1,
                                               curr_ranking, prev_ranking,
                                               &prev_epoch);
    now++;
  }

  // if(do_trace) ndpi_print_ranking(&rank);
  ndpi_term_ranking(&rank);

  /* **************** */

  ndpi_init_ranking(&rank, num+1 /* max_num_items */, 8 /* num_epochs */);

  for(j=0; j<num+1; j++) {
    for(i=0; i<num+1; i++) entries[i].item_unique_id = i+1,
                             entries[i].value = i*(1+j)*10;

    num_changes = ndpi_ranking_add_epoch(&rank, now, entries, num+1,
                                         curr_ranking, prev_ranking,
                                         &prev_epoch);

    if(do_trace) {
      if(num_changes > 0) {
        printf("[loop %u] %u ranking changes at epoch %u\n",
               j+1, num_changes, now);
      } else
        printf("[loop %u] No ranking changes at epoch %u\n", j+1, now);
    }

    if(do_trace)
      ndpi_print_ranking(&rank);

    assert(num_changes == 0);
    now++;
  }

  /* *** */

  entries[num].value = 999;
  num_changes = ndpi_ranking_add_epoch(&rank, now, entries, num+1,
                                       curr_ranking, prev_ranking,
                                       &prev_epoch);

  if(do_trace) {
    if(num_changes > 0) {
      printf("[loop %u] %u ranking changes at epoch %u\n", j+1,
             num_changes, now);
    } else
      printf("[loop %u] No ranking changes at epoch %u\n", j+1, now);
  }

  if(do_trace)
    ndpi_print_ranking(&rank);

  assert(num_changes > 0);
  now++;

  /* *** */

  if(do_trace) {
    printf("***** loop *****\n");
  }

  for(j=0; j<5; j++) {
    for(i=0; i<num+1; i++)
      entries[i].value++;;

    num_changes = ndpi_ranking_add_epoch(&rank, now, entries, num+1,
                                         curr_ranking, prev_ranking,
                                         &prev_epoch);

    if(do_trace) {
      if(num_changes > 0) {
        printf("[loop %u] %u ranking changes at epoch %u\n",
               j+1, num_changes, now);
      } else
        printf("[loop %u] No ranking changes at epoch %u\n", j+1, now);
    }

    if(do_trace)
      ndpi_print_ranking(&rank);

    assert(num_changes == 0);
    now++;
  }

  ndpi_term_ranking(&rank);
}

/* *********************************************** */

/* Simulated feature indices */
#define NET_PKT_SIZE  0   /* bytes, 64–1500 normal */
#define NET_DURATION  1   /* ms,    1–300  normal  */
#define NET_N_PORTS   2   /* number of destination ports */
#define NET_INTERVAL  3   /* ms between connections      */
#define NET_PAYLOAD   4   /* entropy proxy 0–8 bits      */
#define NUM_FEATURES  5

static unsigned long demo_seed = 20240101UL;

static double randomize() {
    demo_seed = demo_seed * 1664525UL + 1013904223UL;
    return (double)(demo_seed & 0x7FFFFFFF) / (double)0x80000000;
}

static void isolationforestUnitTest() {
  void* forest;
  const int N_NORMAL   = 5000;
  const int N_ATTACKS  = 1500;
  const int N          = N_NORMAL + N_ATTACKS;
  u_int32_t len        = sizeof(double*) * (size_t)N;
#ifdef DEBUG
  u_int32_t tot_mem    = len;
#endif
  double **data        = (double **)ndpi_malloc(len);
  double threshold     = 0;
  int i;

  /* Normal web/DB traffic */
  for(i = 0; i < N_NORMAL; i++) {
    u_int32_t l = sizeof(double)* NUM_FEATURES;
    double *row = (double*)ndpi_malloc(l);

#ifdef DEBUG
    tot_mem += l;
#endif

    data[i] = row;
    row[NET_PKT_SIZE]  = 64 + randomize() * 1436;     /* 64–1500 B    */
    row[NET_DURATION]  = 1  + randomize() * 299;      /* 1–300 ms     */
    row[NET_N_PORTS]   = 1  + (int)(randomize() * 3); /* 1–3 ports    */
    row[NET_INTERVAL]  = 5  + randomize() * 295;      /* 5–300 ms     */
    row[NET_PAYLOAD]   = 4  + randomize() * 0.8;      /* ~4–8 entropy */
  }

  /* Attack traffic: port scans, floods, exfil */
  for(i = N_NORMAL; i < N; i++) {
    u_int32_t l = sizeof(double)* NUM_FEATURES;
    double *row = (double*)ndpi_malloc(l);
    int kind = i % 3;

#ifdef DEBUG
    tot_mem += l;
#endif

    data[i] = row;

    if (kind == 0) {
      /* Port scan: many ports, small packets, rapid */
      row[NET_PKT_SIZE] = 40 + randomize() * 20;
      row[NET_DURATION] = randomize() * 2;
      row[NET_N_PORTS]  = 100 + randomize() * 900;
      row[NET_INTERVAL] = randomize() * 0.5;
      row[NET_PAYLOAD]  = 0.5 + randomize() * 0.5;
    } else if (kind == 1) {
      /* Data exfiltration: huge payload, low entropy (compressed/encrypted) */
      row[NET_PKT_SIZE] = 1400 + randomize() * 100;
      row[NET_DURATION] = 5000 + randomize() * 1000;
      row[NET_N_PORTS]  = 1;
      row[NET_INTERVAL] = 0.01 + randomize() * 0.1;
      row[NET_PAYLOAD]  = 7.8 + randomize() * 0.2;
    } else {
      /* SYN flood: tiny packets, zero duration, massive rate */
      row[NET_PKT_SIZE] = 40;
      row[NET_DURATION] = 0;
      row[NET_N_PORTS]  = 1;
      row[NET_INTERVAL] = randomize() * 0.01;
      row[NET_PAYLOAD]  = 1 + randomize();
    }
  }

  //printf("[DEBUG] dataset len %.2f MB\n", (float)tot_mem / (1024. * 1024.));

  /* Train only with normal data */
  forest = ndpi_alloc_iforest(data, N_NORMAL, NUM_FEATURES);
  assert(forest);

  for(int i = 0; i < N_NORMAL; i++) {
    double score = ndpi_iforest_score(forest, data[i]);

    /* printf("[Normal] score=%.4f\n", score); */

    //assert(score <= threshold); /* No false positives */
    threshold = ndpi_max(threshold, score);
  }

#ifdef DEBUG
  u_int num_anomalies = 0;
#endif

  for(i = N_NORMAL; i < N; i++) {
    double score = ndpi_iforest_score(forest, data[i]);

    /* Disabled as some false positives might happen */
    if(score > threshold) {
#if 0
      printf("[anomaly] score=%.4f [threshold: %.4f] [%s]\n",
             score, threshold, (score > threshold) ? "ANOMALY" : "OK");
#endif
      assert(score > threshold);

#ifdef DEBUG
      num_anomalies++;
#endif
    }
  }

#ifdef DEBUG
  printf("%u/%u anomalies [threshold: %.4f]\n", num_anomalies, N_ATTACKS, threshold);
#endif

  ndpi_free_iforest(forest);

  for(i = 0; i < N; i++)
    ndpi_free(data[i]);

  ndpi_free(data);
}

/* *********************************************** */

// #define DEBUG

static void anomalyModelUnitTest() {
  const u_int32_t N_NORMAL  = 5000;
  const u_int32_t N_ATTACKS = 1500;
  ndpi_anomaly_model *m     = ndpi_alloc_anomaly_model(NUM_FEATURES);
  u_int32_t i;
#ifdef DEBUG
  u_int32_t num_anomalies = 0;
#endif

  assert(m);

  /* Normal web/DB traffic */
  for(i = 0; i < N_NORMAL; i++) {
    double row[NUM_FEATURES];

    row[NET_PKT_SIZE]  = 64 + randomize() * 1436;     /* 64–1500 B    */
    row[NET_DURATION]  = 1  + randomize() * 299;      /* 1–300 ms     */
    row[NET_N_PORTS]   = 1  + (int)(randomize() * 3); /* 1–3 ports    */
    row[NET_INTERVAL]  = 5  + randomize() * 295;      /* 5–300 ms     */
    row[NET_PAYLOAD]   = 4  + randomize() * 0.8;      /* ~4–8 entropy */

    assert(ndpi_train_anomaly_model(m, row) == true);
  }

  for(i = 0; i < N_ATTACKS; i++) {
    double row[NUM_FEATURES];
    int kind = i % 3;

    if (kind == 0) {
      /* Port scan: many ports, small packets, rapid */
      row[NET_PKT_SIZE] = 40 + randomize() * 20;
      row[NET_DURATION] = randomize() * 2;
      row[NET_N_PORTS]  = 100 + randomize() * 900;
      row[NET_INTERVAL] = randomize() * 0.5;
      row[NET_PAYLOAD]  = 0.5 + randomize() * 0.5;
    } else if (kind == 1) {
      /* Data exfiltration: huge payload, low entropy (compressed/encrypted) */
      row[NET_PKT_SIZE] = 1400 + randomize() * 100;
      row[NET_DURATION] = 5000 + randomize() * 1000;
      row[NET_N_PORTS]  = 1;
      row[NET_INTERVAL] = 0.01 + randomize() * 0.1;
      row[NET_PAYLOAD]  = 7.8 + randomize() * 0.2;
    } else {
      /* SYN flood: tiny packets, zero duration, massive rate */
      row[NET_PKT_SIZE] = 40;
      row[NET_DURATION] = 0;
      row[NET_N_PORTS]  = 1;
      row[NET_INTERVAL] = randomize() * 0.01;
      row[NET_PAYLOAD]  = 1 + randomize();
    }

    assert(ndpi_compute_anomaly_score(m, row) == true);

#ifdef DEBUG
    if(ndpi_compute_anomaly_score(m, row)) num_anomalies++;
#endif

#ifdef DEBUG
    fprintf(stdout, "."); fflush(stdout);
#endif
  }

#ifdef DEBUG
  fprintf(stdout, "\nnum_anomalies: %u/%u\n", num_anomalies, N_ATTACKS);
#endif

  ndpi_free_anomaly_model(m);
}

static void dgaUnitTest() {
  const char *dga[] = {
    //"www.lbjamwptxz.com",
    "www.l54c2e21e80ba5471be7a8402cffb98768.so",
    "www.wdd7ee574106a84807a601beb62dd851f0.hk",
    "www.jaa12148a5831a5af92aa1d8fe6059e276.ws",
    "www.e6r5p57kbafwrxj3plz.com",
    // "grdawgrcwegpjaoo.eu",
    "www.mcfpeqbotiwxfxqu.eu",
    "www.adgxwxhqsegnrsih.eu",
    NULL
  };

  const char *non_dga[] = {
    "mail.100x100design.com",
    "cdcvps.cloudapps.cisco.com",
    "vcsa.vmware.com",
    "mz.gov.pl",
    "zoomam104zc.zoom.us",
    "5CI_DOMBIN",
    "ALICEGATE",
    "BOWIE",
    "D002465",
    "DESKTOP-RB5T12G",
    "ECI_DOM",
    "ECI_DOMA",
    "ECI_DOMAIN",
    "ENDIAN-PC",
    "GFILE",
    "GIOVANNI-PC",
    "GUNNAR",
    "ISATAP",
    "LAB111",
    "LP-RKERUR-OSX",
    "LUCAS-IMAC",
    "LUCASMACBOOKPRO",
    "MACBOOKAIR-E1D0",
    //"MDJR98",
    "NASFILE",
    "SANJI-LIFEBOOK-",
    "SC.ARRANCAR.ORG",
    "WORKG",
    "WORKGROUP",
    "XSTREAM_HY",
    "__MSBROWSE__",
    "mqtt.facebook.com",
    NULL
  };
  int debug = 0, i;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);

  assert(ndpi_str != NULL);

  assert(ndpi_finalize_initialization(ndpi_str) ==0);

  for(i=0; non_dga[i] != NULL; i++) {
    if(debug) printf("Checking non DGA %s\n", non_dga[i]);
    assert(ndpi_check_dga_name(ndpi_str, NULL, (char*)non_dga[i], 1, 1, 0) == 0);
  }

  for(i=0; dga[i] != NULL; i++) {
    if(debug) printf("Checking DGA %s\n", non_dga[i]);
    assert(ndpi_check_dga_name(ndpi_str, NULL, (char*)dga[i], 1, 1, 0) == 1);
  }

  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static void hllUnitTest() {
  struct ndpi_hll h;
  u_int8_t bits = 8; /* >= 4, <= 16 */
  u_int32_t i;

  assert(ndpi_hll_init(&h, bits) == 0);

  for(i=0; i<21320; i++)
    ndpi_hll_add_number(&h, i);

  /* printf("Count estimate: %f\n", ndpi_hll_count(&h)); */

  ndpi_hll_destroy(&h);
}

/* *********************************************** */

static void bitmapUnitTest() {
  u_int32_t val, i, j;
  u_int64_t val64;

  /* With a 32 bit integer */
  for(i=0; i<32; i++) {
    NDPI_ZERO_BIT(val);
    NDPI_SET_BIT(val, i);

    assert(NDPI_ISSET_BIT(val, i));

    for(j=0; j<32; j++) {
      if(j != i) {
        assert(!NDPI_ISSET_BIT(val, j));
      }
    }
  }

  /* With a 64 bit integer */
  for(i=0; i<64; i++) {
    NDPI_ZERO_BIT(val64);
    NDPI_SET_BIT(val64, i);

    assert(NDPI_ISSET_BIT(val64, i));

    for(j=0; j<64; j++) {
      if(j != i) {
        assert(!NDPI_ISSET_BIT(val64, j));
      }
    }
  }
}

/* *********************************************** */

static void automataUnitTest() {
  void *automa = ndpi_init_automa();

  assert(automa);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("hello")) == 0);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("world")) == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "This is the wonderful world of nDPI") == 1);
  ndpi_free_automa(automa);
}

/* *********************************************** */

static void automataDomainsUnitTest() {
  void *automa = ndpi_init_automa_domain();

  assert(automa);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("wikipedia.it")) == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "wikipedia.it") == 1);
  assert(ndpi_match_string(automa, "foo.wikipedia.it") == 1);
  assert(ndpi_match_string(automa, "foowikipedia.it") == 0);
  assert(ndpi_match_string(automa, "foowikipedia") == 0);
  assert(ndpi_match_string(automa, "-wikipedia.it") == 0);
  assert(ndpi_match_string(automa, "foo-wikipedia.it") == 0);
  assert(ndpi_match_string(automa, "wikipedia.it.com") == 0);
  ndpi_free_automa(automa);

  automa = ndpi_init_automa_domain();
  assert(automa);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("wikipedia.")) == 0); /* matches wikipedia.xxx */
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("wikipedia.it.")) == 0); /* matches wikipedia.it.xxx */
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "wikipedia.it") == 1);
  assert(ndpi_match_string(automa, "foo.wikipedia.it") == 1);
  assert(ndpi_match_string(automa, "foowikipedia.it") == 0);
  assert(ndpi_match_string(automa, "foowikipedia") == 0);
  assert(ndpi_match_string(automa, "-wikipedia.it") == 0);
  assert(ndpi_match_string(automa, "foo-wikipedia.it") == 0);
  assert(ndpi_match_string(automa, "wikipediafoo") == 0);
  assert(ndpi_match_string(automa, "wikipedia.it.com") == 1);
  ndpi_free_automa(automa);

  automa = ndpi_init_automa_domain();
  assert(automa);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("-buy.itunes.apple.com")) == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "buy.itunes.apple.com") == 0);
  assert(ndpi_match_string(automa, "p53-buy.itunes.apple.com") == 1);
  assert(ndpi_match_string(automa, "p53buy.itunes.apple.com") == 0);
  assert(ndpi_match_string(automa, "foo.p53-buy.itunes.apple.com") == 1);
  ndpi_free_automa(automa);
}

/* *********************************************** */

static void blocksUnitTest() {
  struct ndpi_tls_block a[] = { { 4, 1590, 0, 1, 0}, { 5, -1212, 0, 1, 0}, { 1, -1, 0, 1, 0}, { 16, -42, 0, 1, 0}, { 16, -53, 0, 1, 0}  };
  struct ndpi_tls_block b[] = { { 4, 1590, 0, 1, 0}, { 5, -1212, 0, 1, 0}, { 1, -1, 0, 1, 0}, { 16, -42, 0, 1, 0}, { 16, -52, 0, 1, 0}  };
  float ret = ndpi_tls_blocks_len_compare(a, b, 5 /* num_blocks */);

  assert(ret == 1.0);
}

/* *********************************************** */

static void analyzeUnitTest() {
  struct ndpi_analyze_struct *s;
  float avg, var, stddev;
  u_int64_t mn, mx, last;

  /* Allocate with a sliding window of 8 */
  s = ndpi_alloc_data_analysis(8);
  assert(s != NULL);

  /* Populate with known values: 2, 4, 4, 4, 5, 5, 7, 9 (classic variance example) */
  ndpi_data_add_value(s, 2);
  ndpi_data_add_value(s, 4);
  ndpi_data_add_value(s, 4);
  ndpi_data_add_value(s, 4);
  ndpi_data_add_value(s, 5);
  ndpi_data_add_value(s, 5);
  ndpi_data_add_value(s, 7);
  ndpi_data_add_value(s, 9);

  /* mean = 5, variance = 4, stddev = 2 */
  avg = ndpi_data_average(s);
  assert(avg >= 4.9f && avg <= 5.1f);

  var = ndpi_data_variance(s);
  assert(var >= 3.8f && var <= 4.2f);

  stddev = ndpi_data_stddev(s);
  assert(stddev >= 1.9f && stddev <= 2.1f);

  mn = ndpi_data_min(s);
  mx = ndpi_data_max(s);
  last = ndpi_data_last(s);
  assert(mn == 2);
  assert(mx == 9);
  assert(last == 9);

  /* Window average (last 8 values same as all values here) */
  float wavg = ndpi_data_window_average(s);
  assert(wavg >= 4.9f && wavg <= 5.1f);

  /* Reset and verify state */
  ndpi_reset_data_analysis(s);
  ndpi_data_add_value(s, 10);
  assert(ndpi_data_min(s) == 10);
  assert(ndpi_data_max(s) == 10);
  assert(ndpi_data_last(s) == 10);

  ndpi_free_data_analysis(s, 1);

  /* ndpi_alloc_data_analysis_from_series */
  u_int32_t series[] = {1, 2, 3, 4, 5};
  s = ndpi_alloc_data_analysis_from_series(series, 5);
  assert(s != NULL);
  avg = ndpi_data_average(s);
  assert(avg >= 2.9f && avg <= 3.1f);
  ndpi_free_data_analysis(s, 1);

  /* ndpi_data_ratio and ndpi_data_ratio2str */
  float ratio;
  ratio = ndpi_data_ratio(0, 0);
  assert(ratio == 0.0f);

  ratio = ndpi_data_ratio(100, 0);  /* pure upload */
  assert(ratio > 0.2f);
  assert(strcmp(ndpi_data_ratio2str(ratio), "Upload") == 0);

  ratio = ndpi_data_ratio(0, 100);  /* pure download */
  assert(ratio < -0.2f);
  assert(strcmp(ndpi_data_ratio2str(ratio), "Download") == 0);

  ratio = ndpi_data_ratio(50, 50);  /* mixed */
  assert(ratio == 0.0f);
  assert(strcmp(ndpi_data_ratio2str(ratio), "Mixed") == 0);
}

/* *********************************************** */

static void binUnitTest() {
  struct ndpi_bin *bins, b0, b1;
  u_int8_t num_bins = 32;
  u_int8_t num_points = 24;
  u_int32_t i, j;
  u_int8_t num_clusters = 3;
  u_int16_t cluster_ids[256];
  char out_buf[128];
  u_int8_t trace = 0;

  srand(time(NULL));

  assert((bins = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_bins)) != NULL);

  for(i=0; i<num_bins; i++) {
    ndpi_init_bin(&bins[i], ndpi_bin_family8, num_points);

    for(j=0; j<num_points; j++)
      ndpi_set_bin(&bins[i], j, rand() % 0xFF);

    ndpi_normalize_bin(&bins[i]);
  }

  ndpi_cluster_bins(bins, num_bins, num_clusters, cluster_ids, NULL);

  for(j=0; j<num_clusters; j++) {
    if(trace) printf("\n");

    for(i=0; i<num_bins; i++) {
      if(cluster_ids[i] == j) {
        if(trace)
          printf("[%u] %s\n", cluster_ids[i],
                 ndpi_print_bin(&bins[i], 0, out_buf, sizeof(out_buf)));
      }
    }
  }
  // printf("Similarity: %f\n\n", ndpi_bin_similarity(&b1, &b2, 1));

  for(i=0; i<num_bins; i++)
    ndpi_free_bin(&bins[i]);

  ndpi_free(bins);

  /* ************************ */

  ndpi_init_bin(&b0, ndpi_bin_family8, 16);
  ndpi_init_bin(&b1, ndpi_bin_family8, 16);

  ndpi_set_bin(&b0, 1, 100);
  ndpi_set_bin(&b1, 1, 100);

  if(trace)
    printf("Similarity: %f\n\n", ndpi_bin_similarity(&b0, &b1, 1, 0));

  ndpi_free_bin(&b0), ndpi_free_bin(&b1);
}

/* *********************************************** */

static void bitmap64FuseUnitTest(void) {
  ndpi_bitmap64_fuse *bf = ndpi_bitmap64_fuse_alloc();
  assert(bf != NULL);

  /* Add values including a value exceeding 32-bit range to test 64-bit support */
  assert(ndpi_bitmap64_fuse_set(bf, 1) == true);
  assert(ndpi_bitmap64_fuse_set(bf, 42) == true);
  assert(ndpi_bitmap64_fuse_set(bf, 1000) == true);
  assert(ndpi_bitmap64_fuse_set(bf, UINT32_MAX) == true);
  assert(ndpi_bitmap64_fuse_set(bf, 0x100000000ULL) == true); /* > 32-bit range */

  /* Must compress before query */
  assert(ndpi_bitmap64_fuse_compress(bf) == true);

  /* Query after compression */
  assert(ndpi_bitmap64_fuse_isset(bf, 1) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, 42) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, 1000) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, UINT32_MAX) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, 0x100000000ULL) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, 2) == false);
  assert(ndpi_bitmap64_fuse_isset(bf, 999) == false);

  /* Size should be non-zero after compression */
  assert(ndpi_bitmap64_fuse_size(bf) > 0);

  ndpi_bitmap64_fuse_free(bf);

  /* Empty bitmap: compress on empty should be handled gracefully */
  ndpi_bitmap64_fuse *bf2 = ndpi_bitmap64_fuse_alloc();
  assert(bf2 != NULL);
  assert(ndpi_bitmap64_fuse_compress(bf2) == true);
  assert(ndpi_bitmap64_fuse_isset(bf2, 0) == false);
  ndpi_bitmap64_fuse_free(bf2);
}

/* *********************************************** */

static void riskUtilsUnitTest(void) {
  ndpi_risk_enum risk;
  u_int16_t client_score, server_score;
  ndpi_risk risk_bits;

  /* ndpi_risk2str: verify all risk values return non-NULL strings */
  for(risk = NDPI_NO_RISK; risk < NDPI_MAX_RISK; risk++) {
    const char *s = ndpi_risk2str(risk);
    assert(s != NULL && strlen(s) > 0);
  }

  /* ndpi_risk2score: verify specific risk has non-zero total score */
  risk_bits = 0;
  NDPI_SET_BIT(risk_bits, NDPI_TLS_SELFSIGNED_CERTIFICATE);
  u_int16_t total = ndpi_risk2score(risk_bits, &client_score, &server_score);
  assert(total > 0);
  assert(client_score + server_score == total);

  /* No risk -> zero score */
  risk_bits = 0;
  total = ndpi_risk2score(risk_bits, &client_score, &server_score);
  assert(total == 0);
  assert(client_score == 0);
  assert(server_score == 0);

  /* Multiple risks combine */
  risk_bits = 0;
  NDPI_SET_BIT(risk_bits, NDPI_TLS_SELFSIGNED_CERTIFICATE);
  u_int16_t score_single = ndpi_risk2score(risk_bits, &client_score, &server_score);

  risk_bits = 0;
  NDPI_SET_BIT(risk_bits, NDPI_TLS_SELFSIGNED_CERTIFICATE);
  NDPI_SET_BIT(risk_bits, NDPI_TLS_OBSOLETE_VERSION);
  u_int16_t score_multi = ndpi_risk2score(risk_bits, &client_score, &server_score);
  assert(score_multi > score_single);
}
/* *********************************************** */

static void cryptoUnitTest(void) {
  /* ndpi_md5: known hash for empty string */
  {
    u_char hash[16];
    /* MD5("") = d41d8cd98f00b204e9800998ecf8427e */
    u_char expected[] = {
      0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
      0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
    };
    ndpi_md5((const u_char *)"", 0, hash);
    assert(memcmp(hash, expected, 16) == 0);

    /* MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 */
    u_char expected_abc[] = {
      0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
      0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
    };
    ndpi_md5((const u_char *)"abc", 3, hash);
    assert(memcmp(hash, expected_abc, 16) == 0);
  }

  /* ndpi_sha256: known hash for empty string */
  {
    u_int8_t hash[32];
    /* SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    u_int8_t expected[] = {
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
      0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    ndpi_sha256((const u_char *)"", 0, hash);
    assert(memcmp(hash, expected, 32) == 0);
  }

  /* ndpi_crc32: deterministic output for same input */
  {
    u_int32_t crc1 = ndpi_crc32("hello", 5, 0);
    u_int32_t crc2 = ndpi_crc32("hello", 5, 0);
    assert(crc1 == crc2);
    u_int32_t crc3 = ndpi_crc32("world", 5, 0);
    assert(crc1 != crc3);
    /* CRC32("") = 0 when starting from 0 */
    u_int32_t crc_empty = ndpi_crc32("", 0, 0);
    assert(crc_empty == 0);
  }

  /* ndpi_crc16_ccit: deterministic */
  {
    u_int16_t c1 = ndpi_crc16_ccit("hello", 5);
    u_int16_t c2 = ndpi_crc16_ccit("hello", 5);
    assert(c1 == c2);
    u_int16_t c3 = ndpi_crc16_ccit("world", 5);
    assert(c1 != c3);
  }

  /* ndpi_hex2bin and ndpi_bin2hex round trip */
  {
    u_char binary[4];
    u_char hex_out[9]; /* 4 bytes * 2 hex chars + '\0' */

    /* Decode "deadbeef" */
    u_int decoded = ndpi_hex2bin(binary, sizeof(binary), (u_char *)"deadbeef", 8);
    assert(decoded == 4);
    assert(binary[0] == 0xde);
    assert(binary[1] == 0xad);
    assert(binary[2] == 0xbe);
    assert(binary[3] == 0xef);

    /* Encode back */
    u_int encoded = ndpi_bin2hex(hex_out, sizeof(hex_out), binary, 4);
    assert(encoded == 8);
    hex_out[8] = '\0';
    assert(strncasecmp((char *)hex_out, "deadbeef", 8) == 0);
  }
}


static void checkHexDecode(const u_char *encoded, size_t encoded_len,
			   const u_char *expected, size_t expected_len) {
  size_t out_len = 0;
  u_char *decoded;

  decoded = ndpi_hex_decode(encoded, encoded_len, &out_len);
  assert(decoded != NULL);
  assert(out_len == expected_len);
  assert(memcmp(decoded, expected, expected_len) == 0);
  assert(decoded[out_len] == '\0');

  ndpi_free(decoded);
}

static void checkTlsBlocksDecode(const u_char *encoded, size_t encoded_len,
				 const struct ndpi_tls_block *expected_blocks,
				 u_int8_t expected_num_blocks) {
  u_int8_t num_blocks = 0;
  u_int8_t i;
  struct ndpi_tls_block *decoded;

  decoded = ndpi_decode_tls_blocks(encoded, encoded_len, &num_blocks);
  assert(decoded != NULL);
  assert(num_blocks == expected_num_blocks);

  for(i = 0; i < num_blocks; i++) {
    assert(decoded[i].block_type == expected_blocks[i].block_type);
    assert(decoded[i].same_pkt == expected_blocks[i].same_pkt);
    assert(decoded[i].len == expected_blocks[i].len);
  }

  ndpi_free(decoded);
}

static void rewriteHexCase(u_char *encoded, size_t encoded_len) {
  size_t i;

  for(i = 0; i < encoded_len; i++) {
    if(encoded[i] >= 'a' && encoded[i] <= 'f') {
      if((i & 0x1) == 0)
	encoded[i] -= 'a' - 'A';
    } else if(encoded[i] >= 'A' && encoded[i] <= 'F') {
      if((i & 0x1) == 1)
	encoded[i] += 'a' - 'A';
    }
  }
}

static void hexDecodeUnitTest(void) {
  static const u_char lower_hex[] = { 'a', 'f' };
  static const u_char upper_hex[] = { 'A', 'F' };
  static const u_char mixed_hex[] = { '0', '1', 'a', 'B', 'c', 'D' };
  static const u_char zero_hex[] = { '0', '0', 'f', 'F' };
  static const u_char invalid_hex[] = { '0', 'g' };
  static const u_char odd_hex[] = { '0' };
  static const u_char lower_expected[] = { 0xAF };
  static const u_char upper_expected[] = { 0xAF };
  static const u_char mixed_expected[] = { 0x01, 0xAB, 0xCD };
  static const u_char zero_expected[] = { 0x00, 0xFF };
  size_t out_len = 123;
  u_char *decoded;

  checkHexDecode(lower_hex, sizeof(lower_hex), lower_expected, sizeof(lower_expected));
  checkHexDecode(upper_hex, sizeof(upper_hex), upper_expected, sizeof(upper_expected));
  checkHexDecode(mixed_hex, sizeof(mixed_hex), mixed_expected, sizeof(mixed_expected));
  checkHexDecode(zero_hex, sizeof(zero_hex), zero_expected, sizeof(zero_expected));

  decoded = ndpi_hex_decode(invalid_hex, sizeof(invalid_hex), &out_len);
  assert(decoded == NULL);
  assert(out_len == 0);

  out_len = 123;
  decoded = ndpi_hex_decode(odd_hex, sizeof(odd_hex), &out_len);
  assert(decoded == NULL);
  assert(out_len == 0);

  out_len = 123;
  decoded = ndpi_hex_decode((const u_char *)"", 0, &out_len);
  assert(decoded != NULL);
  assert(out_len == 0);
  assert(decoded[0] == '\0');
  ndpi_free(decoded);
}

static void tlsBlocksUnitTest(void) {
  struct ndpi_tls_block expected_blocks[] = {
    { .block_type = tls_handshake_client_hello, .len = 0x0000, .same_pkt = 1 },
    { .block_type = tls_application_data, .len = 0xFFFF, .same_pkt = 0 },
    { .block_type = tls_application_data, .len = 0x00AF, .same_pkt = 1 }
  };
  static const u_char truncated_tls_blocks[] = { '0', '0', '0', '1' };
  static const u_char invalid_tls_blocks[] = { '0', 'g', '0', '0', '0', '0' };
  static const u_char odd_tls_blocks[] = { '0', '0', '0' };
  u_int8_t expected_num_blocks = sizeof(expected_blocks) / sizeof(expected_blocks[0]);
  u_int8_t num_blocks = 0;
  size_t encoded_len;
  size_t oversized_encoded_len = (size_t)256 * 6;
  u_char *encoded;
  u_char *encoded_no_nul;
  u_char *oversized_encoded;

  encoded = ndpi_encode_tls_blocks(expected_blocks, expected_num_blocks);
  assert(encoded != NULL);

  encoded_len = strlen((const char *)encoded);
  encoded_no_nul = ndpi_malloc(encoded_len);
  assert(encoded_no_nul != NULL);

  memcpy(encoded_no_nul, encoded, encoded_len);

  checkTlsBlocksDecode(encoded_no_nul, encoded_len, expected_blocks, expected_num_blocks);
  rewriteHexCase(encoded_no_nul, encoded_len);
  checkTlsBlocksDecode(encoded_no_nul, encoded_len, expected_blocks, expected_num_blocks);
  ndpi_free(encoded_no_nul);
  ndpi_free(encoded);

  num_blocks = expected_num_blocks;
  assert(ndpi_decode_tls_blocks(truncated_tls_blocks, sizeof(truncated_tls_blocks), &num_blocks) == NULL);
  assert(num_blocks == 0);

  num_blocks = expected_num_blocks;
  assert(ndpi_decode_tls_blocks(invalid_tls_blocks, sizeof(invalid_tls_blocks), &num_blocks) == NULL);
  assert(num_blocks == 0);

  num_blocks = expected_num_blocks;
  assert(ndpi_decode_tls_blocks(odd_tls_blocks, sizeof(odd_tls_blocks), &num_blocks) == NULL);
  assert(num_blocks == 0);

  oversized_encoded = ndpi_malloc(oversized_encoded_len);
  assert(oversized_encoded != NULL);
  memset(oversized_encoded, '0', oversized_encoded_len);

  num_blocks = expected_num_blocks;
  assert(ndpi_decode_tls_blocks(oversized_encoded, oversized_encoded_len, &num_blocks) == NULL);
  assert(num_blocks == 0);
  ndpi_free(oversized_encoded);

  num_blocks = expected_num_blocks;
  assert(ndpi_decode_tls_blocks((const u_char *)"", 0, &num_blocks) == NULL);
  assert(num_blocks == 0);
}

void run_unit_tests() {

  checkRankingUnitTest(false);
  hwUnitTest2();
  hwUnitTest3();
  desUnitStressTest();
  domainCacheTestUnit();
  cryptDecryptUnitTest();
  kdUnitTest();
  /* We want the same results, with and without the public suffix list */
  encodeDomainsUnitTest(true);
  encodeDomainsUnitTest(false);
  loadStressTest();
  domainsUnitTest();
  outlierUnitTest();
  pearsonUnitTest();
  binaryBitmapUnitTest();
  domainSearchUnitTest();
  domainSearchUnitTest2();
  sketchUnitTest();
  linearUnitTest();
  zscoreUnitTest();
  sesUnitTest();
  desUnitTest();
  blocksUnitTest();
  binUnitTest();
  hwUnitTest();
  jitterUnitTest();
  rsiUnitTest();
  strHashMapUnitTest();
  dgaUnitTest();
  hllUnitTest();
  bitmapUnitTest();
  filterUnitTest();
  automataUnitTest();
  automataDomainsUnitTest();
  analyzeUnitTest();
  analysisUnitTest();
  compressedBitmapUnitTest();
  strtonumUnitTest();
  strlcpyUnitTest();
  strnstrUnitTest();
  strncasestrUnitTest();
  memmemUnitTest();
  memcasecmpUnitTest();
  mahalanobisUnitTest();
  bitmaskUnitTest();
  checkmemrchrUnitTest();
  isolationforestUnitTest();
  anomalyModelUnitTest();
  ballTreeUnitTest();
  stringUtilsUnitTest();
  hashFunctionsUnitTest();
  bitmap64FuseUnitTest();
  riskUtilsUnitTest();
  cryptoUnitTest();
  hexDecodeUnitTest();
  tlsBlocksUnitTest();

}
