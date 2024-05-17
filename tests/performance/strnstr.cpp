#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <string>
#include <vector>

char *ndpi_strnstr(const char *s, const char *find, size_t slen) {
  char c;
  size_t len;

  if ((c = *find++) != '\0') {
    len = strnlen(find, slen);
    do {
      char sc;

      do {
        if (slen-- < 1 || (sc = *s++) == '\0') return (NULL);
      } while (sc != c);
      if (len > slen) return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
  }

  return ((char *)s);
}

char *ndpi_strnstr_opt(const char *haystack, const char *needle, size_t len)
{
  if (!haystack || !needle)
  {
    return NULL;
  }

  size_t needle_len = strlen(needle);
  size_t hs_real_len = strnlen(haystack, len);

  if (!haystack || !needle)
  {
    return NULL;
  }

  if (needle_len == 0)
  {
    return (char *)haystack;
  }

  if (needle_len > hs_real_len)
  {
    return NULL;
  }

  if (needle_len == 1)
  {
    return (char *)memchr(haystack, (int)*needle, hs_real_len);
  }

  const char *current = haystack;
  const char *haystack_end = haystack + hs_real_len;

  while (current <= haystack_end - needle_len)
  {
    /* Find the first occurrence of the first character from the needle */
    current = (const char *)memchr(current, *needle, haystack_end - current);

    if (!current)
    {
      return NULL;
    }

     /* Check the rest of the needle for a match */
    if ((current + needle_len <= haystack_end) && (memcmp(current, needle, needle_len) == 0))
    {
      return (char *)current;
    }

    /* Shift one character to the right for the next search */
    current++;
  }

  return NULL;
}

std::string random_string(size_t length, std::mt19937 &gen) {
  std::uniform_int_distribution<> dis(0, 255);
  std::string str(length, 0);
  for (size_t i = 0; i < length; i++) {
    str[i] = static_cast<char>(dis(gen));
  }
  return str;
}

double measure_time(const std::function<char *(const char *, const char *,
                                               size_t)> &strnstr_impl,
                    const std::string &haystack, const std::string &needle,
                    std::mt19937 &gen) {
  auto start = std::chrono::high_resolution_clock::now();
  // Call the function to prevent optimization
  volatile auto result =
      strnstr_impl(haystack.c_str(), needle.c_str(), haystack.size());
  auto end = std::chrono::high_resolution_clock::now();

  return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
      .count();
}

int main() {
  std::ios_base::sync_with_stdio(false);
  std::mt19937 gen(std::random_device{}());

  const std::vector<size_t> haystack_lengths = {
      128, 256,  368,  448,  512,  640,  704,  768,  832, 896,
      960, 1024, 1088, 1152, 1216, 1280, 1344, 1408, 1472};
  const std::vector<size_t> needle_lengths = {5,  10, 15, 20, 25, 30,
                                              35, 40, 45, 50, 55, 60};

  const std::vector<std::pair<
      std::string, std::function<char *(const char *, const char *, size_t)>>>
      strnstr_impls = {
          {"ndpi_strnstr", ndpi_strnstr}, {"ndpi_strnstr_opt", ndpi_strnstr_opt}
          // Add other implementations for comparison here
      };

  for (size_t haystack_len : haystack_lengths) {
    for (size_t needle_len : needle_lengths) {
      std::cout << "\nTest case - Haystack length: " << haystack_len
                << ", Needle length: " << needle_len << "\n";

      std::string haystack = random_string(haystack_len, gen);
      std::string needle = random_string(needle_len, gen);

      std::map<std::string, double> times;

      for (const auto &impl : strnstr_impls) {
        double time_sum = 0.0;
        for (int i = 0; i < 100000; i++) {
          time_sum += measure_time(impl.second, haystack, needle, gen);
        }
        double average_time =
            time_sum / 100000.0;  // Average time in nanoseconds

        times[impl.first] = average_time;
        std::cout << "Average time for " << impl.first << ": " << average_time
                  << " ns\n";
      }

      // Compare execution times between implementations
      std::string fastest_impl;
      double fastest_time = std::numeric_limits<double>::max();
      for (const auto &impl_time : times) {
        if (impl_time.second < fastest_time) {
          fastest_impl = impl_time.first;
          fastest_time = impl_time.second;
        }
      }

      for (const auto &impl_time : times) {
        if (impl_time.first != fastest_impl) {
          std::cout << fastest_impl << " is " << impl_time.second / fastest_time
                    << " times faster than " << impl_time.first << "\n";
        }
      }
    }
  }

  return 0;
}
