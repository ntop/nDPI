/*
 * A fast, small, non-recursive O(nlog n) sort for the Linux kernel
 *
 * Jan 23 2005  Matt Mackall <mpm@selenic.com>
 */

#ifdef __KERNEL__
#include <linux/types.h>
#else
#ifdef WIN32
#include <stdint.h>
typedef uint32_t u_int32_t;
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#endif

/* This is a function ported from the Linux kernel lib/sort.c */

static void u_int32_t_swap(void *a, void *b, int size)
{
  u_int32_t t = *(u_int32_t *)a;
  *(u_int32_t *)a = *(u_int32_t *)b;
  *(u_int32_t *)b = t;
}

static void generic_swap(void *_a, void *_b, int size)
{
  char t;
  char *a = (char*)_a;
  char *b = (char*)_b;

  do {
    t = *a;
    *a++ = *b;
    *b++ = t;
  } while (--size > 0);
}

/**
 * sort - sort an array of elements
 * @base: pointer to data to sort
 * @num: number of elements
 * @size: size of each element
 * @cmp_func: pointer to comparison function
 * @swap_func: pointer to swap function or NULL
 *
 * This function does a heapsort on the given array. You may provide a
 * swap_func function optimized to your element type.
 *
 * Sorting time is O(n log n) both on average and worst-case. While
 * qsort is about 20% faster on average, it suffers from exploitable
 * O(n*n) worst-case behavior and extra memory requirements that make
 * it less suitable for kernel use.
 */

void sort(void *_base, size_t num, size_t size,
	  int (*cmp_func)(const void *, const void *),
	  void (*swap_func)(void *, void *, int size))
{
  /* pre-scale counters for performance */
  int i = (num/2 - 1) * size, n = num * size, c, r;
  char *base = (char*)_base;

  if (!swap_func)
    swap_func = (size == 4 ? u_int32_t_swap : generic_swap);

  /* heapify */
  for ( ; i >= 0; i -= size) {
    for (r = i; r * 2 + size < n; r  = c) {
      c = r * 2 + size;
      if (c < n - size &&
	  cmp_func(base + c, base + c + size) < 0)
	c += size;
      if (cmp_func(base + r, base + c) >= 0)
	break;
      swap_func(base + r, base + c, size);
    }
  }

  /* sort */
  for (i = n - size; i > 0; i -= size) {
    swap_func(base, base + i, size);
    for (r = 0; r * 2 + size < i; r = c) {
      c = r * 2 + size;
      if (c < i - size &&
	  cmp_func(base + c, base + c + size) < 0)
	c += size;
      if (cmp_func(base + r, base + c) >= 0)
	break;
      swap_func(base + r, base + c, size);
    }
  }
}


#if 0
/* a simple boot-time regression test */

int cmpint(const void *a, const void *b)
{
  return *(int *)a - *(int *)b;
}

int main(int argc, char *argv[]) {
  int *a, i, r = 1;

  a = ndpi_malloc(1000 * sizeof(int));

  printf("testing sort()\n");

  for (i = 0; i < 1000; i++) {
    r = (r * 725861) % 6599;
    a[i] = r;
  }

  sort(a, 1000, sizeof(int), cmpint, NULL);

  for (i = 0; i < 999; i++)
    if (a[i] > a[i+1]) {
      printf("sort() failed!\n");
      break;
    }

  return 0;
}

#endif
