/* This is a function ported from the Linux kernel lib/sort.c */

void sort(void *base, size_t num, size_t len,
	  int (*cmp_func)(const void *, const void *),
	  void (*swap_func)(void *, void *, int size));
  
