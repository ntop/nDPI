/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * C useful routines
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
 *
 */


#ifndef _RLIBC_H_
#define _RLIBC_H_


/* System headers */
#include <time.h>
#include <sys/time.h>
#include <getopt.h>


/* Array length (not NULL terminated) */
#define alen(x)    (sizeof x / sizeof x [0])

/* GNU Option Array length */
#define optlen(x)  ((sizeof x / sizeof x [0]) - 1)

/* Return # of items in a NULL terminated array of any type */
#define arrlen(x)  valen((void **) x)

#define arrmore(argv, item, type) (type **) vamore ((void **) argv, (void *) item)
#define arrcleanup(argv, func)              vacleanup ((void **) argv, func)


/* A counter for packets and bytes */
typedef double counter_t;

/* A sorting function */
typedef int sf_t (const void * a, const void * b);


#ifdef __cplusplus
extern "C" {
#endif 


/* Public functions in random.c */
unsigned xrand (unsigned x);


/* Public functions in fmemdmp.c */
void memdmp (unsigned char * ptr, unsigned size, char * label);
void mem2c (unsigned char * ptr, unsigned size, char * name);


/* Public functions in options.c */
unsigned optmax (struct option * options);
char * optlegitimate (struct option * options);
char * optname (struct option * options, unsigned n, unsigned val);
void usage_item (struct option * options, unsigned n, unsigned val, char * description);


/* Public functions in varrays.c */
char * itoa (int n);
unsigned valen (void * argv []);
void ** vamore (void * argv [], void * item);
void ** valess (void * argv [], void * item, void (* rmitem) (void *));
void ** vacleanup (void * argv [], void (* rmitem) (void *));
void ** vadup (void * argv []);
unsigned vadigits (unsigned n);
char * valeft (unsigned n);
void ** vasort (void * argv [], sf_t * cmpfunc);

char ** argsadd (char * argv [], char * s);
char ** argsuniq (char * argv [], char * item);
void argsfree (char * argv []);
void argsrows (char * argv []);
char ** argssort (char * argv []);
char ** argssplit (char * str, char * sep);
char * build_names (char * argv []);


/* Public functions in wall.c */
double nwall (void);
double ncpu (void);
char * msectoa (long long ms);


/* Public functions in file timeit.c */
time_t delta_time_in_milliseconds (struct timeval * t2, struct timeval * t1);
void print_time_in_secs (struct timeval * t, char * label);
char * elapsed_time (struct timeval * start, struct timeval * stop);
char * percentage (double partial, double total);
void showbar (unsigned long partial);


#ifdef __cplusplus
}
#endif


#endif /* rlibc.h */
