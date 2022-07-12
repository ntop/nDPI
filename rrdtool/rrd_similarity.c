/*
 * rrd_similarity.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/stat.h>


#include "rrd.h"
#include "ndpi_api.h"

#define DEFAULT_ALPHA  0.5
#define DEFAULT_START  "now-1d"
#define DEFAULT_END    "now"

#define MAX_NUM_RRDS   8192

#ifndef PATH_MAX
#define PATH_MAX       4096
#endif

typedef struct {
  char *path;
  float average, stddev;
  struct ndpi_bin b;
} rrd_file_stats;

u_int verbose = 0, similarity_threshold = 100, skip_zero = 0;

/* *************************************************** */

static void help() {
  printf("Usage: rrd_similarity [-v][-e <end>][-q][-s <start>]\n"
	 "                      -f <filename> -d <basedir> [-t <threshold>]\n"
	 "-a             | Set alpha. Valid range >0 .. <1. Default %.2f\n"
	 "-e <end>       | RRD end time. Default %s\n"
	 "-q             | Quick output (only anomalies are reported)\n"
	 "-s <start>     | RRD start time. Default %s\n"

	 "-d <basedir>   | Base directory where RRD filename is searched\n"
	 "-f <rrd path>  | Path of the RRD filename to analyze\n"
	 "-t <threshold> | Similarity threshold. Default %u (0 == alike)\n"
	 "-v             | Verbose\n"
	 "-z             | Skip zero RRDs during comparison\n"
	 ,
	 DEFAULT_ALPHA, DEFAULT_END, DEFAULT_START, similarity_threshold);

  printf("\n\nExample: rrd_similarity -q -f bytes.rrd -d /var/lib/ntopng/-1/snmpstats\n");

  printf("\n\nGoal: find similar RRDs\n");
  exit(0);
}

/* *************************************************** */

void analyze_rrd(rrd_file_stats *rrd, time_t start, time_t end) {
  unsigned long  step = 0, ds_cnt = 0;
  rrd_value_t *data, *p;
  char **names;
  time_t t;
  u_int i, num_points;
  struct ndpi_analyze_struct *s;

  if(rrd_fetch_r(rrd->path, "AVERAGE", &start, &end, &step, &ds_cnt, &names, &data) != 0) {
    printf("Unable to extract data from rrd %s\n", rrd->path);
    return;
  }

  p = data;
  num_points = (end-start)/step;

  if((s = ndpi_alloc_data_analysis(num_points)) == NULL)
    return;

  ndpi_init_bin(&rrd->b, ndpi_bin_family32, num_points);

  /* Step 1 - Compute average and stddev */
  for(t=start+1, i=0; t<end; t+=step, i++) {
    double value = (double)*p++;
    
    if(isnan(value)) value = 0;
    ndpi_data_add_value(s, value);
    ndpi_set_bin(&rrd->b, i, value);
  }

  rrd->average = ndpi_data_average(s);
  rrd->stddev  = ndpi_data_stddev(s);

  /* Step 2 - Bin analysis */
  ndpi_free_data_analysis(s, 1);
  rrd_freemem(data);
}

/* *************************************************** */

int circles_touch(int x1, int r1, int x2, int r2) {
  int radius_sum = r1+r2;
  int x_diff     = abs(x1 - x2);

  return((radius_sum < x_diff) ? 0 : 1);
}


/* *************************************************** */

void find_rrd_similarities(rrd_file_stats *rrd, u_int num_rrds) {
  u_int i, j, num_similar_rrds = 0, num_potentially_zero_equal = 0;

  for(i=0; i<num_rrds; i++) {
    for(j=i+1; j<num_rrds; j++) {
      /*
	Average is the circle center, and stddev is the radius
	if circles touch each other then there is a chance that
	the two rrds are similar
      */

      if((rrd[i].average == 0) && (rrd[i].average == rrd[j].average)) {
	if(!skip_zero)
	    printf("%s [%.1f/%.1f]  - %s [%.1f/%.1f] are alike\n",
		   rrd[i].path, rrd[i].average, rrd[i].stddev,
		   rrd[j].path, rrd[j].average, rrd[j].stddev);
	  
	num_potentially_zero_equal++;
      } else if(circles_touch(rrd[i].average, rrd[i].stddev, rrd[j].average, rrd[j].stddev)
		) {
	float similarity = ndpi_bin_similarity(&rrd[i].b, &rrd[j].b, 0, similarity_threshold);

	if((similarity >= 0) && (similarity < similarity_threshold)) {
	  if(verbose)
	    printf("%s [%.1f/%.1f]  - %s [%.1f/%.1f] are %s [%.1f]\n",
		   rrd[i].path, rrd[i].average, rrd[i].stddev,
		   rrd[j].path, rrd[j].average, rrd[j].stddev,
		   (similarity == 0) ? "alike" : "similar",
		   similarity
		   );

	  num_similar_rrds++;
	}
      }
    }
  }

  printf("Found %u (%.3f %%) similar RRDs / %u zero alike RRDs [num_rrds: %u]\n",
	 num_similar_rrds,
	 (num_similar_rrds*100.)/(float)(num_rrds*num_rrds),
	 num_potentially_zero_equal,
	 num_rrds);
}

/* *************************************************** */

void find_rrds(char *basedir, char *filename, rrd_file_stats *rrds, u_int *num_rrds) {
  struct dirent **namelist;
  int n = scandir(basedir, &namelist, 0, NULL);

  if(n < 0)
    return; /* End of the tree */

  while(n--) {
    if(namelist[n]->d_name[0] != '.') {
      char path[PATH_MAX];
      struct stat s;

      ndpi_snprintf(path, sizeof(path), "%s/%s", basedir, namelist[n]->d_name);

      if(stat(path, &s) == 0) {
	if(S_ISDIR(s.st_mode))
	  find_rrds(path, filename, rrds, num_rrds);
	else if(strcmp(namelist[n]->d_name, filename) == 0) {
	  if(*num_rrds < MAX_NUM_RRDS) {
	    rrds[*num_rrds].path = strdup(path);
	    if(rrds[*num_rrds].path != NULL)
	      (*num_rrds)++;
	  }
	}
      }
    }

    free(namelist[n]);
  }

  free(namelist);
}

/* *************************************************** */

int main(int argc, char *argv[]) {
  rrd_time_value_t start_tv, end_tv;
  char *filename = NULL, *start_s, *end_s, *basedir = NULL;
  int c;
  time_t start, end;
  u_int num_rrds = 0, i;
  rrd_file_stats *rrds;

  /* Defaults */
  start_s = DEFAULT_START;
  end_s   = DEFAULT_END;


  while((c = getopt(argc, argv, "d:s:e:a:qf:t:vz")) != '?') {
    if(c == -1) break;

    switch(c) {
    case 's':
      start_s = optarg;
      break;

    case 'd':
      basedir = optarg;
      break;

    case 'e':
      end_s = optarg;
      break;

    case 'v':
      verbose = 1;
      break;

    case 'f':
      filename = optarg;
      break;

    case 't':
      similarity_threshold = atoi(optarg);
      break;

    case 'z':
      skip_zero = 1;
      break;

    default:
      help();
      break;
    }
  }

  if((filename == NULL) || (basedir == NULL))
    help();

  if((rrd_parsetime(start_s, &start_tv) != NULL)) {
    printf("Unable to parse start time %s\n", start_s);
    return(-1);
  }

  if((rrd_parsetime(end_s, &end_tv) != NULL)) {
    printf("Unable to parse end time %s\n", end_s);
    return(-1);
  }

  rrd_proc_start_end(&start_tv, &end_tv, &start, &end);

  if((rrds = ndpi_calloc(sizeof(rrd_file_stats), MAX_NUM_RRDS)) == NULL) {
    printf("Not enough memory !\n");
    return(-1);
  }

  /* Find all rrd's */
  find_rrds(basedir, filename, rrds, &num_rrds);

  /* Read RRD's data */
  for(i=0; i<num_rrds; i++)
    analyze_rrd(&rrds[i], start, end);

  find_rrd_similarities(rrds, num_rrds);

#if 0
  if(verbose) {
    for(i=0; i<num_rrds; i++)
      printf("%s\t%.1f\t%.1f\n", rrds[i].path, rrds[i].average, rrds[i].stddev);
  }
#endif
  
  for(i=0; i<num_rrds; i++) {
    ndpi_free_bin(&rrds[i].b);
    free(rrds[i].path);
  }

  ndpi_free(rrds);

  return(0);
}
