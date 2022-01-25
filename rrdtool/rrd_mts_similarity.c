/*
 * rrd_mts_similarity.c
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
#include <string.h>
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
#define MAX_NUM_USERS  1024
#define MAX_NUM_FILE   20

#ifndef PATH_MAX
#define PATH_MAX       4096
#endif

typedef struct {
  char *path;
  float average, stddev;
  struct ndpi_bin b;
} rrd_file_stats;

typedef struct {
  float mts_average, mts_stddev;
  struct ndpi_bin mts_b;
  rrd_file_stats rfs[MAX_NUM_FILE];
}rrd_multifile_stats;

u_int verbose = 0, similarity_threshold = 100, skip_zero = 0;

/* *************************************************** */

static void help() {
  printf("Usage: rrd_mts_similarity [-v][-a <alpha>][-e <end>][-q][-s <start>]\n"
	 "                      -f <filename_1>+<filename_2>+...+<filename_n> -d <basedir> [-t <threshold>]\n"
	 "-a             		| Set alpha. Valid range >0 .. <1. Default %.2f\n"
	 "-e <end>       		| RRD end time. Default %s\n"
	 "-q             		| Quick output (only anomalies are reported)\n"
	 "-s <start>     		| RRD start time. Default %s\n"

	 "-d <basedir>   		| Base directory where RRD filename is searched\n"
	 "-f <rrd_path1>+<rrd_path2>...	| Path of the RRDs filename to analyze, they must be chained using '+' character\n"
	 "-t <threshold> 		| Similarity threshold. Default %u (0 == alike)\n"
	 "-v             		| Verbose\n"
	 "-z             		| Skip zero RRDs during comparison\n"
	 ,
	 DEFAULT_ALPHA, DEFAULT_END, DEFAULT_START, similarity_threshold);

  printf("\n\nExample: rrd_mts_similarity -q -f bytes.rrd+score.rrd -d /var/lib/ntopng/-1/snmpstats\n");

  printf("\n\nGoal: find similar RRDs\n");
  exit(0);
}

/* *************************************************** */

void analyze_rrd(rrd_file_stats *rrd, time_t start, time_t end) {
  unsigned long  step = 0, ds_cnt = 0;
  rrd_value_t *data, *p;
  char **names;
  u_int t, i, num_points;
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

  // Step 1 - Compute average and stddev 
  for(t=start+1, i=0; t<end; t+=step, i++) {
    double value = (double)*p++;

    if(isnan(value)) value = 0; 
    ndpi_data_add_value(s, value);
    ndpi_set_bin(&rrd->b, i, value);
  }

  rrd->average = ndpi_data_average(s);
  rrd->stddev  = ndpi_data_stddev(s);

  // Step 2 - Bin analysis
  ndpi_free_data_analysis(s, 1);
  rrd_freemem(data);
}

/* *************************************************** */

void analyze_mts(rrd_multifile_stats *rrdms, time_t start, time_t end, int n_file) {
  unsigned long  step = 0, ds_cnt = 0;
  rrd_value_t *data;
  char **names;
  u_int t, i, j = 0, num_points;
  struct ndpi_analyze_struct *s;

  /* Initializzation of mts_data */
  rrd_value_t **mts_data;
  
  mts_data = malloc(sizeof(rrd_value_t*)*MAX_NUM_FILE);
  for(i=0; i<MAX_NUM_FILE; i++)
    mts_data[i] = malloc(sizeof(rrd_value_t));

  for(i=0; i<n_file; i++)
  {
    if(rrdms->rfs[i].path != NULL)
    { 
      if(rrd_fetch_r(rrdms->rfs[i].path, "AVERAGE", &start, &end, &step, &ds_cnt, &names, &data) != 0) {
        printf("Unable to extract data from rrd %s\n", rrdms->rfs[i].path);
        return;
      }
      
      mts_data[j] = data;
      j++;
    }
  }
  
  num_points = (end-start)/step;

  if((s = ndpi_alloc_data_analysis(num_points)) == NULL)
    return;

  ndpi_init_bin(&rrdms->mts_b, ndpi_bin_family32, num_points);
  
  double value,acc;

  /* Step 1 - Compute average and stddev */
  for(t=start+1, j=0; t<end; t+=step, j++) {
  value = 0;
  acc = 0;
    /* For each Time Series we took the t-th point */
    for(i=0; i<n_file; i++){
      value = (double)*mts_data[i]++;		
      if(!isnan(value)) acc += value;  			
    }
    
    /* Multivariate Time Series takes the average of the values found */
    ndpi_data_add_value(s, acc/n_file);
    ndpi_set_bin(&rrdms->mts_b, j, acc/n_file);
  }

  /* Compute MTS's average and stddev */
  rrdms->mts_average = ndpi_data_average(s);
  rrdms->mts_stddev  = ndpi_data_stddev(s);

  /* Step 2 - Bin analysis */
  ndpi_free_data_analysis(s, 1);
    
  free(mts_data);
}

/* *************************************************** */

int circles_touch(int x1, int r1, int x2, int r2) {
  int radius_sum = r1+r2;
  int x_diff     = abs(x1 - x2);

  return((radius_sum < x_diff) ? 0 : 1);
}

/* *************************************************** */

void find_rrd_similarities(rrd_file_stats rrd1, rrd_file_stats rrd2) {
     
      if((rrd1.average == 0) && (rrd1.average == rrd2.average)) {
        if(!skip_zero)
	  printf("%s [%.1f/%.1f]  - %s [%.1f/%.1f] are alike\n",
		 rrd1.path, rrd1.average, rrd1.stddev,
		 rrd2.path, rrd2.average, rrd2.stddev);
      } else if(circles_touch(rrd1.average, rrd1.stddev, rrd2.average, rrd2.stddev)) 
        {
	  float similarity = ndpi_bin_similarity(&rrd1.b, &rrd2.b, 0, similarity_threshold);

	  if((similarity >= 0) && (similarity < similarity_threshold)) {
	    if(verbose)
	      printf("%s [%.1f/%.1f]  - %s [%.1f/%.1f] are %s [%.1f]\n",
		   rrd1.path, rrd1.average, rrd1.stddev,
		   rrd2.path, rrd2.average, rrd2.stddev,
		   (similarity == 0) ? "alike" : "similar",
		   similarity
		   );
    }
  }
}

/* *************************************************** */

void find_rrd_multi_similarities(rrd_multifile_stats rrdms[], u_int num_tot_rrds, int num_host, int n_file) {
  u_int i, j, z, num_similar_mts = 0, num_potentially_zero_equal = 0;

  for(i=0; i<num_host; i++) {
    for(j=i+1; j<num_host; j++) {
      /*
	Average is the circle center, and stddev is the radius
	if circles touch each other then there is a chance that
	the two rrds are similar
      */

      if((rrdms[i].mts_average == 0) && (rrdms[i].mts_average == rrdms[j].mts_average)) {
	if(!skip_zero)
	    printf("Host: %d [%.1f/%.1f]  - Host: %d [%.1f/%.1f] are alike\n",
		   i, rrdms[i].mts_average, rrdms[i].mts_stddev,
		   j, rrdms[j].mts_average, rrdms[j].mts_stddev);
	  
	num_potentially_zero_equal++;
      } else if(circles_touch(rrdms[i].mts_average, rrdms[i].mts_stddev, rrdms[j].mts_average, rrdms[j].mts_stddev)
		) {
	float similarity = ndpi_bin_similarity(&rrdms[i].mts_b, &rrdms[j].mts_b, 0, similarity_threshold);

	if((similarity >= 0) && (similarity < similarity_threshold)) {
	  if(verbose)
	    printf("Host: %d [%.1f/%.1f]  - Host: %d [%.1f/%.1f] are %s [%.1f]\n",
		   i, rrdms[i].mts_average, rrdms[i].mts_stddev,
		   j, rrdms[j].mts_average, rrdms[j].mts_stddev,
		   (similarity == 0) ? "alike" : "similar",
		   similarity
		   );
          /* If the two mts are similar we check the similarity of each of their files */
	  for(z = 0; z < n_file; z++)
            find_rrd_similarities(rrdms[i].rfs[z], rrdms[j].rfs[z]);
		
	  num_similar_mts++;
	}
      }
    }
  }
 
  printf("Found %u (%.3f %%) similar Multivariates / %u zero alike Multivariates [num_mts: %d]\n",
	 num_similar_mts,
	 (num_similar_mts*100.)/(float)(num_host*num_host),
	 num_potentially_zero_equal,
	 num_host);
}

/* *************************************************** */

int find_rrds(char *basedir, char *filename[], rrd_multifile_stats *rrdms, u_int *num_tot_rrds, int n_file, int *num_host) {
  struct dirent **namelist;
  int n = scandir(basedir, &namelist, 0, NULL);
  u_int i;
  bool t = true;
  char path[PATH_MAX];
  char* temp[n_file];

  if(n < 0)
    return; /* End of the tree */

  while(n--) {
    if(namelist[n]->d_name[0] != '.') {
      struct stat s;

      snprintf(path, sizeof(path), "%s/%s", basedir, namelist[n]->d_name);

      if(stat(path, &s) == 0) {
	if(S_ISDIR(s.st_mode))
	 find_rrds(path, filename, rrdms, num_tot_rrds, n_file, num_host);
	else {
	for(i=0; i<n_file; i++){
	  if(strcmp(namelist[n]->d_name, filename[i]) == 0) {
	    if(*num_tot_rrds < (MAX_NUM_RRDS-n_file)) {
	     temp[i] = strdup(path);
	      }
	    }
	  }
	}
      }
    }
    free(namelist[n]);
  }
  
  free(namelist);
	
  for(i=0; i<n_file; i++){
    if(temp[i] == NULL)
      t = false;
  }

  /* If we have found all the requested files, we count the directory as a host */
  if(t)
  {
    for(i=0; i<n_file; i++)
      rrdms[*num_host].rfs[i].path = temp[i];
	  
    (*num_host)++;
    (*num_tot_rrds) += n_file;
  }
}

/* *************************************************** */

int main(int argc, char *argv[]) {
  rrd_time_value_t start_tv, end_tv;
  char **filename = NULL, *start_s, *end_s, *dirname = NULL, *basedir = NULL;
  u_int first = 1, quick_mode = 0;
  float alpha;
  char c;
  time_t start, end;
  u_int num_tot_rrds = 0, i, j = 0;
  rrd_multifile_stats *rrdms;
  int n_file = 0, num_host = 0;

  /* Defaults */
  alpha   = DEFAULT_ALPHA;
  start_s = DEFAULT_START;
  end_s   = DEFAULT_END;
  
  while((c = getopt(argc, argv, "d:s:e:a:qf:t:vz")) != '?')
  {
    if(c == -1) break;

    switch(c)
    {
      case 's':
        start_s = optarg;
      break;

      case 'd':
        basedir = optarg;
      break;

      case 'e':
        end_s = optarg;
      break;

      case 'q':
        quick_mode = 1;
      break;

      case 'v':
        verbose = 1;
      break;

      case 'a':
      {
	float f = atof(optarg);

	if((f > 0) && (f < 1))
	  alpha = f;
	else
	  printf("Discarding -a: valid range is >0 .. <1\n");
      }
      break;

      case 'f':
       if(n_file == 0)
    	 filename = malloc(sizeof(char*)*MAX_NUM_FILE);
		 
       char* token = strtok(optarg, "+");
       while(token != NULL)
       {
         filename[n_file] = strdup(token); 
         n_file++;
	       
	 token = strtok(NULL, "+");
       } 
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

   if((rrdms = ndpi_calloc(sizeof(rrd_multifile_stats), MAX_NUM_USERS)) == NULL) {
           printf("Not enough memory !\n");
           return -1;
   }

  /* Find all rrd's */
  find_rrds(basedir, filename, rrdms, &num_tot_rrds, n_file, &num_host);

  /* Read RRD's data */
  for(i=0; i<num_host; i++)
  { for(j=0; j<n_file; j++)
    {
      if(rrdms[i].rfs[j].path != NULL)
        analyze_rrd(&rrdms[i].rfs[j], start, end);
    }

    analyze_mts(&rrdms[i], start, end, n_file);
  }

  find_rrd_multi_similarities(rrdms, num_tot_rrds, num_host, n_file);

#if 0
  if(verbose) {
    for(i=0; i<num_tot_rrds; i++)
      printf("%s\t%.1f\t%.1f\n", rrds[i].path, rrds[i].average, rrds[i].stddev);
  }
#endif
  
  for(i=0; i<num_host; i++) {
    for(j=0; j<n_file; j++){
      ndpi_free_bin(&rrdms[i].rfs[j].b);
      free(rrdms[i].rfs[j].path);
    }
  }

  ndpi_free(rrdms);
	
  for(i=0; i<n_file; i++)
    free(filename[i]);
	
  free(filename);
  return(0);
}
