/*
 * rrd_anomaly.c
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
#include <rrd.h>
#include "ndpi_api.h"

#define  DEFAULT_ALPHA   0.5
#define  DEFAULT_RO      0.05
#define  DEFAULT_START  "now-1d"
#define  DEFAULT_END    "now"

/* *************************************************** */

static void help() {
  printf("Usage: rrd_anomaly [-v][-a <alpha>][-e <end>][-q][-s <start>] -f <filename>\n"
	 "-a             | Set alpha. Valid range >0 .. <1. Default %.2f\n"
	 "-e <end>       | RRD end time. Default %s\n"
	 "-q             | Quick output (only anomalies are reported)\n"
	 "-s <start>     | RRD start time. Default %s\n"
	 "-f <rrd path>  | Path of the RRD filename to analyze\n"
	 "-v             | Verbose\n"
	 ,
	 DEFAULT_ALPHA, DEFAULT_END, DEFAULT_START);

  printf("\n\nExample: rrd_anomaly -q -f hum.rrd\n");
  exit(0);
}

/* *************************************************** */

int main(int argc, char *argv[]) {
  rrd_time_value_t start_tv, end_tv;
  unsigned long  step = 0, ds_cnt = 0;
  rrd_value_t *data, *p;
  char **names, *filename = NULL, *start_s, *end_s, *cf;
  u_int i, j, t, first = 1, quick_mode = 0, verbose = 0;
  time_t start, end;
  struct ndpi_ses_struct ses;
  float alpha, ro;
  char c;

  /* Defaults */
  alpha   = DEFAULT_ALPHA;
  start_s = DEFAULT_START;
  end_s   = DEFAULT_END;
  cf      = "AVERAGE";
  ro      = DEFAULT_RO;
    
  while((c = getopt(argc, argv, "s:e:a:qf:r:v")) != '?') {
    if(c == -1) break;

    switch(c) {
    case 's':
      start_s = optarg;
      break;

    case 'e':
      end_s = optarg;
      break;

    case 'q':
      quick_mode = 1;
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
      filename = optarg;
      break;

    case 'r':
      ro = atof(optarg);
      if((ro <= 0) || (ro >= 1))
	ro = DEFAULT_RO;
      break;

    case 'v':
      verbose = 1;
      break;

    default:
      help();
      break;
    }
  }

  if(filename == NULL)
    help();

  ndpi_ses_init(&ses, alpha, ro);

  if((rrd_parsetime(start_s, &start_tv) != NULL)) {
    printf("Unable to parse start time %s\n", start_s);
    return(-1);
  }

  if((rrd_parsetime(end_s, &end_tv) != NULL)) {
    printf("Unable to parse end time %s\n", end_s);
    return(-1);
  }

  rrd_proc_start_end(&start_tv, &end_tv, &start, &end);

  if(rrd_fetch_r(filename, cf, &start, &end, &step, &ds_cnt, &names, &data) != 0) {
    printf("Unable to extract data from rrd %s\n", filename);
    return(-2);
  }

  p = data;
  for(t=start+1, i=0; t<end; t+=step, i++) {
    j = 0; /* Consider only the first DS */
    /* for(j=0; j<ds_cnt; j++) */ {
      rrd_value_t value = *p++;

      if(!isnan(value)) {
	double prediction, confidence_band;
	double lower, upper;
	char buf[32];
	int rc;
	u_int is_anomaly;

	value *= 100; /* trick to avoid dealing with floats */
	rc = ndpi_ses_add_value(&ses, value, &prediction, &confidence_band);
	lower = prediction - confidence_band, upper = prediction + confidence_band;
	is_anomaly = ((rc == 0) || (confidence_band == 0) || ((value >= lower) && (value <= upper))) ? 0 : 1;
	
	if(verbose || is_anomaly) {
	  if(quick_mode) {
	    printf("%u\n", t);
	  } else {
	    const time_t _t = t;
	    struct tm *t_info = localtime((const time_t*)&_t);

	    strftime(buf, sizeof(buf), "%d/%b/%Y %H:%M:%S", t_info);

	    if(first) {
	      first = 0;
	      printf("%s                       %s\t%s    %s           %s\t %s     [%s]\n",
		     "When", "Value", "Prediction", "Lower", "Upper", "Out", "Band");
	    }

	    printf("%s %12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n",
		   buf, value/100., prediction/100., lower/100., upper/100., is_anomaly? "ANOMALY" : "OK",
		   confidence_band/100.);
	  }
	}
      }
    }
  }

  rrd_freemem(data);

  return(0);
}
