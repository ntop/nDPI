/*
 * intrusion_detection.c
 *
 * Copyright (C) 2011-21 - ntop.org
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

#include "intrusion_detection.h"

double normalize(ndpi_norm_value* tresholds){
  if(tresholds->upper_bound != tresholds->lower_bound){
    tresholds->norm_value = (tresholds->value - tresholds->lower_bound) / (tresholds->upper_bound - tresholds->lower_bound);
  }else{
    if(tresholds->value > tresholds->upper_bound){
      tresholds->norm_value = 1 + (tresholds->value - tresholds->lower_bound) / tresholds->upper_bound;
    }else{
      tresholds->norm_value = 1 - (tresholds->value - tresholds->lower_bound) / tresholds->upper_bound;
    }

  }
  if(tresholds->norm_value >= 0){
    return tresholds->norm_value * tresholds->weight;
  }
  else{
    return (1 - tresholds->norm_value) * tresholds->weight;
  }
}

double get_flow_score(ndpi_norm_value* scores, int n_metrics){
  double flow_score = 0;
  for(int i=0; i<n_metrics; i++){
    flow_score += normalize(&scores[i]);
  }
  return flow_score;
}

/* ********************************** */

double Ddos_score(struct ndpi_flow_info* flow){
  int n_metrics = 6;
  ndpi_norm_value* scores = malloc(n_metrics * sizeof(ndpi_norm_value));
  /* pktlen_c_to_s_avg */
  int i = 0;
  scores[i].lower_bound = 70.0;
  scores[i].upper_bound = 263.4799999999999;
  scores[i].weight = 0.21257330032661592;
  scores[i].value = ndpi_data_average(flow->pktlen_c_to_s);

  /* pktlen_s_to_c_max */
  i++;
  scores[i].lower_bound = 90.0;
  scores[i].upper_bound = 2974.0;
  scores[i].weight = 0.21073785073559176;
  scores[i].value = ndpi_data_max(flow->pktlen_s_to_c);

  /* pktlen_s_to_c_avg */
  i++;
  scores[i].lower_bound = 72.7;
  scores[i].upper_bound = 1130.4199999999996;
  scores[i].weight = 0.21257330032661592;
  scores[i].value = ndpi_data_average(flow->pktlen_s_to_c);

  /* pktlen_s_to_c_stddev */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 906.0;
  scores[i].weight = 0.20990954527912953;
  scores[i].value = ndpi_data_stddev(flow->pktlen_s_to_c);

  /* fin */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.07710300166602348;
  scores[i].value = flow->fin_count;

  /* s_to_c_fin */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.07710300166602348;
  scores[i].value = flow->dst2src_fin_count;

  // sum = 1.0
  double flow_score = get_flow_score(scores, n_metrics);
  free(scores);
  return flow_score;
}

double Dos_goldeneye_score(struct ndpi_flow_info* flow){
  int n_metrics = 6;
  ndpi_norm_value* scores = malloc(n_metrics * sizeof(ndpi_norm_value));
  /* pktlen_s_to_c_max */
  int i = 0;
  scores[i].lower_bound = 74.0;
  scores[i].upper_bound = 3292.6699999999764;
  scores[i].weight = 0.3123007140611667;
  scores[i].value = ndpi_data_max(flow->pktlen_s_to_c);
  /* pktlen_s_to_c_avg */
  i++;
  scores[i].lower_bound = 68.7;
  scores[i].upper_bound = 1354.0569999999987;
  scores[i].weight = 0.23802038891633356;
  scores[i].value = ndpi_data_average(flow->pktlen_s_to_c);

  /* pktlen_s_to_c_stddev */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 959.4469999999993;
  scores[i].weight = 0.3111779763775991;
  scores[i].value = ndpi_data_stddev(flow->pktlen_s_to_c);

  /* syn */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.0464364305923564;
  scores[i].value = flow->syn_count;

  /* c_to_s_syn */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 1.0;
  scores[i].weight = 0.04562805946018772;
  scores[i].value = flow->src2dst_syn_count;

  /* s_to_c_syn */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.0464364305923564;
  scores[i].value = flow->dst2src_syn_count;

  // sum = 0.9999999999999998
  double flow_score = get_flow_score(scores, n_metrics);
  free(scores);
  return flow_score;
}

double Dos_hulk_score(struct ndpi_flow_info* flow){
  double f = (double)flow->first_seen_ms/1000.0, l = (double)flow->last_seen_ms/1000.0;
  int n_metrics = 6;
  ndpi_norm_value* scores = malloc(n_metrics * sizeof(ndpi_norm_value));
  /* duration */
  int i = 0;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 539.40668006422;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = (l - f);

  /* src2dst_packets */
  i++;
  scores[i].lower_bound = 2.0;
  scores[i].upper_bound = 41.0;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = flow->src2dst_packets;

  /* dst2src_packets */
  i++;
  scores[i].lower_bound = 2.0;
  scores[i].upper_bound = 45.0;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = flow->dst2src_packets;

  /* src2dst_bytes */
  i++;
  scores[i].lower_bound = 146.0;
  scores[i].upper_bound = 6306.300000000001;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = flow->src2dst_bytes;

  /* ack */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 82.0;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = flow->ack_count;

  /* syn */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = flow->syn_count;

  // sum = 0.9999999999999999
  double flow_score = get_flow_score(scores, n_metrics);
  free(scores);
  return flow_score;
}

double Dos_slow_score(struct ndpi_flow_info* flow){
  int n_metrics = 6;
  ndpi_norm_value* scores = malloc(n_metrics * sizeof(ndpi_norm_value));
  /* pktlen_s_to_c_max */
  int i = 0;
  scores[i].lower_bound = 90.0;
  scores[i].upper_bound = 3135.0;
  scores[i].weight = 0.1760747755022144;
  scores[i].value = ndpi_data_max(flow->pktlen_s_to_c);

  /* pktlen_s_to_c_avg */
  i++;
  scores[i].lower_bound = 80.37100000000001;
  scores[i].upper_bound = 1292.5900000000008;
  scores[i].weight = 0.17600137023171597;
  scores[i].value = ndpi_data_average(flow->pktlen_s_to_c);

  /* dst2src_bytes */
  i++;
  scores[i].lower_bound = 262.0;
  scores[i].upper_bound = 53227.80000000002;
  scores[i].weight = 0.16919914849886225;
  scores[i].value = flow->dst2src_bytes;

  /* syn */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.168000195747388;
  scores[i].value = flow->syn_count;

  /* c_to_s_syn */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 1.0;
  scores[i].weight = 0.14272431427243143;
  scores[i].value = flow->src2dst_syn_count;

  /* s_to_c_syn */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.168000195747388;
  scores[i].value = flow->dst2src_syn_count;

  // sum = 1.0
  double flow_score = get_flow_score(scores, n_metrics);
  free(scores);
  return flow_score;
}

double Ftp_patator_score(struct ndpi_flow_info* flow){
  int n_metrics = 6;
  ndpi_norm_value* scores = malloc(n_metrics * sizeof(ndpi_norm_value));
  /* iat_flow_min */
  int i = 0;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 24.0;
  scores[i].weight = 0.002732919254658385;
  scores[i].value = ndpi_data_min(flow->iat_flow);

  /* pktlen_s_to_c_max */
  i++;
  scores[i].lower_bound = 90.0;
  scores[i].upper_bound = 3393.0;
  scores[i].weight = 0.007453416149068323;
  scores[i].value = ndpi_data_max(flow->pktlen_s_to_c);

  /* pktlen_s_to_c_avg */
  i++;
  scores[i].lower_bound = 81.3;
  scores[i].upper_bound = 1315.021;
  scores[i].weight = 0.9833540372670807;
  scores[i].value = ndpi_data_average(flow->pktlen_s_to_c);

  /* dst2src_bytes */
  i++;
  scores[i].lower_bound = 256.0;
  scores[i].upper_bound = 56434.0;
  scores[i].weight = 0.0034782608695652175;
  scores[i].value = flow->dst2src_bytes;

  /* fin */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.0014906832298136647;
  scores[i].value = flow->fin_count;

  /* rst */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.0014906832298136647;
  scores[i].value = flow->rst_count;

  // sum = 1.0
  double flow_score = get_flow_score(scores, n_metrics);
  free(scores);
  return flow_score;
}

double Hearthbleed_score(struct ndpi_flow_info* flow){
  double f = (double)flow->first_seen_ms/1000.0, l = (double)flow->last_seen_ms/1000.0;
  int n_metrics = 6;
  ndpi_norm_value* scores = malloc(n_metrics * sizeof(ndpi_norm_value));
  /* iat_flow_max */
  int i = 0;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 595213.3999999999;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = ndpi_data_max(flow->iat_flow);

  /* iat_flow_stddev */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 245377.74799999973;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = ndpi_data_stddev(flow->iat_flow);

  /* pktlen_s_to_c_max */
  i++;
  scores[i].lower_bound = 74.0;
  scores[i].upper_bound = 3380.0;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = ndpi_data_max(flow->pktlen_s_to_c);

  /* pktlen_s_to_c_avg */
  i++;
  scores[i].lower_bound = 70.0;
  scores[i].upper_bound = 1344.6399999999996;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = ndpi_data_average(flow->pktlen_s_to_c);

  /* pktlen_s_to_c_stddev */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 944.6399999999996;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = ndpi_data_stddev(flow->pktlen_s_to_c);

  /* duration */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 711.6677598000391;
  scores[i].weight = 0.16666666666666666;
  scores[i].value = (l - f);

  // sum = 0.9999999999999999
  double flow_score = get_flow_score(scores, n_metrics);
  free(scores);
  return flow_score;
}

double Infiltration_score(struct ndpi_flow_info* flow){
  int n_metrics = 6;
  ndpi_norm_value* scores = malloc(n_metrics * sizeof(ndpi_norm_value));
  /* pktlen_c_to_s_max */
  int i = 0;
  scores[i].lower_bound = 72.0;
  scores[i].upper_bound = 1840.739999999998;
  scores[i].weight = 0.11937557392102846;
  scores[i].value = ndpi_data_max(flow->pktlen_c_to_s);

  /* pktlen_c_to_s_avg */
  i++;
  scores[i].lower_bound = 70.0;
  scores[i].upper_bound = 296.56599999999816;
  scores[i].weight = 0.12526782981328435;
  scores[i].value = ndpi_data_average(flow->pktlen_c_to_s);

  /* pktlen_s_to_c_max */
  i++;
  scores[i].lower_bound = 90.0;
  scores[i].upper_bound = 3496.1399999999776;
  scores[i].weight = 0.13927150290786652;
  scores[i].value = ndpi_data_max(flow->pktlen_s_to_c);

  /* pktlen_s_to_c_avg */
  i++;
  scores[i].lower_bound = 72.6;
  scores[i].upper_bound = 1367.7959999999991;
  scores[i].weight = 0.12182430364248545;
  scores[i].value = ndpi_data_average(flow->pktlen_s_to_c);

  /* src2dst_bytes */
  i++;
  scores[i].lower_bound = 144.0;
  scores[i].upper_bound = 7847.69999999999;
  scores[i].weight = 0.12059993878175697;
  scores[i].value = flow->src2dst_bytes;

  /* dst2src_bytes */
  i++;
  scores[i].lower_bound = 236.0;
  scores[i].upper_bound = 74486.7799999998;
  scores[i].weight = 0.3736608509335782;
  scores[i].value = flow->dst2src_bytes;

  // sum = 1.0
  double flow_score = get_flow_score(scores, n_metrics);
  free(scores);
  return flow_score;
}

double Ssh_patator_score(struct ndpi_flow_info* flow){
  int n_metrics = 6;
  ndpi_norm_value* scores = malloc(n_metrics * sizeof(ndpi_norm_value));
  /* fin */
  int i = 0;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.0033738191632928477;
  scores[i].value = flow->fin_count;

  /* psh */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 30.0;
  scores[i].weight = 0.33076923076923076;
  scores[i].value = flow->psh_count;

  /* c_to_s_syn */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 1.0;
  scores[i].weight = 0.0004048582995951417;
  scores[i].value = flow->src2dst_syn_count;

  /* c_to_s_psh */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 12.0;
  scores[i].weight = 0.33130904183535764;
  scores[i].value = flow->src2dst_psh_count;

  /* s_to_c_fin */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 2.0;
  scores[i].weight = 0.0033738191632928477;
  scores[i].value = flow->dst2src_fin_count;

  /* s_to_c_psh */
  i++;
  scores[i].lower_bound = 0.0;
  scores[i].upper_bound = 30.0;
  scores[i].weight = 0.33076923076923076;
  scores[i].value = flow->dst2src_psh_count;

  // sum = 1.0
  double flow_score = get_flow_score(scores, n_metrics);
  free(scores);
  return flow_score;
}
