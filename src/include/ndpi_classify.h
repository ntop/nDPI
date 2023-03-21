/*
 *
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file ndpi_classify.h
 *
 * \brief header file for inline Classification functionality
 */

#ifndef NDPI_CLASSIFY_H
#define NDPI_CLASSIFY_H

#include "ndpi_includes.h"

/* constants */
#define NUM_PARAMETERS_SPLT_LOGREG 208
#define NUM_PARAMETERS_BD_LOGREG 464
#define MC_BINS_LEN 10
#define MC_BINS_TIME 10
#define MC_BIN_SIZE_TIME 50
#define MC_BIN_SIZE_LEN 150
#define MAX_BIN_LEN 1500
#define NUM_BD_VALUES 256
#define NDPI_TIMESTAMP_LEN       64

/** Classifier parameter type codes */
typedef enum {
    SPLT_PARAM_TYPE = 0,
    BD_PARAM_TYPE = 1
} classifier_type_codes_t;

extern float parameters_bd[NUM_PARAMETERS_BD_LOGREG];
extern float parameters_splt[NUM_PARAMETERS_SPLT_LOGREG];

/* Classifier functions */
float ndpi_classify(const unsigned short *pkt_len, const pkt_timeval *pkt_time,
       const unsigned short *pkt_len_twin, const pkt_timeval *pkt_time_twin,
       pkt_timeval start_time, pkt_timeval start_time_twin, u_int32_t max_num_pkt_len,
       u_int16_t sp, u_int16_t dp, u_int32_t op, u_int32_t ip, u_int32_t np_o, u_int32_t np_i,
       u_int32_t ob, u_int32_t ib, u_int16_t use_bd, const u_int32_t *bd, const u_int32_t *bd_t);

void ndpi_merge_splt_arrays(const u_int16_t *pkt_len, const pkt_timeval *pkt_time,
       const u_int16_t *pkt_len_twin, const pkt_timeval *pkt_time_twin,
       pkt_timeval start_time, pkt_timeval start_time_twin,
       u_int16_t s_idx, u_int16_t r_idx,
       u_int16_t *merged_lens, u_int16_t *merged_times);

void ndpi_update_params(classifier_type_codes_t param_type, const char *param_file);

void ndpi_flow_info_freer(void *node);
unsigned int ndpi_timer_eq(const pkt_timeval *a, const pkt_timeval *b);
unsigned int ndpi_timer_lt(const pkt_timeval *a, const pkt_timeval *b);
void ndpi_timer_sub(const pkt_timeval *a, const pkt_timeval *b, pkt_timeval *result);
void ndpi_timer_clear(pkt_timeval *a);
u_int64_t ndpi_timeval_to_milliseconds(pkt_timeval ts);
u_int64_t ndpi_timeval_to_microseconds(pkt_timeval ts);
void ndpi_log_timestamp(char *log_ts, u_int32_t log_ts_len);

#endif /* NDPI_CLASSIFY_H */
