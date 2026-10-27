/*
 * ollama.c
 *
 * Copyright (C) 2026 - ntop.org
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

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_OLLAMA

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * Ollama (https://ollama.com) self-hosted LLM runtime.
 *
 * NOTE 1: the well known TCP port (11434) is intentionally NOT used for
 *         classification. In production Ollama is routinely reverse-proxied,
 *         tunnelled (ssh -L) or served on arbitrary ports - in one of the
 *         captures attached to ntop/nDPI#2772 it is reached over TLS on
 *         TCP/3003 - so all the evidence below is payload based.
 *
 * NOTE 2: like every HTTP sub-protocol dissector, this runs on HTTP requests
 *         only (the flow is classified, and sub-protocol dissectors stop
 *         running, as soon as the request has been dissected). The native
 *         /api/... endpoints are unambiguous, so the request alone is enough
 *         here; for the OpenAI compatible API (/v1/...) shared with vLLM,
 *         llama.cpp and friends, see vllm.c.
 */

static void ndpi_int_ollama_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow,
                                           char * const risk_info)
{

  /*
    Ollama is named by its own route; the request body adds the API dialect when
    it is provably a DeepSeek request (llm_api.c), which is how a DeepSeek model
    served by Ollama on a private hostname is reported.
  */
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  char info[NDPI_LLM_API_INFO_LEN];

  ndpi_llm_api_info(info, sizeof(info), risk_info, NULL,
                    ndpi_llm_api_is_deepseek(packet));
  NDPI_LOG_INFO(ndpi_struct, "found Ollama\n");

  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_OLLAMA,
                             NDPI_PROTOCOL_HTTP,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, info);
}

static void ndpi_search_ollama(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Ollama\n");

  /*
    This dissector is called before HTTP has been detected too (e.g. on the SYN
    packet), so the flow MUST NOT be excluded just because it is not HTTP yet.
  */
  if(flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
    if(flow->core.packet_counter > 8)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(packet->packet_direction != 0) {
    /* Responses carry no Ollama specific evidence we can use (see NOTE 2). */
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /*
    Inference endpoints. These are always POST (the prompt is in the body), so
    requiring POST removes GET probes/crawlers from the picture.
  */
  if(flow->metadata.http.method == NDPI_HTTP_METHOD_POST &&
     (LINE_EQUALS(packet->http_url_name, "/api/chat")     ||
     LINE_EQUALS(packet->http_url_name, "/api/generate") ||
     LINE_EQUALS(packet->http_url_name, "/api/embed")    ||
     LINE_EQUALS(packet->http_url_name, "/api/show"))) {
    ndpi_int_ollama_add_connection(ndpi_struct, flow, (char *)"Ollama inference API");
    return;
  }

  /* Model management endpoints */
  if(LINE_EQUALS(packet->http_url_name, "/api/tags")    ||
     LINE_EQUALS(packet->http_url_name, "/api/version") ||
     LINE_EQUALS(packet->http_url_name, "/api/ps")      ||
     LINE_EQUALS(packet->http_url_name, "/api/pull")    ||
     LINE_EQUALS(packet->http_url_name, "/api/push")    ||
     LINE_EQUALS(packet->http_url_name, "/api/delete")  ||
     LINE_EQUALS(packet->http_url_name, "/api/copy")    ||
     LINE_EQUALS(packet->http_url_name, "/api/running") ||
     LINE_STARTS(packet->http_url_name, "/api/blobs/")) {
    ndpi_int_ollama_add_connection(ndpi_struct, flow, (char *)"Ollama model API");
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_ollama_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Ollama", ndpi_struct,
                     ndpi_search_ollama,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_OLLAMA);
}
