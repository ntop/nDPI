/*
 * llamacpp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_LLAMA_CPP

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * llama.cpp HTTP server (https://github.com/ggml-org/llama.cpp) and the
 * applications embedding it (LM Studio, KoboldCpp, GPT4All, ...).
 *
 * The server exposes a native API (/completion, /props, /slots, ...) next to
 * an OpenAI compatible one; as usual, only the native endpoints are used to
 * name a vendor, the shared ones just raise the AI inference risk (see vllm.c).
 *
 * The default TCP port (8080) is not used for classification: see ollama.c.
 */

static void ndpi_int_llamacpp_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                             struct ndpi_flow_struct * const flow,
                                             char * const risk_info)
{

  /*
    llama.cpp is named by its own route; the request body adds the API dialect when
    it is provably a DeepSeek request (llm_api.c), which is how a DeepSeek model
    served by llama.cpp on a private hostname is reported.
  */
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  char info[NDPI_LLM_API_INFO_LEN];

  ndpi_llm_api_info(info, sizeof(info), risk_info, NULL,
                    ndpi_llm_api_is_deepseek(packet));
  NDPI_LOG_INFO(ndpi_struct, "found llama.cpp\n");

  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_LLAMA_CPP,
                             NDPI_PROTOCOL_HTTP,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, info);
}

static void ndpi_search_llamacpp(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search llama.cpp\n");

  if(flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
    if(flow->core.packet_counter > 8)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(packet->packet_direction != 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* LM Studio (llama.cpp based) REST API */
  if(LINE_STARTS(packet->http_url_name, "/api/v0/")) {
    ndpi_int_llamacpp_add_connection(ndpi_struct, flow, (char *)"LM Studio API (llama.cpp based)");
    return;
  }

  /* Inference endpoints: always POST (the prompt is in the body) */
  if(flow->metadata.http.method == NDPI_HTTP_METHOD_POST &&
     (LINE_EQUALS(packet->http_url_name, "/completion")     ||
      LINE_EQUALS(packet->http_url_name, "/embedding")      ||
      LINE_EQUALS(packet->http_url_name, "/apply-template") ||
      LINE_EQUALS(packet->http_url_name, "/infill"))) {
    ndpi_int_llamacpp_add_connection(ndpi_struct, flow, (char *)"llama.cpp inference API");
    return;
  }

  /* Management/inspection endpoints (GET, DELETE) */
  if(LINE_EQUALS(packet->http_url_name, "/props")          ||
     LINE_EQUALS(packet->http_url_name, "/slots")          ||
     LINE_EQUALS(packet->http_url_name, "/tokens")         ||
     LINE_EQUALS(packet->http_url_name, "/bdev")           ||
     LINE_EQUALS(packet->http_url_name, "/lora-adapters")) {
    ndpi_int_llamacpp_add_connection(ndpi_struct, flow, (char *)"llama.cpp management endpoint");
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_llamacpp_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("LlamaCpp", ndpi_struct,
                     ndpi_search_llamacpp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_LLAMA_CPP);
}
