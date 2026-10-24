/*
 * vllm.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_VLLM

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * vLLM (https://vllm.ai).
 *
 * vLLM exposes an OpenAI compatible API (/v1/chat/completions, ...) next to a
 * set of vLLM specific control endpoints, and so do llama.cpp, Ollama, TGI,
 * SGLang, TensorRT-LLM, Triton, LocalAI, LM Studio, LiteLLM, the many vLLM
 * forks/distributions built for specific hardware, and a long tail of LLM
 * gateways/proxies that forward the very same JSON to any upstream provider. A
 * fork is recognised as vLLM because the wire API is vLLM's: no id is minted
 * per distribution, same reason the generic NDPI_PROTOCOL_LLM was removed in
 * 6.0.
 *
 * What this dissector does is therefore only what is vLLM specific: name the
 * protocol on vLLM's own control endpoints (/load, /scale, /model_info, ...).
 *
 * Everything else about an LLM request - which API family it speaks (OpenAI
 * compatible, Anthropic Messages, the media APIs, a tokenizer, model/metrics),
 * which engine a route belongs to when that engine has no protocol id (TGI,
 * Triton/KServe, LiteLLM, LocalAI, the MLX family, ...), and whether it is a
 * DeepSeek dialect request - lives in llm_api.c, because it is true of every
 * engine and of a gateway with no engine at all. SGLang, llama.cpp, Ollama,
 * Radiance, MLX-VLM, oMLX, vMLX and Strata call the same code, so a DeepSeek
 * request is reported as one whichever engine served it.
 *
 * The default TCP port (8000) is not used for classification: see ollama.c.
 */

static void ndpi_int_vllm_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow,
                                         char * const risk_info)
{
  NDPI_LOG_INFO(ndpi_struct, "found vLLM\n");

  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_VLLM,
                             NDPI_PROTOCOL_HTTP,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, risk_info);
}

static void ndpi_int_vllm_add_risk(struct ndpi_detection_module_struct * const ndpi_struct,
                                   struct ndpi_flow_struct * const flow,
                                   char * const risk_info)
{
  /*
    LLM API traffic with no vendor specific evidence: flag the flow, leave the
    protocol as HTTP.
  */
  if(!ndpi_isset_risk(&flow->core, NDPI_AI_INFERENCE_TRAFFIC))
    ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, risk_info);
}

static void ndpi_search_vllm(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search vLLM\n");

  if(flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
    if(flow->core.packet_counter > 8)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(packet->packet_direction != 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /*
    A flow already named by one of the engine specific dissectors does not
    need the vendorless risk on top of it. Checked here (and not by relying on
    the dissector registration order) because the order in which the HTTP
    sub-protocol dissectors are invoked is not something to depend on.
  */
  if(flow->core.detected_protocol_stack[0] == NDPI_PROTOCOL_OLLAMA   ||
     flow->core.detected_protocol_stack[0] == NDPI_PROTOCOL_LLAMA_CPP ||
     flow->core.detected_protocol_stack[0] == NDPI_PROTOCOL_SGLANG) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* vLLM specific control endpoints: these are what names the protocol */
  if(LINE_EQUALS(packet->http_url_name, "/load")          ||
     LINE_EQUALS(packet->http_url_name, "/scale")         ||
     LINE_EQUALS(packet->http_url_name, "/version")       ||
     LINE_EQUALS(packet->http_url_name, "/model_info")    ||
     LINE_EQUALS(packet->http_url_name, "/set_lora")      ||
     LINE_EQUALS(packet->http_url_name, "/sleep")         ||
     LINE_EQUALS(packet->http_url_name, "/wake_up")       ||
     LINE_EQUALS(packet->http_url_name, "/collective_rpc")) {
    ndpi_int_vllm_add_connection(ndpi_struct, flow, (char *)"vLLM control endpoint");
    return;
  }

  /*
    The shared LLM API layer (llm_api.c): first a route that belongs to an
    engine with no protocol id of its own, then the API family of the request.
  */
  {
    const char *api = ndpi_llm_api_engine_route(flow, packet);

    if(api == NULL)
      api = ndpi_llm_api_family(flow, packet);

    if(api != NULL) {
      char info[NDPI_LLM_API_INFO_LEN];

      ndpi_llm_api_info(info, sizeof(info), NULL, api,
                        ndpi_llm_api_is_deepseek(packet));
      ndpi_int_vllm_add_risk(ndpi_struct, flow, info);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_vllm_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("vLLM", ndpi_struct,
                     ndpi_search_vllm,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_VLLM);
}
