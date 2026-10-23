/*
 * radiance.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RADIANCE

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * Radiance (https://codeberg.org/StillDeadcode/radiance), a modular inference
 * server for AMD GPUs, written in C++/HIP.
 *
 * Radiance is the case that proves the "one engine, many APIs" rule: it
 * implements OpenAI's chat/completions/responses/images/audio/video APIs,
 * Anthropic's Messages API, llama-server's native API (/completion, /props,
 * /server_info, /apply-template, /infill) and vLLM's control API (/load,
 * /version, /tokenize, /detokenize, /reset_prefix_cache) - on one port. A flow
 * on any of those routes is therefore correctly attributed to the API it
 * speaks (OpenAI/Anthropic compatible risk, LlamaCpp, vLLM), and NOT to
 * Radiance: the request alone cannot tell Radiance from the engine that
 * originally defined the route.
 *
 * Only Radiance's own routes, taken from docs/GUIDE.md section 5.1, name it:
 *
 *   GET  /v1/loras                        adapters a request may name
 *   POST /v1/load_lora_adapter            (llama.cpp spells this without /v1,
 *   POST /v1/unload_lora_adapter           SGLang has /load_lora_adapter only)
 *   GET  /v1/health                       liveness, /v1 spelling
 *   GET  /get_tokenizer_info              tokenizer configuration
 *
 * Deliberately not used, because the names are not Radiance's: /, /dashboard,
 * /stats, /graph, /sessions, /diagnostics (generic web/serving names), /ping
 * (vLLM/SageMaker), POST /v1/systemone (oMLX implements the same LiquidAI d1
 * decisions route, omlx/api/systemone_models.py, so it names the operation and
 * not an engine), POST /v1/responses/input_tokens (ninfer, src/serve/http_server.cpp,
 * and MLX-VLM serve it too), and every route listed above as belonging to
 * another API.
 *
 * No ports: --port is free (8000 by default, the same default as vLLM, so a
 * port rule would attribute Radiance to vLLM and vice versa). See ollama.c.
 */

static void ndpi_int_radiance_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                             struct ndpi_flow_struct * const flow,
                                             char * const risk_info)
{

  /*
    Radiance is named by its own route; the request body adds the API dialect when
    it is provably a DeepSeek request (llm_api.c), which is how a DeepSeek model
    served by Radiance on a private hostname is reported.
  */
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  char info[NDPI_LLM_API_INFO_LEN];

  ndpi_llm_api_info(info, sizeof(info), risk_info, NULL,
                    ndpi_llm_api_is_deepseek(packet));
  NDPI_LOG_INFO(ndpi_struct, "found Radiance\n");

  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_RADIANCE,
                             NDPI_PROTOCOL_HTTP,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, info);
}

static void ndpi_search_radiance(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Radiance\n");

  if(flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
    if(flow->core.packet_counter > 8)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(packet->packet_direction != 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(LINE_EQUALS(packet->http_url_name, "/v1/loras")             ||
     LINE_EQUALS(packet->http_url_name, "/v1/load_lora_adapter") ||
     LINE_EQUALS(packet->http_url_name, "/v1/unload_lora_adapter") ||
     LINE_EQUALS(packet->http_url_name, "/v1/health")            ||
     LINE_EQUALS(packet->http_url_name, "/get_tokenizer_info")) {
    ndpi_int_radiance_add_connection(ndpi_struct, flow, (char *)"Radiance management endpoint");
    return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_radiance_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Radiance", ndpi_struct,
                     ndpi_search_radiance,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_RADIANCE);
}
