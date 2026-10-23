/*
 * sglang.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SGLANG

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * SGLang Runtime (SRT), https://github.com/sgl-project/sglang.
 *
 * Endpoints taken from the documented SGLang Native API surface
 * (docs.sglang.io, "SGLang Native APIs") and from the FastAPI routes of
 * sglang/srt/entrypoints/http_server.py. Only routes that no other serving
 * engine exposes are used to name SGLang; everything SGLang shares with
 * another engine (OpenAI compatible /v1/..., /generate, /classify, /metrics,
 * /health, /encode) is left to vllm.c, which raises the AI inference risk
 * without naming a vendor. Same policy as ollama.c, vllm.c and llamacpp.c.
 *
 * Ports are deliberately not registered (see the long note in ollama.c):
 * SRT takes an arbitrary --port (30000 by default) and is routinely proxied
 * on 80/443/8080 by sglang-router, LiteLLM, nginx, ...
 */

/*
 * SGLang-specific routes. `inference` distinguishes the request surface that
 * carries prompts from the control/inspection surface, only to build the risk
 * info string; both are SGLang, so both set the protocol.
 *
 * Method is not checked: SRT declares most of these as GET/POST (the control
 * ones take their arguments in the query string or the body), and the names
 * are specific enough on their own.
 */
static const struct {
  const char *path;
  u_int8_t    inference;
} sglangRoutes[] = {
  /* Native inference (OpenAI compatible traffic is vllm.c's job) */
  { "/generate_from_file",           1 }, /* multipart upload, VLM input_embeds */
  { "/vertex_generate",              1 }, /* Vertex AI compatible route */
  /* Model / server introspection */
  { "/get_server_info",              0 },
  { "/get_model_info",               0 },
  { "/get_weight_version",           0 },
  { "/get_weights_by_name",          0 },
  { "/get_load",                     0 },
  { "/health_generate",              0 }, /* health check that runs a generate */
  /* Generation control */
  { "/abort_request",                0 },
  { "/pause_generation",             0 },
  { "/continue_generation",          0 },
  { "/flush_cache",                  0 }, /* radix KV cache flush */
  /* Sessions (SGLang session-aware radix cache) */
  { "/open_session",                 0 },
  { "/close_session",                0 },
  /* LoRA adapters */
  { "/load_lora_adapter",            0 },
  { "/unload_lora_adapter",          0 },
  /* Memory / weight management (RL weight sync) */
  { "/release_memory_occupation",    0 },
  { "/resume_memory_occupation",     0 },
  { "/update_weights_from_disk",     0 },
  { "/update_weights_from_tensor",   0 },
  { "/update_weights_from_distributed", 0 },
  { "/update_weight_version",        0 },
  { "/init_weights_update_group",    0 },
  /* Output post-processing helpers */
  { "/parse_function_call",          0 },
  { "/separate_reasoning",           0 },
  /* Misc */
  { "/configure_logging",            0 },
  { "/slow_down",                    0 }, /* testing route, shipped in the server */
  { NULL, 0 }
};

static void ndpi_int_sglang_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow,
                                           char * const risk_info)
{

  /*
    SGLang is named by its own route; the request body adds the API dialect when
    it is provably a DeepSeek request (llm_api.c), which is how a DeepSeek model
    served by SGLang on a private hostname is reported.
  */
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  char info[NDPI_LLM_API_INFO_LEN];

  ndpi_llm_api_info(info, sizeof(info), risk_info, NULL,
                    ndpi_llm_api_is_deepseek(packet));
  NDPI_LOG_INFO(ndpi_struct, "found SGLang\n");

  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_SGLANG,
                             NDPI_PROTOCOL_HTTP,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, info);
}

/*
  The native generate route is shared with TGI, so the URL alone is not enough.
  The SGLang request body is {"text": ..., "sampling_params": {...}} and
  "sampling_params" is SGLang's own field name (TGI posts "parameters", vLLM and
  every OpenAI compatible gateway post the OpenAI body), so it is the one
  discriminator that names SGLang without guessing. Exported for vllm.c, which
  has to skip the shared /generate rule on exactly this condition (the two
  dissectors see the same packet, the generic one must not name an engine that
  the specific one is about to prove).
  Limitation: the body must be in this packet; a prompt split across packets is
  left unattributed (risk only), which is the safe direction.
*/
int ndpi_is_sglang_native_generate(struct ndpi_packet_struct *packet) {
  return(packet->payload_packet_len >= 32 &&
         ndpi_strnstr((const char*)packet->payload, "\"sampling_params\"",
                      packet->payload_packet_len) != NULL);
}

static void ndpi_search_sglang(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  int i;

  NDPI_LOG_DBG(ndpi_struct, "search SGLang\n");

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
    The native generate endpoint is shared with TGI: see
    ndpi_is_sglang_native_generate() for what names the engine here. When the
    proof is not visible the flow is left to vllm.c, which flags it as native
    LLM generate without naming an engine.
  */
  if(flow->metadata.http.method == NDPI_HTTP_METHOD_POST &&
     LINE_EQUALS(packet->http_url_name, "/generate")) {
    if(ndpi_is_sglang_native_generate(packet)) {
      ndpi_int_sglang_add_connection(ndpi_struct, flow,
                                     (char *)"SGLang native generate API");
    }
    return;
  }

  for(i = 0; sglangRoutes[i].path != NULL; i++) {
    if(LINE_EQUALS(packet->http_url_name, sglangRoutes[i].path)) {
      ndpi_int_sglang_add_connection(ndpi_struct, flow,
                                     sglangRoutes[i].inference ?
                                     (char *)"SGLang native generate API" :
                                     (char *)"SGLang management endpoint");
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_sglang_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("SGLang", ndpi_struct,
                     ndpi_search_sglang,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_SGLANG);
}
