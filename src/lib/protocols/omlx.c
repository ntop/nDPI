/*
 * omlx.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_OMLX

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * oMLX (https://github.com/jundot/omlx), an OpenAI compatible inference server
 * for Apple Silicon with continuous batching and SSD caching.
 *
 * Its data plane is entirely borrowed: /v1/chat/completions, /v1/completions,
 * /v1/embeddings, /v1/messages (Anthropic Messages), /v1/rerank, /v1/systemone,
 * /tokenize and /detokenize (vLLM's names, so those flows are named vLLM), and
 * the media APIs. All of that is detected, and none of it names oMLX.
 *
 * What names oMLX is its own surface, taken from omlx/api/audio_routes.py and
 * omlx/admin/routes.py:
 *
 *   POST /v1/audio/process            audio preprocessing
 *   GET  /api/activity                live engine activity
 *   GET/POST /api/bench/...           accuracy / context / ANE tuning benchmarks
 *   GET/POST /api/oq/...              oq quantization tasks
 *   GET/DELETE /api/profile-templates/...
 *   GET/DELETE /api/sub-keys          sub-key management
 *   GET/DELETE /api/hf/task/...       Hugging Face download tasks
 *   GET/DELETE /api/ms/task/...       ModelScope download tasks
 *   GET/DELETE /api/upload/task/...   upload tasks
 *
 * Not used: /v1/decisions, which MLX-VLM serves under the same name
 * (mlx_vlm/server/decisions.py); /v1/audio/voices, also served by vMLX;
 * /v1/systemone, shared with Radiance; /api/status and /api/models, names every
 * admin UI on earth uses; /mcp/... operation names.
 *
 * No ports: the MLX family shares port defaults. See ollama.c.
 */

static const struct {
  const char *path;
  u_int8_t   prefix;     /* 1 = the real URL has a suffix after this path */
  const char *info;
} omlxRoutes[] = {
  { "/v1/audio/process",      0, "oMLX audio API" },
  { "/v1/web/search",         0, "oMLX web tools API" },
  { "/v1/web/fetch",          0, "oMLX web tools API" },
  { "/v1/models/status",      0, "oMLX management endpoint" },
  { "/api/activity",          0, "oMLX admin API" },
  { "/api/bench/",            1, "oMLX admin API" },
  { "/api/oq/",               1, "oMLX admin API" },
  { "/api/profile-templates/",1, "oMLX admin API" },
  { "/api/sub-keys",          0, "oMLX admin API" },
  { "/api/hf/task/",          1, "oMLX admin API" },
  { "/api/ms/task/",          1, "oMLX admin API" },
  { "/api/upload/task/",      1, "oMLX admin API" },
  { NULL, 0, NULL }
};

static void ndpi_int_omlx_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow,
                                         char * const risk_info)
{

  /*
    oMLX is named by its own route; the request body adds the API dialect when
    it is provably a DeepSeek request (llm_api.c), which is how a DeepSeek model
    served by oMLX on a private hostname is reported.
  */
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  char info[NDPI_LLM_API_INFO_LEN];

  ndpi_llm_api_info(info, sizeof(info), risk_info, NULL,
                    ndpi_llm_api_is_deepseek(packet));
  NDPI_LOG_INFO(ndpi_struct, "found oMLX\n");

  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_OMLX,
                             NDPI_PROTOCOL_HTTP,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, info);
}

static void ndpi_search_omlx(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  int i;

  NDPI_LOG_DBG(ndpi_struct, "search oMLX\n");

  if(flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
    if(flow->core.packet_counter > 8)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(packet->packet_direction != 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  for(i = 0; omlxRoutes[i].path != NULL; i++) {
    int match = omlxRoutes[i].prefix ? LINE_STARTS(packet->http_url_name, omlxRoutes[i].path)
                                     : LINE_EQUALS(packet->http_url_name, omlxRoutes[i].path);
    if(match) {
      ndpi_int_omlx_add_connection(ndpi_struct, flow, (char *)omlxRoutes[i].info);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_omlx_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("oMLX", ndpi_struct,
                     ndpi_search_omlx,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_OMLX);
}
