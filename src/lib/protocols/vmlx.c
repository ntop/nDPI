/*
 * vmlx.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_VMLX

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * vMLX (https://github.com/jjang-ai/vmlx), an inference engine for Apple
 * Silicon that reads JANGQ (GGUF for MLX) model files.
 *
 * It is the most aggressive compatibility surface of the family: vmlx_engine
 * ships an Ollama adapter (api/ollama_adapter.py: /api/tags, /api/ps,
 * /api/version, /api/show, /api/pull, /api/create, /api/copy, /api/delete), an
 * Anthropic adapter (api/anthropic_adapter.py: /v1/messages) and the OpenAI
 * API. So an /api/tags flow is named Ollama and a /v1/messages flow is named by
 * the Anthropic rules: correct, because that is the API the request speaks; the
 * engine behind it is only provable from vMLX's own routes, taken from
 * vmlx_engine/server.py:
 *
 *   GET  /health.mtp                multi-token-prediction liveness
 *   GET  /v1/capabilities           what this server can serve
 *   GET/POST/DELETE /v1/cluster/...  node discovery and status
 *   GET  /v1/cache/entries          SSD cache contents
 *   POST /v1/cache/warm             pre-load the cache
 *   GET  /v1/mcp/servers, /v1/mcp/tools
 *   POST /admin/deep-sleep, /admin/soft-sleep, /admin/wake
 *
 * Not used: /v1/mcp/ (oMLX mounts the same prefix, omlx/api/mcp_routes.py),
 * /v1/cache/stats (mlx-vlm serves the same route) and /v1/audio/voices (oMLX
 * does) - all three name the family and are handled by vllm.c; /health,
 * /v1/models and /api/... (Ollama's names) are shared as well.
 *
 * No ports: the MLX family shares port defaults. See ollama.c.
 */

static const struct {
  const char *path;
  u_int8_t   prefix;     /* 1 = the real URL has a suffix after this path */
  u_int8_t   post_only;  /* 1 = the operation takes its input in the body */
  const char *info;
} vmlxRoutes[] = {
  { "/health.mtp",       0, 0, "vMLX management endpoint" },
  { "/v1/capabilities",  0, 0, "vMLX management endpoint" },
  { "/v1/cluster/",      1, 0, "vMLX cluster API" },
  { "/v1/cache/entries", 0, 0, "vMLX cache API" },
  { "/v1/cache/warm",    0, 1, "vMLX cache API" },
  { "/admin/deep-sleep", 0, 1, "vMLX admin API" },
  { "/admin/soft-sleep", 0, 1, "vMLX admin API" },
  { "/admin/wake",       0, 1, "vMLX admin API" },
  { NULL, 0, 0, NULL }
};

static void ndpi_int_vmlx_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow,
                                         char * const risk_info)
{

  /*
    vMLX is named by its own route; the request body adds the API dialect when
    it is provably a DeepSeek request (llm_api.c), which is how a DeepSeek model
    served by vMLX on a private hostname is reported.
  */
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  char info[NDPI_LLM_API_INFO_LEN];

  ndpi_llm_api_info(info, sizeof(info), risk_info, NULL,
                    ndpi_llm_api_is_deepseek(packet));
  NDPI_LOG_INFO(ndpi_struct, "found vMLX\n");

  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_VMLX,
                             NDPI_PROTOCOL_HTTP,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, info);
}

static void ndpi_search_vmlx(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  int i;

  NDPI_LOG_DBG(ndpi_struct, "search vMLX\n");

  if(flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
    if(flow->core.packet_counter > 8)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(packet->packet_direction != 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  for(i = 0; vmlxRoutes[i].path != NULL; i++) {
    int match;

    if(vmlxRoutes[i].post_only && flow->metadata.http.method != NDPI_HTTP_METHOD_POST)
      continue;

    match = vmlxRoutes[i].prefix ? LINE_STARTS(packet->http_url_name, vmlxRoutes[i].path)
                                 : LINE_EQUALS(packet->http_url_name, vmlxRoutes[i].path);
    if(match) {
      ndpi_int_vmlx_add_connection(ndpi_struct, flow, (char *)vmlxRoutes[i].info);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_vmlx_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("vMLX", ndpi_struct,
                     ndpi_search_vmlx,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_VMLX);
}
