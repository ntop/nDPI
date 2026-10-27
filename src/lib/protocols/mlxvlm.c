/*
 * mlxvlm.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MLX_VLM

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * MLX-VLM (https://github.com/Blaizzy/mlx-vlm), a serving engine for
 * vision-language (and audio/reranking/decision) models on Apple Silicon.
 *
 * Like the rest of the MLX serving family (mlx_lm.server, oMLX, vMLX) it leads
 * with an OpenAI compatible API (/v1/chat/completions, /v1/completions,
 * /v1/models, /v1/embeddings) plus Anthropic's Messages API, so those flows are
 * attributed to the API, not to the engine: the request alone cannot tell the
 * family members apart. Only the routes MLX-VLM defines itself name it, taken
 * from mlx_vlm/server/app.py, mlx_vlm/server/decisions.py:
 *
 *   GET  /v1/images/defaults    the image defaults a request inherits
 *   GET  /v1/moe-offload/stats  MoE expert offload counters
 *   GET  /v1/settings           runtime settings
 *   GET  /v1/metrics            metrics under the /v1 spelling
 *   POST /unload                unload the loaded model
 *   POST /v1/cache/reset        drop the prefix cache
 *
 * Not used, because another engine serves the same name, so the route proves
 * the operation and not the engine: /v1/decisions (oMLX, omlx/server.py),
 * POST /unload (Strata, serve/server.py), /v1/cache/stats (also vMLX) and
 * /v1/audio/voices (also oMLX) - all four handled by vllm.c, naming the family.
 * /health, /v1/models, /metrics, /v1/messages, /v1/responses and the OpenAI
 * data plane are shared with every other engine.
 *
 * mlx_lm.server (https://github.com/ml-explore/mlx-lm), the reference MLX
 * server, is deliberately NOT here: its whole surface is /v1/completions,
 * /v1/chat/completions, /v1/models, /chat/completions and /health
 * (mlx_lm/server.py), i.e. nothing it defines itself. Its traffic is detected
 * as OpenAI compatible inference, and it cannot be named from the wire.
 *
 * No ports: the family shares port defaults (8000/8080), so a port rule would
 * attribute every MLX engine to whichever one owns the port. See ollama.c.
 */

static const struct {
  const char *path;
  u_int8_t   prefix;     /* 1 = the real URL has a suffix after this path */
  u_int8_t   post_only;  /* 1 = the operation takes its input in the body */
  const char *info;
} mlxvlmRoutes[] = {
  { "/v1/images/defaults",  0, 0, "MLX-VLM management endpoint" },
  { "/v1/moe-offload/stats",0, 0, "MLX-VLM management endpoint" },
  { "/v1/settings",         0, 0, "MLX-VLM management endpoint" },
  { "/v1/metrics",          0, 0, "MLX-VLM management endpoint" },
  { "/v1/cache/reset",      0, 1, "MLX-VLM management endpoint" },
  { NULL, 0, 0, NULL }
};

static void ndpi_int_mlxvlm_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow,
                                           char * const risk_info)
{

  /*
    MLX-VLM is named by its own route; the request body adds the API dialect when
    it is provably a DeepSeek request (llm_api.c), which is how a DeepSeek model
    served by MLX-VLM on a private hostname is reported.
  */
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  char info[NDPI_LLM_API_INFO_LEN];

  ndpi_llm_api_info(info, sizeof(info), risk_info, NULL,
                    ndpi_llm_api_is_deepseek(packet));
  NDPI_LOG_INFO(ndpi_struct, "found MLX-VLM\n");

  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_MLX_VLM,
                             NDPI_PROTOCOL_HTTP,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, info);
}

static void ndpi_search_mlxvlm(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  int i;

  NDPI_LOG_DBG(ndpi_struct, "search MLX-VLM\n");

  if(flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
    if(flow->core.packet_counter > 8)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(packet->packet_direction != 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  for(i = 0; mlxvlmRoutes[i].path != NULL; i++) {
    int match;

    if(mlxvlmRoutes[i].post_only && flow->metadata.http.method != NDPI_HTTP_METHOD_POST)
      continue;

    match = mlxvlmRoutes[i].prefix ? LINE_STARTS(packet->http_url_name, mlxvlmRoutes[i].path)
                                   : LINE_EQUALS(packet->http_url_name, mlxvlmRoutes[i].path);
    if(match) {
      ndpi_int_mlxvlm_add_connection(ndpi_struct, flow, (char *)mlxvlmRoutes[i].info);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_mlxvlm_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("MLX-VLM", ndpi_struct,
                     ndpi_search_mlxvlm,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_MLX_VLM);
}
