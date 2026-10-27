/*
 * strata.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_STRATA

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * Strata (https://github.com/Niko1221/Strata), an inference engine for consumer
 * hardware (C++ core, Python http.server control plane).
 *
 * Its signature is three API families on one port: OpenAI (/v1/chat/completions,
 * /v1/completions, /v1/responses, /v1/images/generations), Anthropic's Messages
 * API (/v1/messages, /v1/messages/count_tokens) and llama-server's native one
 * (/props, /slots). The OpenAI and Anthropic flows are named by the API rules;
 * the /props and /slots flows are named LlamaCpp, correctly: that is the API
 * the request speaks, and no route of Strata's can be assumed for a flow that
 * does not carry it.
 *
 * Strata's own routes, all from serve/server.py, name it:
 *
 *   GET  /v1/status                     self describing; answers with the
 *                                       "dialects" it serves (server.py:6494)
 *   GET  /v1/telemetry                  read only telemetry (:6218)
 *   GET  /metrics/prometheus            Prometheus exposition (:6194)
 *   POST /v1/vram                       elastic VRAM reservation (:6597)
 *   POST /v1/load, POST /v1/unload      model control, /v1 spelling (:6571)
 *   GET  /v1/images/files/...           generated image download (:6427)
 *   GET  /api-monitor                   live request monitor page (:6415)
 *   POST /v1/v1/messages[/count_tokens] base URL alias, /v1/v1/ spelling (:268)
 *
 * Not used: /health, /metrics, /v1/models, /models (every engine has them),
 * /props and /slots (llama.cpp's names), /status (llama.cpp added it too),
 * /settings, /config, /mcp, /api/health, /api/requests (generic web names),
 * and bare POST /unload, which MLX-VLM also serves (named by vllm.c).
 *
 * No ports: --port defaults to 8095 while the project's own docs run it on
 * 8080, the default of vLLM, mlx_lm.server, vMLX and ninfer. A port rule would
 * attribute Strata to all four. See ollama.c.
 */

static const struct {
  const char *path;
  u_int8_t   prefix;     /* 1 = the real URL has a suffix after this path */
  u_int8_t   post_only;  /* 1 = the operation takes its input in the body */
  const char *info;
} strataRoutes[] = {
  { "/v1/status",          0, 0, "Strata status endpoint" },
  { "/v1/telemetry",       0, 0, "Strata telemetry endpoint" },
  { "/metrics/prometheus", 0, 0, "Strata management endpoint" },
  { "/v1/vram",            0, 1, "Strata VRAM control" },
  { "/v1/load",            0, 1, "Strata model control" },
  { "/v1/unload",          0, 1, "Strata model control" },
  { "/v1/images/files/",   1, 0, "Strata generated image download" },
  { "/api-monitor",        0, 0, "Strata request monitor" },
  { "/v1/v1/messages",     0, 1, "Strata Messages API alias" },
  { NULL, 0, 0, NULL }
};

static void ndpi_int_strata_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow,
                                           char * const risk_info)
{

  /*
    Strata is named by its own route; the request body adds the API dialect when
    it is provably a DeepSeek request (llm_api.c), which is how a DeepSeek model
    served by Strata on a private hostname is reported.
  */
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  char info[NDPI_LLM_API_INFO_LEN];

  ndpi_llm_api_info(info, sizeof(info), risk_info, NULL,
                    ndpi_llm_api_is_deepseek(packet));
  NDPI_LOG_INFO(ndpi_struct, "found Strata\n");

  ndpi_set_detected_protocol(ndpi_struct, &flow->core,
                             NDPI_PROTOCOL_STRATA,
                             NDPI_PROTOCOL_HTTP,
                             NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, &flow->core, NDPI_AI_INFERENCE_TRAFFIC, info);
}

static void ndpi_search_strata(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  int i;

  NDPI_LOG_DBG(ndpi_struct, "search Strata\n");

  if(flow->core.detected_protocol_stack[0] != NDPI_PROTOCOL_HTTP) {
    if(flow->core.packet_counter > 8)
      NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(packet->packet_direction != 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  for(i = 0; strataRoutes[i].path != NULL; i++) {
    int match;

    if(strataRoutes[i].post_only && flow->metadata.http.method != NDPI_HTTP_METHOD_POST)
      continue;

    match = strataRoutes[i].prefix ? LINE_STARTS(packet->http_url_name, strataRoutes[i].path)
                                   : LINE_EQUALS(packet->http_url_name, strataRoutes[i].path);
    if(match) {
      ndpi_int_strata_add_connection(ndpi_struct, flow, (char *)strataRoutes[i].info);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_strata_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Strata", ndpi_struct,
                     ndpi_search_strata,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_STRATA);
}
