/*
 * ndpi_ai.h -- AI endpoint identification (segregated namespace) for nDPI.
 *
 * This header defines the AI *endpoint* identity: which AI system a flow is
 * talking to. It is deliberately kept OUT of ndpi_protocol_ids.h so that the
 * core protocol schema grows by exactly one marker (NDPI_PROTOCOL_AI) instead
 * of one number per provider/engine.
 *
 * A flow that is AI traffic is classified as NDPI_PROTOCOL_AI (category
 * ARTIFICIAL_INTELLIGENCE) and carries a single attribute, flow->ai_endpoint,
 * whose value is one of the ndpi_ai_endpoint identifiers below. The value
 * itself names the endpoint; the provider/engine split is a grouping of the
 * values (see the *_MIN / *_MAX bounds) so a consumer can derive
 * hosted-vs-self-hosted without a second field.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __NDPI_AI_H__
#define __NDPI_AI_H__

#include "ndpi_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Value layout (disjoint ranges so the categories grow independently and never
 * renumber each other):
 *
 *   0            NDPI_AI_ENDPOINT_NONE -- sentinel: no AI endpoint detected
 *   1-999        generic API-format markers (compatible dialects) -- pinned low
 *   1000-5499    hosted providers (identified by peer name: SNI / DNS / cert)
 *   5500-9999    self-hosted inference engines (identified by wire signature)
 *
 * Adding a hosted provider or a self-hosted engine means taking the next free
 * slot in its own range; it never touches the other two. The wide gaps are the
 * firewall between categories. The value is a u_int16_t (fits 9999).
 */
typedef enum _ndpi_ai_endpoint {
  NDPI_AI_ENDPOINT_NONE = 0,

  /* ---- generic API-format markers (provider unknown). The traffic speaks the
     * OpenAI / Anthropic wire dialect, but no specific provider/engine is proven
     * by the name; identified from the HTTP path/body in a later chunk. Pinned at
     * the low end (1-999) so they never shift as providers/engines are appended. ---- */
  NDPI_AI_ENDPOINT_OPENAI_COMPATIBLE     = 1,
  NDPI_AI_ENDPOINT_ANTHROPIC_COMPATIBLE  = 2,
  NDPI_AI_ENDPOINT_COMPATIBLE_MIN        = 1,
  NDPI_AI_ENDPOINT_COMPATIBLE_MAX        = 999,

  /* ---- hosted providers (identified by peer name: SNI / DNS / certificate) ---- */
  NDPI_AI_ENDPOINT_OPENAI         = 1000,
  NDPI_AI_ENDPOINT_ANTHROPIC      = 1001,
  NDPI_AI_ENDPOINT_GOOGLE_GEMINI  = 1002,
  NDPI_AI_ENDPOINT_DEEPSEEK       = 1003,
  NDPI_AI_ENDPOINT_MISTRAL        = 1004,
  NDPI_AI_ENDPOINT_XAI            = 1005,
  NDPI_AI_ENDPOINT_COHERE         = 1006,
  NDPI_AI_ENDPOINT_GROQ           = 1007,
  NDPI_AI_ENDPOINT_HUGGINGFACE    = 1008,
  NDPI_AI_ENDPOINT_PERPLEXITY     = 1009,
  NDPI_AI_ENDPOINT_Z_AI           = 1010,
  NDPI_AI_ENDPOINT_ALIBABA_QWEN   = 1011,
  NDPI_AI_ENDPOINT_MINIMAX        = 1012,
  NDPI_AI_ENDPOINT_MOONSHOT       = 1013,
  NDPI_AI_ENDPOINT_VOLCENGINE_ARK = 1014,
  NDPI_AI_ENDPOINT_SILICONFLOW    = 1015,
  NDPI_AI_ENDPOINT_BAIDU_QIANFAN  = 1016,
  NDPI_AI_ENDPOINT_TENCENT_HUNYUAN= 1017,
  NDPI_AI_ENDPOINT_IFLYTEK_SPARK  = 1018,
  NDPI_AI_ENDPOINT_STEPFUN        = 1019,
  NDPI_AI_ENDPOINT_ZERO_ONE_AI    = 1020,
  NDPI_AI_ENDPOINT_PROVIDER_MIN   = 1000,
  NDPI_AI_ENDPOINT_PROVIDER_MAX   = 5499,

  /* ---- specific self-hosted inference engines (identified by wire signature) ---- */
  NDPI_AI_ENDPOINT_VLLM           = 5500,
  NDPI_AI_ENDPOINT_LLAMA_CPP      = 5501,
  NDPI_AI_ENDPOINT_OLLAMA         = 5502,
  NDPI_AI_ENDPOINT_SGLANG         = 5503,
  NDPI_AI_ENDPOINT_RADIANCE       = 5504,
  NDPI_AI_ENDPOINT_MLX_VLM        = 5505,
  NDPI_AI_ENDPOINT_OMLX           = 5506,
  NDPI_AI_ENDPOINT_VMLX           = 5507,
  NDPI_AI_ENDPOINT_STRATA         = 5508,
  NDPI_AI_ENDPOINT_ENGINE_MIN     = 5500,
  NDPI_AI_ENDPOINT_ENGINE_MAX     = 9999,

  NDPI_AI_ENDPOINT_MAX            = 9999
} ndpi_ai_endpoint;

/* The value space is three disjoint ranges (see the layout note above); NONE (0)
 * is the only invalid value, so validity is a 3-way range check. */
static inline int ndpi_ai_endpoint_is_valid(u_int16_t e) {
  return((e >= NDPI_AI_ENDPOINT_COMPATIBLE_MIN && e <= NDPI_AI_ENDPOINT_COMPATIBLE_MAX)
      || (e >= NDPI_AI_ENDPOINT_PROVIDER_MIN   && e <= NDPI_AI_ENDPOINT_PROVIDER_MAX)
      || (e >= NDPI_AI_ENDPOINT_ENGINE_MIN     && e <= NDPI_AI_ENDPOINT_ENGINE_MAX));
}
static inline int ndpi_ai_endpoint_is_provider(u_int16_t e)   { return(e >= NDPI_AI_ENDPOINT_PROVIDER_MIN && e <= NDPI_AI_ENDPOINT_PROVIDER_MAX); }
static inline int ndpi_ai_endpoint_is_compatible(u_int16_t e) { return(e >= NDPI_AI_ENDPOINT_COMPATIBLE_MIN && e <= NDPI_AI_ENDPOINT_COMPATIBLE_MAX); }
static inline int ndpi_ai_endpoint_is_engine(u_int16_t e)     { return(e >= NDPI_AI_ENDPOINT_ENGINE_MIN   && e <= NDPI_AI_ENDPOINT_ENGINE_MAX); }

/* Human-readable name for an endpoint id ("" for NONE / unknown). */
const char *ndpi_get_ai_endpoint_name(u_int16_t ai_endpoint);

/* Resolve a hostname/SNI to its ndpi_ai_endpoint (NDPI_AI_ENDPOINT_NONE if not an AI endpoint). */
u_int16_t ndpi_get_ai_endpoint_by_name(struct ndpi_detection_module_struct *ndpi_struct, const char *name, size_t name_len);

/* Run the SNI/Host automaton against `what`; returns the matched endpoint or NONE. */
u_int16_t ndpi_ai_check_hostname(struct ndpi_detection_module_struct *ndpi_struct, char *what, u_int what_len);

/* Module lifecycle: build the SNI/Host automaton. Called once from the core init,
 * after the other automata are finalized. */
void ndpi_ai_init(struct ndpi_detection_module_struct *ndpi_struct);

/* Module lifecycle: release the SNI/Host automaton. */
void ndpi_ai_cleanup(struct ndpi_detection_module_struct *ndpi_struct);

#ifdef __cplusplus
}
#endif

#endif /* __NDPI_AI_H__ */
