/*
 * llm_api.c
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

#include "ndpi_api.h"
#include "ndpi_private.h"

/*
 * The vendorless LLM API layer.
 *
 * This file answers, for one request, three questions that every LLM engine
 * dissector needs and that are not specific to any engine:
 *
 *   ndpi_llm_api_family()        which API family does this request speak
 *                                (OpenAI compatible, Anthropic Messages, the
 *                                media APIs, a tokenizer, model/metrics),
 *                                including the payload shape case where the
 *                                URL says nothing;
 *   ndpi_llm_api_engine_route()  does this route belong to an engine that has
 *                                no protocol id of its own (TGI, Triton/KServe,
 *                                LiteLLM, LocalAI, the MLX family, ...);
 *   ndpi_llm_api_is_deepseek()   is this a DeepSeek dialect request.
 *
 * It is not in vllm.c because none of it is vLLM specific: the same DeepSeek
 * request reaches SGLang, llama.cpp, Ollama, a gateway, or a server with no
 * routes of its own. Keeping one copy is also what makes the risk info string
 * say the same thing whichever engine caught the flow.
 *
 * Nothing here classifies a flow: these are pure per-packet predicates over the
 * request, and the callers (the dissectors) decide what to set. Cleartext
 * HTTP/1.1 only, as in every dissector that calls them: on TLS the body is not
 * visible.
 */

#define NDPI_LLM_DIALECT_DEEPSEEK ";DeepSeek API request"

/* Substring search in the request URL: gateways mount the API anywhere
   (https://gateway.example.com/team/model/v1/chat/completions, ...) */
int ndpi_llm_url_has(struct ndpi_packet_struct *packet, const char *needle)
{
  return((packet->http_url_name.ptr != NULL) &&
         (ndpi_strnstr((const char *)packet->http_url_name.ptr, needle,
                       packet->http_url_name.len) != NULL));
}

/*
  DeepSeek specific request fields, from the DeepSeek API request schema as
  implemented by deepseek-recipe (github.com/deepseek-ai/deepseek-recipe, main
  @ 935817c, 2026-10-20). They travel over an OpenAI or Anthropic compatible
  surface, so they identify the DeepSeek dialect on a self-hosted engine
  (DeepInfer, vLLM, SGLang, MLX, ...) whose hostname proves nothing.
  deepseek-recipe's own servers read no request header at all - no
  anthropic-version, no DeepSeek-* header - so the body is the only signal.
*/
int ndpi_llm_api_is_deepseek(struct ndpi_packet_struct *packet)
{
  const char *pay = (const char *)packet->payload;
  const size_t len = packet->payload_packet_len;

  if(len < 32)
    return(0);

  /* DeepSeek model ids on a self-hosted engine: "model":"deepseek-ai/DeepSeek-V4-Pro" */
  if(ndpi_strncasestr(pay, "\"model\":\"deepseek", len) != NULL ||
     ndpi_strncasestr(pay, "\"model\": \"deepseek", len) != NULL)
    return(1);

  /* DeepSeek-only vocabulary: a message role and a prompt token that exist
     nowhere else (special tokens use the fullwidth bar, U+FF5C = EF BD 9C) */
  if(ndpi_strnstr(pay, "latest_reminder", len) != NULL) return(1);
  if(ndpi_strnstr(pay, "\357\275\234", len) != NULL)   return(1);
  if(ndpi_strnstr(pay, "DSML", len) != NULL)            return(1);

  /* DeepSeek-only request fields */
  if(ndpi_strnstr(pay, "\"prefix\":true", len) != NULL)     return(1);
  if(ndpi_strnstr(pay, "\"output_config\"", len) != NULL)   return(1);
  if(ndpi_strnstr(pay, "\"defer_loading\"", len) != NULL)   return(1);
  if(ndpi_strnstr(pay, "\"tool_search\"", len) != NULL)     return(1);

  /* extensions of a shared field: only DeepSeek spells response_format regex,
     or reasoning_effort xhigh/ultra (OpenAI: json_object/json_schema, and
     minimal/low/medium/high) */
  if(ndpi_strnstr(pay, "response_format", len) != NULL &&
     ndpi_strnstr(pay, "\"regex\"", len) != NULL)
    return(1);
  if(ndpi_strnstr(pay, "reasoning_effort", len) != NULL &&
     (ndpi_strnstr(pay, "\"xhigh\"", len) != NULL ||
      ndpi_strnstr(pay, "\"ultra\"", len) != NULL))
    return(1);

  return(0);
}

/*
  Anthropic's Messages API. Its request is the same family as OpenAI's (a model
  plus a list of {role, content} messages), so it is identified by what the two
  families do NOT share:
    - the "anthropic-version" header, mandatory in the Anthropic API and sent by
      the official SDKs, by Claude Code and by every passthrough gateway;
    - a top level "system" field next to the mandatory "max_tokens" (OpenAI has
      no top level system field, it puts the system prompt inside "messages").
  Naming the API family is not naming a vendor: LiteLLM, Portkey, Helicone and
  several engines expose an Anthropic compatible /v1/messages of their own.
  The route alone proves nothing ("/messages" is an extremely common web-API
  name, see the json_api_not_ai test), so it is never matched by itself.
*/
static int llm_api_anthropic_header(struct ndpi_packet_struct *packet)
{
  int i;

  for(i = 0; i < packet->parsed_lines; i++) {
    if(packet->line[i].ptr == NULL || packet->line[i].len < 17)
      continue;
    if(ndpi_strncasestr((const char *)packet->line[i].ptr, "anthropic-version",
                        packet->line[i].len) != NULL)
      return(1);
  }

  return(0);
}

/*
  Endpoints that are specific to a given engine, and that raise the risk without
  naming a protocol. They are unambiguous, so they name the engine in the risk
  info; no protocol id is invented for them: a protocol per serving engine would
  be a catalogue of products, not a protocol (this is why the old generic
  NDPI_PROTOCOL_LLM was removed in 6.0). Engines with a large, unambiguous native
  surface get their own protocol and dissector, and are not listed here.
*/
static const struct {
  const char *path;
  u_int8_t   prefix;    /* 1 = the real URL has a suffix after this path */
  u_int8_t   post_only; /* 1 = the operation takes its input in the body */
  const char *engine;
} otherEngines[] = {
  /*
    Hugging Face Text Generation Inference.
    /generate and /classify are the native generate endpoint of TGI *and* of
    SGLang, so they name both: picking one of the two from the request alone
    would be a guess. /generate_stream, /generate_filter and /embed are TGI
    only (SGLang has no such routes), so they keep a single name.
    SGLang's own routes are matched by sglang.c, which can name it as a
    protocol; the entries below only raise the risk.
  */
  { "/generate",         0, 1, "native LLM generate (TGI/SGLang)" },
  { "/generate_stream",  0, 1, "TGI (text-generation-inference)" },
  { "/generate_filter",  0, 1, "TGI (text-generation-inference)" },
  { "/embed",            0, 1, "TGI (text-generation-inference)" },
  { "/classify",         0, 1, "native LLM classify (TGI/SGLang)" },
  /* Embedding models: SGLang native endpoint, also used by tokenizer servers */
  { "/encode",           0, 1, "LLM encode" },
  /* NVIDIA Triton Inference Server / KServe v2 data plane */
  { "/v2/models/",       1, 0, "Triton/KServe" },
  { "/v2/health",        1, 0, "Triton/KServe" },
  { "/v2/repository/",   1, 0, "Triton/KServe" },
  /* LiteLLM proxy (control plane; its data plane is plain /v1/...) */
  { "/key/generate",     0, 1, "LiteLLM proxy" },
  { "/key/info",         0, 1, "LiteLLM proxy" },
  { "/model/new",        0, 1, "LiteLLM proxy" },
  { "/model/info",       0, 0, "LiteLLM proxy" },
  { "/user/new",         0, 1, "LiteLLM proxy" },
  { "/team/new",         0, 1, "LiteLLM proxy" },
  { "/config/litellm",   0, 0, "LiteLLM proxy" },
  { "/health/liveliness",0, 0, "LiteLLM proxy" },
  { "/spend/logs",       0, 0, "LiteLLM proxy" },
  /* LocalAI */
  { "/readyz",           0, 0, "LocalAI" },
  { "/wake",             0, 1, "LocalAI" },
  { "/shutdown",         0, 1, "LocalAI" },
  /*
    Decision models (LiquidAI d1 and kin): Radiance (docs/GUIDE.md 5.13) and
    oMLX (omlx/api/systemone_models.py) both serve this exact route, so it names
    the operation and both engines, and never a single one of them.
  */
  { "/v1/systemone",     0, 1, "SystemOne decisions API (Radiance/oMLX)" },
  /*
    Routes two of the MLX engines serve with the same name: mlx-vlm
    (mlx_vlm/server/app.py) and vMLX (vmlx_engine/server.py) both expose
    /v1/cache/stats, oMLX (omlx/api/audio_routes.py) and vMLX both expose
    /v1/audio/voices. They name the family, never one engine.
  */
  { "/v1/cache/stats",   0, 0, "MLX serving engine cache stats (mlx-vlm/vMLX)" },
  { "/v1/audio/voices",  0, 0, "MLX serving engine voices (oMLX/vMLX)" },
  { "/v1/decisions",     0, 1, "Decisions API (mlx-vlm/oMLX)" },
  { "/unload",           0, 1, "Model unload control (mlx-vlm/Strata)" },
  { "/v1/mcp/",          1, 0, "MCP control API (oMLX/vMLX)" },
  { NULL, 0, 0, NULL }
};

const char *ndpi_llm_api_engine_route(struct ndpi_flow_struct *flow,
                                      struct ndpi_packet_struct *packet)
{
  static char info[NDPI_LLM_API_INFO_LEN];
  int i;

  for(i = 0; otherEngines[i].path != NULL; i++) {
    int match;

    if(otherEngines[i].post_only &&
       flow->metadata.http.method != NDPI_HTTP_METHOD_POST)
      continue;

    match = otherEngines[i].prefix ?
      ndpi_llm_url_has(packet, otherEngines[i].path) :
      LINE_EQUALS(packet->http_url_name, otherEngines[i].path);

    if(match) {
      /*
        SGLang proves itself on the shared /generate route (see sglang.c):
        both are invoked on this packet, and the engine must be named once, by
        the code that has the proof.
      */
      if(LINE_EQUALS(packet->http_url_name, "/generate") &&
         ndpi_is_sglang_native_generate(packet))
        return(NULL);

      snprintf(info, sizeof(info), "%s endpoint", otherEngines[i].engine);
      return(info);
    }
  }

  return(NULL);
}

/*
  OpenAI compatible inference operations, matched at any path depth (gateways
  mount the API under their own prefix). Only unambiguous names are listed:
  "/messages" or "/score" appear in plenty of non-AI web APIs, and those cases
  are left to the payload shape below, which is the reliable signal. The media
  names (images, audio) are OpenAI's own API surface, i.e. generative inference
  of a non-text modality, served by the same engines (vLLM-Omni, Radiance, ...);
  "/v1/videos" is deliberately absent, since a plain video service would expose
  exactly that route.
*/
static const char *inferenceOps[] = {
  "/chat/completions", "/completions", "/embeddings", "/generate_content",
  "/rerank", "/converse", "/inference", "/v1/responses",
  "/images/generations", "/images/edits", "/audio/speech", "/audio/transcriptions",
  /* prompt token counting: Radiance spells it /v1/chat/completions/input_tokens,
     ninfer and MLX-VLM /v1/responses/input_tokens - the suffix is the signal */
  "/input_tokens",
  NULL
};

const char *ndpi_llm_api_family(struct ndpi_flow_struct *flow,
                                struct ndpi_packet_struct *packet)
{
  int i;

  /*
    Inference is POST-only (the prompt is in the body), which keeps GET probes,
    crawlers and health checks out.
  */
  if(flow->metadata.http.method == NDPI_HTTP_METHOD_POST) {
    /*
      Anthropic proves itself with its mandatory version header, whatever the
      URL is: gateways mount the API under their own prefix. A server built on
      deepseek-recipe accepts /v1/messages without any header at all, which is
      why the payload shape below also identifies the Messages format.
    */
    if(llm_api_anthropic_header(packet))
      return("Anthropic Messages API (anthropic-version header)");

    for(i = 0; inferenceOps[i] != NULL; i++) {
      if(ndpi_llm_url_has(packet, inferenceOps[i]))
        return("OpenAI compatible inference API");
    }

    /*
      Payload shape: the prompt travels as
        {"model":"...","messages":[{"role":"...","content":"..."}],...}
      (chat), {"model":"...","prompt":"..."} (completions) or
      {"model":"...","input":...} (responses/embeddings). This is the signal
      that survives a gateway with an opaque URL.
    */
    if(packet->payload_packet_len >= 48 &&
       packet->content_line.ptr != NULL &&
       ndpi_strnstr((const char *)packet->content_line.ptr, "json",
                    packet->content_line.len) != NULL) {
      const char *pay = (const char *)packet->payload;
      const size_t len = packet->payload_packet_len;
      int messages = (ndpi_strnstr(pay, "\"messages\"", len) != NULL);
      int role     = (ndpi_strnstr(pay, "\"role\"", len) != NULL);
      int content  = (ndpi_strnstr(pay, "\"content\"", len) != NULL);
      int model    = (ndpi_strnstr(pay, "\"model\"", len) != NULL);
      int prompt   = (ndpi_strnstr(pay, "\"prompt\"", len) != NULL);
      int input    = (ndpi_strnstr(pay, "\"input\"", len) != NULL);
      int max_tok  = (ndpi_strnstr(pay, "\"max_tokens\"", len) != NULL);
      int sys_field= (ndpi_strnstr(pay, "\"system\"", len) != NULL);

      if(messages && role && content) {
        /*
          OpenAI and Anthropic share the message list; the Anthropic request
          adds the mandatory max_tokens and a top level system prompt.
        */
        return((max_tok && sys_field) ?
               "Anthropic compatible message format" :
               "OpenAI compatible message format");
      }

      if((model && (messages || prompt || input)) ||
         (prompt && (max_tok ||
                     ndpi_strnstr(pay, "\"temperature\"", len) != NULL ||
                     ndpi_strnstr(pay, "\"stop\"", len) != NULL)))
        return("LLM completion request payload");
    }

    /* Tokeniser: the text travels in the request body, so POST */
    if(LINE_EQUALS(packet->http_url_name, "/tokenize") ||
       LINE_EQUALS(packet->http_url_name, "/detokenize"))
      return("LLM tokenizer endpoint");
  }

  /* Read-only (GET) endpoints shared by every engine: model listing and the
     Prometheus metrics. GET /generate... (connectivity probes) is NOT one of
     them, the inference endpoints above are POST-only for the same reason. */
  if(flow->metadata.http.method == NDPI_HTTP_METHOD_GET &&
     (LINE_EQUALS(packet->http_url_name, "/metrics") ||
      LINE_STARTS(packet->http_url_name, "/v1/models")))
    return("LLM model/metrics endpoint");

  return(NULL);
}

/*
  Build a risk info string: "<label>[;<api family>][;DeepSeek API request]".
  A dissector that names the engine from its own route passes the label only -
  it already knows which API that route speaks - while the generic layer passes
  the family and no label.
*/
void ndpi_llm_api_info(char *out, size_t out_len,
                       const char *label, const char *family, int deepseek)
{
  size_t n = 0;
  int rc;

  if(out_len == 0)
    return;

  out[0] = '\0';

  if(label) {
    rc = snprintf(out, out_len, "%s", label);
    if(rc < 0) return;
    n = ((size_t)rc < out_len - 1) ? (size_t)rc : out_len - 1;
  }

  if(family && n < out_len - 1) {
    rc = snprintf(&out[n], out_len - n, "%s%s", n ? ";" : "", family);
    if(rc < 0) return;
    n += ((size_t)rc < out_len - 1 - n) ? (size_t)rc : out_len - 1 - n;
  }

  if(deepseek && n < out_len - 1)
    snprintf(&out[n], out_len - n, "%s", NDPI_LLM_DIALECT_DEEPSEEK);
}
