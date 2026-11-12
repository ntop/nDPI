/*
 * ndpi_ai.c -- AI endpoint identification (segregated module, see ndpi_ai.h).
 *
 * This file is self-contained: the domain->endpoint data, the name lookup, the
 * SNI/Host check, and the automaton lifecycle all live here. The rest of the
 * detection core only calls the public API declared in ndpi_ai.h from thin hook
 * points, so this module is independent of the core. The state (the automaton)
 * lives in the detection module struct; this file manages it.
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

#include "ndpi_protocol_ids.h"
#include "ndpi_api.h"
#include "ndpi_private.h"
#include "ndpi_ai.h"
#include "ahocorasick.h"

/* The core's shared domain-match handler (defined in ndpi_main.c). */
extern int ac_domain_match_handler(AC_MATCH_t *m, AC_TEXT_t *txt, AC_REP_t *match);

/* --------------------------------------------------------------- *
 *  domain -> endpoint data (the single place the provider list lives)
 * --------------------------------------------------------------- */
typedef struct {
  const char *domain;
  u_int16_t   ai_endpoint;
} ndpi_ai_endpoint_match_t;

static ndpi_ai_endpoint_match_t ai_endpoint_match[] = {
  /* OpenAI */
  { "openai.com",                      NDPI_AI_ENDPOINT_OPENAI },
  { "chatgpt.com",                     NDPI_AI_ENDPOINT_OPENAI },
  { "oaistatic.com",                   NDPI_AI_ENDPOINT_OPENAI },
  { "oaiusercontent.com",              NDPI_AI_ENDPOINT_OPENAI },
  /* Anthropic */
  { "anthropic.com",                   NDPI_AI_ENDPOINT_ANTHROPIC },
  { "claude.ai",                       NDPI_AI_ENDPOINT_ANTHROPIC },
  { "claude.app",                      NDPI_AI_ENDPOINT_ANTHROPIC },
  { "claudeusercontent.com",           NDPI_AI_ENDPOINT_ANTHROPIC },
  /* Google Gemini */
  { "gemini.google.com",               NDPI_AI_ENDPOINT_GOOGLE_GEMINI },
  { "aistudio.google.com",             NDPI_AI_ENDPOINT_GOOGLE_GEMINI },
  { "notebooklm.google.com",           NDPI_AI_ENDPOINT_GOOGLE_GEMINI },
  { "generativelanguage.googleapis.com", NDPI_AI_ENDPOINT_GOOGLE_GEMINI },
  /* DeepSeek (web front-end + APM telemetry served from BytePlus/Volcengine) */
  { "deepseek.com",                    NDPI_AI_ENDPOINT_DEEPSEEK },
  { "gator.volces.com",                NDPI_AI_ENDPOINT_DEEPSEEK },
  { "apmplus.volces.com",              NDPI_AI_ENDPOINT_DEEPSEEK },
  /* Mistral */
  { "mistral.ai",                      NDPI_AI_ENDPOINT_MISTRAL },
  /* xAI */
  { "grok.com",                        NDPI_AI_ENDPOINT_XAI },
  { "grokipedia.com",                  NDPI_AI_ENDPOINT_XAI },
  /* Cohere */
  { "cohere.com",                      NDPI_AI_ENDPOINT_COHERE },
  { "cohere.ai",                       NDPI_AI_ENDPOINT_COHERE },
  /* Groq */
  { "groq.com",                        NDPI_AI_ENDPOINT_GROQ },
  /* Hugging Face */
  { "huggingface.co",                  NDPI_AI_ENDPOINT_HUGGINGFACE },
  { "huggingface.com",                 NDPI_AI_ENDPOINT_HUGGINGFACE },
  { "hf.co",                           NDPI_AI_ENDPOINT_HUGGINGFACE },
  /* Perplexity */
  { "perplexity.ai",                   NDPI_AI_ENDPOINT_PERPLEXITY },
  /* Z.ai */
  { "api.z.ai",                        NDPI_AI_ENDPOINT_Z_AI },
  { "bigmodel.cn",                     NDPI_AI_ENDPOINT_Z_AI },
  { "zhipu.ai",                        NDPI_AI_ENDPOINT_Z_AI },
  { "chatglm.cn",                      NDPI_AI_ENDPOINT_Z_AI },
  /* Alibaba Qwen */
  { "dashscope.aliyuncs.com",          NDPI_AI_ENDPOINT_ALIBABA_QWEN },
  { "dashscope-intl.aliyuncs.com",     NDPI_AI_ENDPOINT_ALIBABA_QWEN },
  { "chat.qwen.ai",                    NDPI_AI_ENDPOINT_ALIBABA_QWEN },
  /* MiniMax */
  { "minimaxi.com",                    NDPI_AI_ENDPOINT_MINIMAX },
  { "minimax.io",                      NDPI_AI_ENDPOINT_MINIMAX },
  { "minimax.chat",                    NDPI_AI_ENDPOINT_MINIMAX },
  /* Moonshot */
  { "moonshot.cn",                     NDPI_AI_ENDPOINT_MOONSHOT },
  { "moonshot.ai",                     NDPI_AI_ENDPOINT_MOONSHOT },
  { "kimi.com",                        NDPI_AI_ENDPOINT_MOONSHOT },
  /* Volcengine Ark */
  { "ark.cn-beijing.volces.com",       NDPI_AI_ENDPOINT_VOLCENGINE_ARK },
  { "ark.ap-southeast.volces.com",     NDPI_AI_ENDPOINT_VOLCENGINE_ARK },
  { "ark.cn-shanghai.volces.com",      NDPI_AI_ENDPOINT_VOLCENGINE_ARK },
  /* SiliconFlow */
  { "siliconflow.cn",                  NDPI_AI_ENDPOINT_SILICONFLOW },
  { "siliconflow.com",                 NDPI_AI_ENDPOINT_SILICONFLOW },
  /* Baidu Qianfan */
  { "qianfan.baidubce.com",            NDPI_AI_ENDPOINT_BAIDU_QIANFAN },
  { "qianfan.baidu.com",               NDPI_AI_ENDPOINT_BAIDU_QIANFAN },
  /* Tencent Hunyuan */
  { "hunyuan.tencentcloudapi.com",     NDPI_AI_ENDPOINT_TENCENT_HUNYUAN },
  { "hunyuan.tencent.com",             NDPI_AI_ENDPOINT_TENCENT_HUNYUAN },
  /* iFlytek Spark */
  { "api.xfyun.cn",                    NDPI_AI_ENDPOINT_IFLYTEK_SPARK },
  { "spark-api.xf-yun.com",            NDPI_AI_ENDPOINT_IFLYTEK_SPARK },
  /* StepFun */
  { "stepfun.com",                     NDPI_AI_ENDPOINT_STEPFUN },
  { "stepfun.ai",                      NDPI_AI_ENDPOINT_STEPFUN },
  /* 01AI */
  { "lingyiwanwu.com",                 NDPI_AI_ENDPOINT_ZERO_ONE_AI },
  { "api.01.ai",                       NDPI_AI_ENDPOINT_ZERO_ONE_AI },

  { NULL, NDPI_AI_ENDPOINT_NONE } /* terminator */
};

/* --------------------------------------------------------------- *
 *  name lookup. The endpoint ids live in three sparse ranges (see
 *  ndpi_ai.h), so a dense names[value] array would be ~10000 slots of
 *  mostly holes. A switch keeps the lookup O(1) with zero waste and is
 *  trivial to extend as ids are appended.
 * --------------------------------------------------------------- */
const char *ndpi_get_ai_endpoint_name(u_int16_t ai_endpoint) {
  switch(ai_endpoint) {
    /* hosted providers */
    case NDPI_AI_ENDPOINT_OPENAI:                 return "openai";
    case NDPI_AI_ENDPOINT_ANTHROPIC:              return "anthropic";
    case NDPI_AI_ENDPOINT_GOOGLE_GEMINI:          return "google_gemini";
    case NDPI_AI_ENDPOINT_DEEPSEEK:               return "deepseek";
    case NDPI_AI_ENDPOINT_MISTRAL:                return "mistral";
    case NDPI_AI_ENDPOINT_XAI:                    return "xai";
    case NDPI_AI_ENDPOINT_COHERE:                 return "cohere";
    case NDPI_AI_ENDPOINT_GROQ:                   return "groq";
    case NDPI_AI_ENDPOINT_HUGGINGFACE:            return "huggingface";
    case NDPI_AI_ENDPOINT_PERPLEXITY:             return "perplexity";
    case NDPI_AI_ENDPOINT_Z_AI:                   return "z_ai";
    case NDPI_AI_ENDPOINT_ALIBABA_QWEN:           return "alibaba_qwen";
    case NDPI_AI_ENDPOINT_MINIMAX:                return "minimax";
    case NDPI_AI_ENDPOINT_MOONSHOT:               return "moonshot";
    case NDPI_AI_ENDPOINT_VOLCENGINE_ARK:         return "volcengine_ark";
    case NDPI_AI_ENDPOINT_SILICONFLOW:            return "siliconflow";
    case NDPI_AI_ENDPOINT_BAIDU_QIANFAN:          return "baidu_qianfan";
    case NDPI_AI_ENDPOINT_TENCENT_HUNYUAN:        return "tencent_hunyuan";
    case NDPI_AI_ENDPOINT_IFLYTEK_SPARK:          return "iflytek_spark";
    case NDPI_AI_ENDPOINT_STEPFUN:                return "stepfun";
    case NDPI_AI_ENDPOINT_ZERO_ONE_AI:            return "zero_one_ai";
    /* generic API-format markers */
    case NDPI_AI_ENDPOINT_OPENAI_COMPATIBLE:      return "openai_compatible";
    case NDPI_AI_ENDPOINT_ANTHROPIC_COMPATIBLE:   return "anthropic_compatible";
    /* self-hosted engines */
    case NDPI_AI_ENDPOINT_VLLM:                   return "vllm";
    case NDPI_AI_ENDPOINT_LLAMA_CPP:              return "llama_cpp";
    case NDPI_AI_ENDPOINT_OLLAMA:                 return "ollama";
    case NDPI_AI_ENDPOINT_SGLANG:                 return "sglang";
    case NDPI_AI_ENDPOINT_RADIANCE:               return "radiance";
    case NDPI_AI_ENDPOINT_MLX_VLM:                return "mlx_vlm";
    case NDPI_AI_ENDPOINT_OMLX:                   return "omlx";
    case NDPI_AI_ENDPOINT_VMLX:                   return "vmlx";
    case NDPI_AI_ENDPOINT_STRATA:                 return "strata";
    default:                                      return "";
  }
}

/* --------------------------------------------------------------- *
 *  SNI/Host check: run the automaton and return the matched
 *  ndpi_ai_endpoint id, or NDPI_AI_ENDPOINT_NONE.
 * --------------------------------------------------------------- */
u_int16_t ndpi_ai_check_hostname(struct ndpi_detection_module_struct *ndpi_str,
                                 char *what, u_int what_len) {
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
                     NDPI_PROTOCOL_UNRATED, 0, 0, 0, 0, 0 };
  AC_TEXT_t ac_input_text;
  int rc;

  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t *) ndpi_str->ai_endpoint_automa.ac_automa;

  if(!ndpi_str || automa == NULL ||
     what == NULL || what_len == 0 || what[0] == '\0')
    return NDPI_AI_ENDPOINT_NONE;
  if(automa->automata_open)
    return NDPI_AI_ENDPOINT_NONE;

  ac_input_text.astring = what;
  ac_input_text.length  = what_len;
  ac_input_text.option  = 0;
  rc = ac_automata_search(automa, &ac_input_text, &match);
  if(rc <= 0 || match.number == NDPI_AI_ENDPOINT_NONE)
    return NDPI_AI_ENDPOINT_NONE;

  return (u_int16_t)match.number;
}

/* Public: resolve a hostname/SNI to its ndpi_ai_endpoint (0 if not an AI endpoint). */
u_int16_t ndpi_get_ai_endpoint_by_name(struct ndpi_detection_module_struct *ndpi_str,
                                       const char *name, size_t name_len) {
  return ndpi_ai_check_hostname(ndpi_str, (char *)name, name_len);
}



/* --------------------------------------------------------------- *
 *  lifecycle: build the automaton + LRU cache
 * --------------------------------------------------------------- */
void ndpi_ai_init(struct ndpi_detection_module_struct *ndpi_str) {
  int i;

  ndpi_str->ai_endpoint_automa.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(ndpi_str->ai_endpoint_automa.ac_automa) {
    ac_automata_feature(ndpi_str->ai_endpoint_automa.ac_automa, AC_FEATURE_LC);
    ac_automata_name(ndpi_str->ai_endpoint_automa.ac_automa, "ai_endpoint", AC_FEATURE_DEBUG);

    /* The automaton terminal value is an ndpi_ai_endpoint id, not a core
     * protocol id (see ndpi_ai.h). */
    for(i = 0; ai_endpoint_match[i].domain != NULL; i++)
      ndpi_add_string_value_to_automa(ndpi_str->ai_endpoint_automa.ac_automa,
                                      (char*)ai_endpoint_match[i].domain,
                                      ai_endpoint_match[i].ai_endpoint);

    ac_automata_finalize((AC_AUTOMATA_t *) ndpi_str->ai_endpoint_automa.ac_automa);
  }

}

/* lifecycle: release the SNI/Host automaton */
void ndpi_ai_cleanup(struct ndpi_detection_module_struct *ndpi_str) {
  if(ndpi_str->ai_endpoint_automa.ac_automa != NULL)
    ac_automata_release((AC_AUTOMATA_t *) ndpi_str->ai_endpoint_automa.ac_automa,
                        0 /* pattern strings are literals; do not free them */);
}
