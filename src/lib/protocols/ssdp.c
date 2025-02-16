/*
 * ssdp.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-25 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SSDP

#include "ndpi_api.h"
#include "ndpi_private.h"

static struct SSDP {
  const char *detection_line;
  const char *method;
} SSDP_METHODS[] = {
        { "M-SEARCH * HTTP/1.1", "M-SEARCH" },
        { "NOTIFY * HTTP/1.1", "NOTIFY" }
};

static void ssdp_parse_lines(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  ndpi_parse_packet_line_info(ndpi_struct, flow);

  /* Save user-agent for device discovery if available */
  if(packet->user_agent_line.ptr != NULL && packet->user_agent_line.len > 0) {
    if (ndpi_user_agent_set(flow, packet->user_agent_line.ptr, packet->user_agent_line.len) == NULL)
    {
      NDPI_LOG_DBG2(ndpi_struct, "Could not set SSDP user agent\n");
    }
  }

  /* Save host which provides a service if available */
  if (packet->host_line.ptr != NULL && packet->host_line.len > 0) {
    ndpi_hostname_sni_set(flow, packet->host_line.ptr, packet->host_line.len, NDPI_HOSTNAME_NORM_ALL);
  }

  if (packet->bootid.ptr != NULL && packet->bootid.len > 0) {
    flow->protos.ssdp.bootid = ndpi_malloc(packet->bootid.len + 1);
    if (flow->protos.ssdp.bootid) {
      memcpy(flow->protos.ssdp.bootid, packet->bootid.ptr, packet->bootid.len);
      flow->protos.ssdp.bootid[packet->bootid.len] = '\0';
    }
  }

  if (packet->usn.ptr != NULL && packet->usn.len > 0) {
    flow->protos.ssdp.usn = ndpi_malloc(packet->usn.len + 1);
    if (flow->protos.ssdp.usn) {
      memcpy(flow->protos.ssdp.usn, packet->usn.ptr, packet->usn.len);
      flow->protos.ssdp.usn[packet->usn.len] = '\0';
    }
  }

  if (packet->cache_controle.ptr != NULL && packet->cache_controle.len > 0) { 
    flow->protos.ssdp.cache_controle = ndpi_malloc(packet->cache_controle.len + 1);
    if (flow->protos.ssdp.cache_controle) {
      memcpy(flow->protos.ssdp.cache_controle, packet->cache_controle.ptr, packet->cache_controle.len);
      flow->protos.ssdp.cache_controle[packet->cache_controle.len] = '\0';
    }
  }

  if (packet->location.ptr != NULL && packet->location.len > 0) {
    flow->protos.ssdp.location = ndpi_malloc(packet->location.len + 1);
    if (flow->protos.ssdp.location) {
      memcpy(flow->protos.ssdp.location, packet->location.ptr, packet->location.len);
      flow->protos.ssdp.location[packet->location.len] = '\0';
    }
  }

  if (packet->household_smart_speaker_audio.ptr != NULL && packet->household_smart_speaker_audio.len > 0) {
    flow->protos.ssdp.household_smart_speaker_audio = ndpi_malloc(packet->household_smart_speaker_audio.len + 1);
    if (flow->protos.ssdp.household_smart_speaker_audio) {
      memcpy(flow->protos.ssdp.household_smart_speaker_audio, packet->household_smart_speaker_audio.ptr, packet->household_smart_speaker_audio.len);
      flow->protos.ssdp.household_smart_speaker_audio[packet->household_smart_speaker_audio.len] = '\0';
    }
  }

  if (packet->rincon_household.ptr != NULL && packet->rincon_household.len > 0) {
    flow->protos.ssdp.rincon_household = ndpi_malloc(packet->rincon_household.len + 1);
    if (flow->protos.ssdp.rincon_household) {
      memcpy(flow->protos.ssdp.rincon_household, packet->rincon_household.ptr, packet->rincon_household.len);
      flow->protos.ssdp.rincon_household[packet->rincon_household.len] = '\0';
    }
  }

  if (packet->rincon_bootseq.ptr != NULL && packet->rincon_bootseq.len > 0) {
    flow->protos.ssdp.rincon_bootseq = ndpi_malloc(packet->rincon_bootseq.len + 1);
    if (flow->protos.ssdp.rincon_bootseq) {
      memcpy(flow->protos.ssdp.rincon_bootseq, packet->rincon_bootseq.ptr, packet->rincon_bootseq.len);
      flow->protos.ssdp.rincon_bootseq[packet->rincon_bootseq.len] = '\0';
    }
  }

  if (packet->rincon_wifimode.ptr != NULL && packet->rincon_wifimode.len > 0) {
    flow->protos.ssdp.rincon_wifimode = ndpi_malloc(packet->rincon_wifimode.len + 1);
    if (flow->protos.ssdp.rincon_wifimode) {
      memcpy(flow->protos.ssdp.rincon_wifimode, packet->rincon_wifimode.ptr, packet->rincon_wifimode.len);
      flow->protos.ssdp.rincon_wifimode[packet->rincon_wifimode.len] = '\0';
    }
  }

  if (packet->rincon_variant.ptr != NULL && packet->rincon_variant.len > 0) {
    flow->protos.ssdp.rincon_variant = ndpi_malloc(packet->rincon_variant.len + 1);
    if (flow->protos.ssdp.rincon_variant) {
      memcpy(flow->protos.ssdp.rincon_variant, packet->rincon_variant.ptr, packet->rincon_variant.len);
      flow->protos.ssdp.rincon_variant[packet->rincon_variant.len] = '\0';
    }
  }

  if (packet->sonos_securelocation.ptr != NULL && packet->sonos_securelocation.len > 0) {
    flow->protos.ssdp.sonos_securelocation = ndpi_malloc(packet->sonos_securelocation.len + 1);
    if (flow->protos.ssdp.sonos_securelocation) {
      memcpy(flow->protos.ssdp.sonos_securelocation, packet->sonos_securelocation.ptr, packet->sonos_securelocation.len);
      flow->protos.ssdp.sonos_securelocation[packet->sonos_securelocation.len] = '\0';
    }
  }

  if (packet->securelocation_upnp.ptr != NULL && packet->securelocation_upnp.len > 0) {
    flow->protos.ssdp.securelocation_upnp = ndpi_malloc(packet->securelocation_upnp.len + 1);
    if (flow->protos.ssdp.securelocation_upnp) {
      memcpy(flow->protos.ssdp.securelocation_upnp, packet->securelocation_upnp.ptr, packet->securelocation_upnp.len);
      flow->protos.ssdp.securelocation_upnp[packet->securelocation_upnp.len] = '\0';
    }
  }

  if (packet->location_smart_speaker_audio.ptr != NULL && packet->location_smart_speaker_audio.len > 0) {
    flow->protos.ssdp.location_smart_speaker_audio = ndpi_malloc(packet->location_smart_speaker_audio.len + 1);
    if (flow->protos.ssdp.location_smart_speaker_audio) {
      memcpy(flow->protos.ssdp.location_smart_speaker_audio, packet->location_smart_speaker_audio.ptr, packet->location_smart_speaker_audio.len);
      flow->protos.ssdp.location_smart_speaker_audio[packet->location_smart_speaker_audio.len] = '\0';
    }
  }

  if (packet->nt.ptr != NULL && packet->nt.len > 0) {
    flow->protos.ssdp.nt = ndpi_malloc(packet->nt.len + 1);
    if (flow->protos.ssdp.nt) {
      memcpy(flow->protos.ssdp.nt, packet->nt.ptr, packet->nt.len);
      flow->protos.ssdp.nt[packet->nt.len] = '\0';
    }
  }

  if (packet->nts.ptr != NULL && packet->nts.len > 0) {
    flow->protos.ssdp.nts = ndpi_malloc(packet->nts.len + 1);
    if (flow->protos.ssdp.nts) {
      memcpy(flow->protos.ssdp.nts, packet->nts.ptr, packet->nts.len);
      flow->protos.ssdp.nts[packet->nts.len] = '\0';
    }
  }

  if (packet->server_line.ptr != NULL && packet->server_line.len > 0) {
    flow->protos.ssdp.server = ndpi_malloc(packet->server_line.len + 1);
    if (flow->protos.ssdp.server) {
      memcpy(flow->protos.ssdp.server, packet->server_line.ptr, packet->server_line.len);
      flow->protos.ssdp.server[packet->server_line.len] = '\0';
    }
  }
}

static void ndpi_int_ssdp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ssdp_parse_lines(ndpi_struct, flow);
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SSDP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* this detection also works asymmetrically */
static void ndpi_search_ssdp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
	
  NDPI_LOG_DBG(ndpi_struct, "search ssdp\n");
  if (packet->udp != NULL) {

    if (packet->payload_packet_len >= 19) {
      for (unsigned int i=0; i < sizeof(SSDP_METHODS)/sizeof(SSDP_METHODS[0]); i++) {
        if(memcmp(packet->payload, SSDP_METHODS[i].detection_line, strlen(SSDP_METHODS[i].detection_line)) == 0) {
          flow->protos.ssdp.method = ndpi_malloc(strlen(SSDP_METHODS[i].detection_line) + 1);
          if (flow->protos.ssdp.method) {
            memcpy(flow->protos.ssdp.method, SSDP_METHODS[i].method, strlen(SSDP_METHODS[i].method));
            flow->protos.ssdp.method[strlen(SSDP_METHODS[i].method)] = '\0';
          }
          NDPI_LOG_INFO(ndpi_struct, "found ssdp\n");
          ndpi_int_ssdp_add_connection(ndpi_struct, flow);
          return;
        }
    }

#define SSDP_HTTP "HTTP/1.1 200 OK\r\n"
      if(memcmp(packet->payload, SSDP_HTTP, strlen(SSDP_HTTP)) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found ssdp\n");
	ndpi_int_ssdp_add_connection(ndpi_struct, flow);
	return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_ssdp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("SSDP", ndpi_struct, *id,
				      NDPI_PROTOCOL_SSDP,
				      ndpi_search_ssdp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

