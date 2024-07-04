/*
 * cloudflare_warp.c
 *
 * Copyright (C) 2024 - ntop.org
 *
 * nDPI is free software: you can zmqtribute it and/or modify
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CLOUDFLARE_WARP

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_cloudflare_warp_add_connection(struct ndpi_detection_module_struct * ndpi_struct,
                                                    struct ndpi_flow_struct * flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found CloudflareWarp\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CLOUDFLARE_WARP,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}


static void ndpi_search_cloudflare_warp(struct ndpi_detection_module_struct *ndpi_struct,
                                        struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search CloudflareWarp\n");

  /* https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/firewall/ */

  /* Cloudflare has been using wireguard and it is moving to MASQUE:
     * https://blog.cloudflare.com/1111-warp-better-vpn/
     * https://blog.cloudflare.com/zero-trust-warp-with-a-masque

     Wireguard. It is not a standard wireguard traffic:
     * message type seems to be 0xc1-0xc4 instead of 1-4
     * handshake messages are different
     * reserved bytes are set to 0x00 only on the very first msg, i.e 0xc1
     However:
     * for the "data" messages, the receiver_index and counter fields seems as the standard ones
     * the general logic (2 handshake pkts + data) seems the same

     TODO: Not yet available traffic sample with MASQUE

     Overall, it should be enough to identify it via ip and port matching
  */

  if(flow->guessed_protocol_id_by_ip == NDPI_PROTOCOL_CLOUDFLARE_WARP) {
    /* Wireguard */
    if(flow->s_port == ntohs(2408) || flow->c_port == ntohs(2408) ||
       flow->s_port == ntohs(500) || flow->c_port == ntohs(500) ||
       flow->s_port == ntohs(1701) || flow->c_port == ntohs(1701) ||
       flow->s_port == ntohs(4500) || flow->c_port == ntohs(4500)) {
      ndpi_int_cloudflare_warp_add_connection(ndpi_struct, flow);
      return;
    }
    /* MASQUE */
    /* TODO: we should check if the QUIC dissector already owns this flow, i.e
       if this code path is ever triggered... */
    if(flow->s_port == ntohs(443) || flow->c_port == ntohs(443) ||
       flow->s_port == ntohs(4443) || flow->c_port == ntohs(4443) ||
       flow->s_port == ntohs(8443) || flow->c_port == ntohs(8443) ||
       flow->s_port == ntohs(8095) || flow->c_port == ntohs(8095)) {
      ndpi_int_cloudflare_warp_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_cloudflare_warp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                    u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("CloudflareWarp", ndpi_struct, *id,
                                      NDPI_PROTOCOL_CLOUDFLARE_WARP,
                                      ndpi_search_cloudflare_warp,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
