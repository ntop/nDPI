/*
 * AST onsatmail.c
 *
 * Copyright (C) 2016 - ast-uk.com
 *
 */


#include "ndpi_protocols.h"

#ifdef NDPI_SERVICE_ONSATMAIL

void ndpi_search_onsatmail(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	if (flow->packet.iph)
	{
		// IPv4
		u_int32_t src = ntohl(flow->packet.iph->saddr);
		u_int32_t dst = ntohl(flow->packet.iph->daddr);
		u_int16_t dport;
		u_int16_t sport;

		if ((src == 0x40048DF7) || (dst == 0x40048DF7))     /* 64.4.141.247/32 */
		{
//			dport = ntohs(flow->packet.tcp->dest);
//			sport = ntohs(flow->packet.tcp->source);
//			if ((dport == 5110) || (dport == 5540) ||
//				(sport == 5110) || (sport == 5540))
			{
				ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_SERVICE_ONSATMAIL, NDPI_PROTOCOL_UNKNOWN);
				return;
			}
		}
	}

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_SERVICE_ONSATMAIL);
}


void init_onsatmail_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
	ndpi_set_bitmask_protocol_detection("OnSatMail", ndpi_struct, detection_bitmask, *id,
					  NDPI_SERVICE_ONSATMAIL,
					  ndpi_search_onsatmail,
					  NDPI_SELECTION_BITMASK_PROTOCOL_TCP,
					  SAVE_DETECTION_BITMASK_AS_UNKNOWN,
					  ADD_TO_DETECTION_BITMASK);

	*id += 1;
}

#endif
