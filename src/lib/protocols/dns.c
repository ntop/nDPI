/*
 * dns.c
 *
 * Copyright (C) 2012-20 - ntop.org
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

 #include <stdbool.h>
 
#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DNS

#include "dns.h"
#include "ndpi_api.h"

#define FLAGS_MASK 0x8000

/* #define DNS_DEBUG 1 */

#define DNS_PORT   53
#define LLMNR_PORT 5355
#define MDNS_PORT  5353

static void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow);

/* *********************************************** */

static void ndpi_check_dns_type(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				u_int16_t dns_type) {
  /* https://en.wikipedia.org/wiki/List_of_DNS_record_types */

  switch(dns_type) {
    /* Obsolete record types */
  case 3:
  case 4:
  case 254:
  case 7:
  case 8:
  case 9:
  case 14:
  case 253:
  case 11:
  case 33:
  case 10:
  case 38:
  case 30:
  case 25:
  case 24:
  case 13:
  case 17:
  case 19:
  case 20:
  case 21:
  case 22:
  case 23:
  case 26:
  case 31:
  case 32:
  case 34:
  case 42:
  case 40:
  case 27:
  case 100:
  case 101:
  case 102:
  case 103:
  case 99:
  case 56:
  case 57:
  case 58:
  case 104:
  case 105:
  case 106:
  case 107:
  case 259:
    NDPI_SET_BIT(flow->risk, NDPI_DNS_SUSPICIOUS_TRAFFIC);
    break;
  }
}

/* *********************************************** */

static u_int16_t checkPort(u_int16_t port) {
  switch(port) {
  case DNS_PORT:
    return(NDPI_PROTOCOL_DNS);
    break;
  case LLMNR_PORT:
    return(NDPI_PROTOCOL_LLMNR);
    break;
  case MDNS_PORT:
    return(NDPI_PROTOCOL_MDNS);
    break;
  }

  return(0);
}

/* *********************************************** */

static u_int16_t checkDNSSubprotocol(u_int16_t sport, u_int16_t dport) {
  u_int16_t rc = checkPort(sport);

  if(rc == 0)
    return(checkPort(dport));
  else
    return(rc);
}

/* *********************************************** */

static u_int16_t get16(int *i, const u_int8_t *payload) {
  u_int16_t v = *(u_int16_t*)&payload[*i];

  (*i) += 2;

  return(ntohs(v));
}

static u_int32_t get32(int *i, const u_int8_t *payload) {
  uint32_t v = *(uint32_t*)&payload[*i];

  (*i) += 4;

  return(ntohl(v));
}

static struct dnsRRList_t *add_RR_elem_to_list(struct dnsRRList_t *currList, struct dnsRR_t *newItem) {
	
	//printf("DBG(add_RR_elem_to_list): list: %p, item: %p\n",currList,newItem);	
	struct dnsRRList_t *retList= ndpi_calloc(1, sizeof(struct dnsRRList_t));
	if ( retList ) {
		retList->rrItem= newItem;
		retList->nextItem= NULL;
		
		if ( currList ) {
			currList->nextItem= retList;
			retList->prevItem= currList;
		} 
		else {
			retList->prevItem= NULL;
		}
		//printf("DBG(add_RR_elem_to_list): return list: %p\n",retList);
		return retList;
	}	
	//printf("DBG(add_RR_elem_to_list): ERR: input pointer nil \n");
	return NULL;
}

void free_dns_QSec(struct dnsQuestionSec_t *qs) {
	if (qs) {
		if (qs->questionName) ndpi_free(qs->questionName);
		ndpi_free(qs);
	}
}

static void free_dns_RR(struct dnsRR_t *rr) {
	if (rr) {

		//printf("DBG(free_dns_RR): rrItem=%p, rrName=%p, rrType=%d \n",rr,rr->rrName,rr->rrType);
		if (rr->rrName) ndpi_free(rr->rrName);
		
		switch(rr->rrType) {
			case 2:
				if (rr->RData.NSDName) ndpi_free(rr->RData.NSDName);
				break;
			case 5:
				if (rr->RData.CName) ndpi_free(rr->RData.CName);		
				break;
			case 6:
				if (rr->RData.SOA.MName) ndpi_free(rr->RData.SOA.MName);
				if (rr->RData.SOA.RName) ndpi_free(rr->RData.SOA.RName);
				break;		
			case 12:
				if (rr->RData.PTRDName) ndpi_free(rr->RData.PTRDName);		
				break;		
			case 13:
				if (rr->RData.HINFO.cpu) ndpi_free(rr->RData.HINFO.cpu);		
				if (rr->RData.HINFO.os) ndpi_free(rr->RData.HINFO.os);		
				break;
			case 15:
				if (rr->RData.MX.exchange) ndpi_free(rr->RData.MX.exchange);
				break;		
			case 16:
				if (rr->RData.txtData) ndpi_free(rr->RData.txtData);		
				break;		
		};	
		ndpi_free(rr);
	}
}
	
void clear_dns_RR_list(struct dnsRRList_t* currList, unsigned char bForward) {	
	//printf("DBG(clear_dns_RR_list): currList=%p, bForward=%d \n",currList,bForward);
	while (currList) {		
		free_dns_RR(currList->rrItem);
		struct dnsRRList_t* tmp= (bForward) ? currList->nextItem :  currList->prevItem;
		ndpi_free( currList );
		currList= tmp;		
	}	
}


/* *********************************************** */

/*
  get the DNS name length, 
  using the DNS Name Notation and Message Compression Technique
  so:
	if there is a pointer to other location of packet (c0), 
	jumps there and continue with count.
	return the real length of dns name, without change the pointer  
*/  
u_int getNameLength(u_int i, const u_int8_t *payload, u_int payloadLen) {
  u_int8_t len=0,retLen=0;
  // printf("DBG(getNameLength): off=%d/%d\n",i,payloadLen);
  if(i >= payloadLen)
    return(0);
  else if(payload[i] == 0x00)
    return(0);
  else if(payload[i] == 0xC0) {
	u_int8_t noff = payload[i+1];	// jump to new position
	// printf("DBG(getNameLength): jump to pos=%d\n",noff);
    retLen=getNameLength(noff, payload, payloadLen);
	// printf("DBG(getNameLength): returned c0 len=%d\n",retLen);
	return (retLen);
  } else {
    len = payload[i]+1;	// word length and dot or termination char
    u_int8_t off = len; // new offset 
	// printf("DBG(getNameLength): curr len=%d\n",len);
    if(off == 0) /* Bad packet */
      return(0);
    else {
	  // printf("DBG(getNameLength): delta len=%d\n",len);
	  retLen=getNameLength(i+off, payload, payloadLen);
	  // printf("DBG(getNameLength): returned len=%d\n",retLen);
	  return (len + retLen);
	}      
  }
}

/* *********************************************** */

/*
  allowed chars for dns names A-Z 0-9 _ -
  Perl script for generation map:
  my @M;
  for(my $ch=0; $ch < 256; $ch++) {
  $M[$ch >> 5] |= 1 << ($ch & 0x1f) if chr($ch) =~ /[a-z0-9_-]/i;
  }
  print join(',', map { sprintf "0x%08x",$_ } @M),"\n";
*/
static uint32_t dns_validchar[8] =
  {
   0x00000000,0x03ff2000,0x87fffffe,0x07fffffe,0,0,0,0
  };

/* *********************************************** */

/*
	parse and retrieve a dns name, 
	using the DNS Name Notation and Message Compression Technique
	at exit increment offset of pointer on payload
	
   NB: if return_field pointer points to an area of max_len bytes, and
	retrieved dns name is longer, the returned value is truncated!	
*/
void parseDnsName( u_char *return_field, const int max_len, int *i, const u_int8_t *payload, const u_int payloadLen ) {
	u_int j= 0, off, cloff= 0, data_len, tmpv;
	
	//printf("DBG(parseDnsName)\n");
	
	// printf("DBG(parseDnsName) initial offset: %d\n",*i);
	off=(u_int)*i;
	data_len= getNameLength(off, payload, payloadLen);
	// printf("DBG(parseDnsName): len %d, space: %d\n",data_len,max_len);
	
	u_char *dnsName= ndpi_calloc(data_len+1,sizeof(u_char));
	if ( return_field && dnsName) {
		
		while(j < data_len && off < payloadLen && payload[off] != '\0') {
		  uint8_t c, cl = payload[off++];	//init label counter

		  // printf("DBG(parseDnsName): off: %d, value: %02X %c\n",off, cl, cl);
		  if( (cl & 0xc0) != 0 ) {
			cloff=(cloff)?cloff:off+1;		// save return offset, first time
			tmpv= (payload[off++]);			// change offset
			off = tmpv;
			// printf("DBG(parseDnsName): saved offset %d for jump to new off: %d\n",cloff, off);
			continue;
		  } else if (off + cl >= payloadLen) {
			j = 0;	
			break;
		  }

		  if(j && j < data_len) dnsName[j++] = '.';	// replace the label length with dot, except the at first 

		  while(j < data_len && cl != 0) {
			u_int32_t shift;
			
			c = payload[off++];
			shift = ((u_int32_t) 1) << (c & 0x1f);
			dnsName[j++] = tolower((dns_validchar[c >> 5] & shift) ? c : '_');
			cl--;
		  }
		}
		
		dnsName[j] = '\0';	// terminate dnsName
				
		if(j > 0) {
			j = MIN(max_len,j);
			// printf("DBG(parseDnsName): offset iniziale: (%d), len:[%d] ? c0_inc_offset:[%d]\n", *i, j, cloff);
			*i= (cloff)?cloff:(j+2+*i);
			strncpy((char*)return_field,(char*)dnsName,j);
			// printf("DBG(parseDnsName): result: (%d) [%s]; new offset:[%d]\n", j, dnsName, *i);
		}
	}
	else
		printf("ERR: input pointer nil [%p] or failed to allocate memory.\n",return_field);
	
	// printf("DBG(parseDnsName) final offset: %d\n",*i);
	
	ndpi_free(dnsName);	// free memory
}


/* *********************************************** */

/*
	scan and parse a RR section (Answer,Authority,Additional) of DNS packet
	increment the offset in the payload, after the last rr record successfully parsed

*/
struct dnsRRList_t *parseDnsRRs(u_int8_t nitems, int *i, const u_int8_t *payload, const u_int payloadLen ) {
	
	struct dnsRRList_t *retRRList=NULL, *lastRRListItem=NULL;
	u_int off= (u_int)*i; // init offset 
	
	//printf("DBG(parseDnsRRs): off initialized = %u\n", off);
	
	for (int k=0; k<nitems; k++) {
	
		//printf("DBG(parseDnsRRs): next record start at offset=%u\n", off);	
		
		struct dnsRR_t *currItem= ndpi_calloc( 1, sizeof(struct dnsRR_t) ); 
		if ( currItem ) {
			size_t data_len;		
				
			//printf("DBG(parseDnsRRs): extracting data of item no. %d/%d \n",(k+1),nitems);
				
			/* parse the rrName */
			if((data_len = getNameLength(off, payload, payloadLen)) == 0) {
				printf("ERR(parseDnsRRs): 0 length of dns name \n");
				ndpi_free(currItem);
				break;
			}
			currItem->rrName = ndpi_calloc( data_len, sizeof(char) );
			if ( currItem->rrName ) {
				parseDnsName( (u_char*)currItem->rrName, data_len, (int*)&off, payload, payloadLen );
				//printf("DBG(parseDnsRRs): rrName: [%p] (%u) %s\n",currItem->rrName,(u_int)data_len,currItem->rrName);
			}
			else {
				printf("ERR(parseDnsRRs): fail to allocate memory for dns name\n");
				ndpi_free(currItem);
				return NULL; 
			}

			currItem->rrType =  get16((int*)&off, payload); 						// resource type
			currItem->rrClass = get16((int*)&off, payload); 						// class of the resource record
			currItem->rrTTL= get32((int*)&off, payload);							// cache time to live			
			currItem->rrRDL= get16((int*)&off, payload);							// resource data length
			
			//printf("DBG(parseDnsRRs): type:%u, class:%u, ttl:%u, RDlen: %u\n",currItem->rrType,currItem->rrClass,currItem->rrTTL,currItem->rrRDL);
			switch(currItem->rrType) {
				
				case DNS_TYPE_A:
					memcpy(&currItem->RData.addressIP, &payload[off], sizeof(uint32_t));
					//printf("DBG(parseDnsRRs): A [%p]\n",&currItem->RData.addressIP);
					off+=4;
					break;
				
				case DNS_TYPE_NS:
					if((data_len = getNameLength(off, payload, payloadLen)) > 0) {
						currItem->RData.NSDName= ndpi_calloc(data_len, sizeof(char));
						if ( currItem->RData.NSDName ) {
							parseDnsName( (u_char*)currItem->RData.NSDName, data_len, (int*)&off, payload, payloadLen );
							//printf("DBG(parseDnsRRs): NS: (%u) %s\n",(u_int)data_len,currItem->RData.NSDName);
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for NS [ ]\n");
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}					
					}
					else {
						printf("ERR(parseDnsRRs): fail to allocate memory for txtData [ ]\n");
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					break;
				
				case DNS_TYPE_CNAME:
					if((data_len = getNameLength(off, payload, payloadLen)) > 0) {
						currItem->RData.CName= ndpi_calloc(data_len, sizeof(char));
						if ( currItem->RData.CName ) {
							parseDnsName( (u_char*)currItem->RData.CName, data_len, (int*)&off, payload, payloadLen );
							//printf("DBG(parseDnsRRs): CNAME: (%u) %s\n",(u_int)data_len,currItem->RData.CName);
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for CNAME [ ]\n");
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}				
					}
					else {
						printf("ERR(parseDnsRRs): fail to allocate memory for txtData [ ]\n");
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					break;
				
				case DNS_TYPE_SOA:
					// extract SOA Master name
					if((data_len = getNameLength(off, payload, payloadLen)) > 0) {
						currItem->RData.SOA.MName= ndpi_calloc(data_len, sizeof(char));
						if ( currItem->RData.SOA.MName ) {
							parseDnsName( (u_char*)currItem->RData.SOA.MName, data_len, (int*)&off, payload, payloadLen );
							//printf("DBG(parseDnsRRs): SOA.MName: (%u) %s\n",(u_int)data_len, currItem->RData.SOA.MName);							
						}			
						else { 
							printf("ERR(parseDnsRRs): fail to allocate memory for SOA.MName [ ]\n");
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}
					} else currItem->RData.SOA.MName= NULL;
					
					// extract SOA Responsible name
					if((data_len = getNameLength(off, payload, payloadLen)) > 0) {
						currItem->RData.SOA.RName= ndpi_calloc(data_len, sizeof(char));
						if ( currItem->RData.SOA.RName ) {
							parseDnsName( (u_char*)currItem->RData.SOA.RName, data_len, (int*)&off, payload, payloadLen );
							//printf("DBG(parseDnsRRs): SOA.RName: (%u) %s\n",(u_int)data_len,currItem->RData.SOA.RName);							
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for SOA.RName [ ]\n");
							ndpi_free(currItem->RData.SOA.MName);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}					
					} 
					else currItem->RData.SOA.RName= NULL;
					
					currItem->RData.SOA.Serial= get32((int*)&off, payload); 	// serial
					currItem->RData.SOA.Refresh= get32((int*)&off, payload); 	// refresh
					currItem->RData.SOA.Retry= get32((int*)&off, payload); 		// retry
					currItem->RData.SOA.Expire= get32((int*)&off, payload); 	// expire
					currItem->RData.SOA.Minimum= get32((int*)&off, payload); 	// minimum
					
					break;
				
				case DNS_TYPE_PTR:
					if((data_len = getNameLength(off, payload, payloadLen)) > 0) {
						currItem->RData.PTRDName= ndpi_calloc(data_len, sizeof(char));
						if ( currItem->RData.PTRDName ) {
							parseDnsName( (u_char*)currItem->RData.PTRDName, data_len, (int*)&off, payload, payloadLen );
							//printf("DBG(parseDnsRRs): PTR: (%u) %s\n",(u_int)data_len,currItem->RData.PTRDName);
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for PTR [ ]\n");
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}				
					}
					else {
						printf("ERR(parseDnsRRs): fail to allocate memory for PTR [ ]\n");
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					break;
					
				case DNS_TYPE_HINFO:
					currItem->RData.HINFO.cpu_len= payload[off++];
					//printf("DBG(parseDnsRRs): DNS_TYPE_HINFO cpu len: %d\n",currItem->RData.HINFO.cpu_len);
					currItem->RData.HINFO.cpu= ndpi_calloc(currItem->RData.HINFO.cpu_len+1, sizeof(char));
					if (currItem->RData.HINFO.cpu) {
						memcpy(currItem->RData.HINFO.cpu, &payload[off],currItem->RData.HINFO.cpu_len);
						off+=currItem->RData.HINFO.cpu_len;
						//printf("DBG(parseDnsRRs): DNS_TYPE_HINFO: os: (%d) [%s]\n", currItem->RData.HINFO.cpu_len, currItem->RData.HINFO.cpu);
					}					
					currItem->RData.HINFO.os_len= payload[off++];
					//printf("DBG(parseDnsRRs): DNS_TYPE_HINFO os len: %d\n",currItem->RData.HINFO.os_len);
					currItem->RData.HINFO.os= ndpi_calloc(currItem->RData.HINFO.os_len+1, sizeof(char));
					if (currItem->RData.HINFO.os) {
						memcpy(currItem->RData.HINFO.os, &payload[off],currItem->RData.HINFO.os_len);
						off+=currItem->RData.HINFO.os_len;
						//printf("DBG(parseDnsRRs): DNS_TYPE_HINFO: os: (%d) [%s]\n", currItem->RData.HINFO.os_len, currItem->RData.HINFO.os);
					}
					break;
					
				case DNS_TYPE_MX:
					currItem->RData.MX.preference= payload[off++];
					if((data_len = getNameLength(off, payload, payloadLen)) > 0) {
						currItem->RData.MX.exchange= ndpi_calloc(data_len, sizeof(char));
						if ( currItem->RData.MX.exchange ) {
							parseDnsName( (u_char*)currItem->RData.MX.exchange, data_len, (int*)&off, payload, payloadLen );
							//printf("DBG(parseDnsRRs): MX: (%u) %s - P: %d\n",(u_int)data_len,currItem->RData.MX.exchange,currItem->RData.MX.preference);	
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for MX [ ]\n");
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}
						
					}
					else {
						printf("ERR(parseDnsRRs): fail to allocate memory for txtData [ ]\n");
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					break;
				
				case DNS_TYPE_TXT:
					currItem->RData.txtData= ndpi_calloc((1+currItem->rrRDL), sizeof(char));
					if (currItem->RData.txtData) {
						memcpy(currItem->RData.txtData, &payload[off], currItem->rrRDL);
						currItem->RData.txtData[currItem->rrRDL]='\0';
						//printf("DBG(parseDnsRRs): [(%u) %s]\n",currItem->rrRDL,currItem->RData.txtData);
						off+= currItem->rrRDL;
					} else {
						printf("ERR(parseDnsRRs): fail to allocate memory for txtData [ ]\n");
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					break;
				
				case DNS_TYPE_AFSDB:
					printf("DBG(parseDnsRRs): DNS_TYPE_AFSDB:\n");
					break;
					
				case DNS_TYPE_AAAA:
					memcpy(&currItem->RData.addressIPv6, &payload[off], currItem->rrRDL);
					//printf("DBG(parseDnsRRs): AAAA [%p]\n",&currItem->RData.addressIPv6);
					off+=16;
					break;

				case DNS_TYPE_LOC:
					printf("DBG(parseDnsRRs): DNS_TYPE_LOC:\n");
					break;
					
				case DNS_TYPE_SRV:
					printf("DBG(parseDnsRRs): DNS_TYPE_SRV:\n");
					break;

				case DNS_TYPE_NAPTR:
					printf("DBG(parseDnsRRs): DNS_TYPE_NAPTR:\n");
					break;
					
				case DNS_TYPE_AFXR:
					//memcpy(&currItem->RData.addressIPv6, &payload[off], currItem->rrRDL);
					//printf("DBG(parseDnsRRs): AFXR [%p]\n",&currItem->RData.addressIPv6);
					off+=16;
					break;
								
				default:
					printf("RR type: [%02X] not managed.\n",currItem->rrType);
			}
			
			// fill the list
			if ( retRRList ) {
				lastRRListItem= add_RR_elem_to_list(lastRRListItem, currItem);
			} else {
				// list empty: first item
				retRRList= add_RR_elem_to_list(NULL, currItem);
				lastRRListItem= retRRList;
			}
		}
		else 
			printf("ERR(parseDnsRRs): fail to allocate memory for a RR.\n");
	}
	*i=off;
	return retRRList;
}

/* *********************************************** */

static int search_valid_dns(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow,
			    struct ndpi_dns_packet_header *dns_header,
			    int payload_offset, u_int8_t *is_query) {
  int x = payload_offset;
  u_int16_t dns_class;
  
  memcpy(dns_header, (struct ndpi_dns_packet_header*)&flow->packet.payload[x],
	 sizeof(struct ndpi_dns_packet_header));

  dns_header->tr_id = ntohs(dns_header->tr_id);
  dns_header->flags = ntohs(dns_header->flags);
  dns_header->num_queries = ntohs(dns_header->num_queries);
  dns_header->num_answers = ntohs(dns_header->num_answers);
  dns_header->authority_rrs = ntohs(dns_header->authority_rrs);
  dns_header->additional_rrs = ntohs(dns_header->additional_rrs);

  x += sizeof(struct ndpi_dns_packet_header);
 
  //printf("DBG(search_valid_dns): #%02Xh, counters: [%d,%d,%d,%d]\n",dns_header->tr_id,dns_header->num_queries,dns_header->num_answers,dns_header->authority_rrs,dns_header->additional_rrs);
  
  /* 0x0000 QUERY */
  if((dns_header->flags & FLAGS_MASK) == 0x0000)
    *is_query = 1;
  /* 0x8000 RESPONSE */
  else if((dns_header->flags & FLAGS_MASK) == 0x8000)
    *is_query = 0;
  else {
    NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
    return(1 /* invalid */);
  }

#ifdef __DNS_H__  
  /* setting ID and flag to flow struct */
  flow->protos.dns.tr_id= dns_header->tr_id;
  flow->protos.dns.flags= dns_header->flags;
#endif
  
  if(*is_query) {
    /* DNS Request */
    if((dns_header->num_queries > 0) && (dns_header->num_queries <= NDPI_MAX_DNS_REQUESTS)
       && (((dns_header->flags & 0x2800) == 0x2800 /* Dynamic DNS Update */)
	   || ((dns_header->num_answers == 0) && (dns_header->authority_rrs == 0)))) {

      /* This is a good query */
      while(x+2 < flow->packet.payload_packet_len) {
        if(flow->packet.payload[x] == '\0') {
          x++;
          flow->protos.dns.query_type = get16((int*)&x, flow->packet.payload);
		  
		  dns_class =  get16((int*)&x, flow->packet.payload); x -=2;
		  flow->protos.dns.query_class = dns_class;
		  
#ifdef DNS_DEBUG
          NDPI_LOG_DBG2(ndpi_struct, "query_type=%2d\n", flow->protos.dns.query_type);
#endif
			break;
		} else
	  		x++;
      }
    } else {
      NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
      return(1 /* invalid */);
    }
  } else {
    /* DNS Reply */
    flow->protos.dns.reply_code = dns_header->flags & 0x0F; // 0= no error

    if((dns_header->num_queries > 0) && (dns_header->num_queries <= NDPI_MAX_DNS_REQUESTS) /* Don't assume that num_queries must be zero */
       && ((((dns_header->num_answers > 0) && (dns_header->num_answers <= NDPI_MAX_DNS_REQUESTS))
	    || ((dns_header->authority_rrs > 0) && (dns_header->authority_rrs <= NDPI_MAX_DNS_REQUESTS))
	    || ((dns_header->additional_rrs > 0) && (dns_header->additional_rrs <= NDPI_MAX_DNS_REQUESTS))))
       ) {
      /* This is a good reply: we dissect it both for request and response */

      /* Leave the statement below commented necessary in case of call to ndpi_get_partial_detection() */
      x++;

	  // skip 'Question Name' section, because do its extraction after
	  if(x < flow->packet.payload_packet_len && flow->packet.payload[x] != '\0') {
		while((x < flow->packet.payload_packet_len)
			  && (flow->packet.payload[x] != '\0')) {
		  x++;
		}
		x++;
      }
      x += 4;
	  // end skip 'Question Name' section

      if(dns_header->num_answers > 0) {
		  
#ifdef __DNS_H__
		   
	  	/* WARNING: if there is a flow active it need to free allocated memory! */
		flow->protos.dns.dnsAnswerRRList= parseDnsRRs(dns_header->num_answers,&x,flow->packet.payload,flow->packet.payload_packet_len);
		
		// for compatibility with previous code, set the following variables with the first answer
		if ( flow->protos.dns.dnsAnswerRRList ) {
			
			struct dnsRR_t *firstRR = flow->protos.dns.dnsAnswerRRList->rrItem;
			if (firstRR) {
				flow->protos.dns.rsp_type= firstRR->rrType;
				flow->protos.dns.query_class= firstRR->rrClass;
				
				if ( (((firstRR->rrType == 0x1) && (firstRR->rrRDL == 4)) /* A */
#ifdef NDPI_DETECTION_SUPPORT_IPV6
					|| ((firstRR->rrType == 0x1c) && (firstRR->rrRDL == 16)) /* AAAA */
#endif
				)) {
					memcpy(&flow->protos.dns.rsp_addr, &firstRR->RData, firstRR->rrRDL);
				}					
			}
		}		
#else		  
		u_int16_t rsp_type;
		u_int16_t num;

		for(num = 0; num < dns_header->num_answers; num++) {
		  u_int16_t data_len;

		  if((x+6) >= flow->packet.payload_packet_len) {
			break;
		  }

		  if((data_len = getNameLength(x, flow->packet.payload, flow->packet.payload_packet_len)) == 0) {
			break;
		  } else
			x += data_len;

		  if((x+2) >= flow->packet.payload_packet_len) {
			break;
		  }
		  rsp_type = get16((int*)&x, flow->packet.payload);
		  flow->protos.dns.rsp_type = rsp_type;
		  
		  //dns_class =  get16((int*)&x, flow->packet.payload); x -=2;
		  //flow->protos.dns.query_class = dns_class;

		  /* here x points to the response "class" field */
		  if((x+12) <= flow->packet.payload_packet_len) {
			x += 6;
			data_len = get16((int*)&x, flow->packet.payload);
			
			if((x + data_len) <= flow->packet.payload_packet_len) {
			  // printf("[rsp_type: %u][data_len: %u]\n", rsp_type, data_len);

			  if(rsp_type == 0x05 /* CNAME */) {
				x += data_len;
				continue; /* Skip CNAME */
			  }
			  
			  if((((rsp_type == 0x1) && (data_len == 4)) /* A */
#ifdef NDPI_DETECTION_SUPPORT_IPV6
			  || ((rsp_type == 0x1c) && (data_len == 16)) /* AAAA */
#endif
			  )) {
			memcpy(&flow->protos.dns.rsp_addr, flow->packet.payload + x, data_len);
			  }
			}
		  }
		  
		  break;
		}
#endif		
      }
#ifdef __DNS_H__
	  else
		  flow->protos.dns.dnsAnswerRRList= NULL;	

	  if(dns_header->authority_rrs > 0) 
		flow->protos.dns.dnsAuthorityRRList= parseDnsRRs(dns_header->authority_rrs,&x, flow->packet.payload, flow->packet.payload_packet_len);
	  else
		  flow->protos.dns.dnsAuthorityRRList= NULL;
		
	  if(dns_header->additional_rrs > 0) 
		flow->protos.dns.dnsAdditionalRRList= parseDnsRRs(dns_header->additional_rrs,&x, flow->packet.payload, flow->packet.payload_packet_len);
	  else
		  flow->protos.dns.dnsAdditionalRRList= NULL;	
		  
#endif
     
      if((flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_DNS)
	 || (flow->packet.detected_protocol_stack[1] == NDPI_PROTOCOL_DNS)) {
	/* Request already set the protocol */
	// flow->extra_packets_func = NULL; /* Removed so the caller can keep dissecting DNS flows */
      } else {
	/* We missed the request */
	u_int16_t s_port = flow->packet.udp ? ntohs(flow->packet.udp->source) : ntohs(flow->packet.tcp->source);

	ndpi_set_detected_protocol(ndpi_struct, flow, checkPort(s_port), NDPI_PROTOCOL_UNKNOWN);
      }
    }
  }

  /* Valid */
  return(0);
}

/* *********************************************** */

static int search_dns_again(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  /* possibly dissect the DNS reply */
  ndpi_search_dns(ndpi_struct, flow);

  /* Possibly more processing */
  return(1);
}

/* *********************************************** */

static void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  int payload_offset;
  u_int8_t is_query;
  u_int16_t s_port = 0, d_port = 0;

  NDPI_LOG_DBG(ndpi_struct, "search DNS\n");

  if(flow->packet.udp != NULL) {
    s_port = ntohs(flow->packet.udp->source);
    d_port = ntohs(flow->packet.udp->dest);
    payload_offset = 0;
  } else if(flow->packet.tcp != NULL) /* pkt size > 512 bytes */ {
    s_port = ntohs(flow->packet.tcp->source);
    d_port = ntohs(flow->packet.tcp->dest);
    payload_offset = 2;
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if((s_port == 53 || d_port == 53 || d_port == 5355)
     && (flow->packet.payload_packet_len > sizeof(struct ndpi_dns_packet_header)+payload_offset)) {
    struct ndpi_dns_packet_header dns_header;
    int j = 0, max_len, off;
    int invalid = search_valid_dns(ndpi_struct, flow, &dns_header, payload_offset, &is_query);
	//printf("DBG(ndpi_search_dns): invalid=%d\n", invalid);
	
    ndpi_protocol ret;

    ret.master_protocol   = NDPI_PROTOCOL_UNKNOWN;
    ret.app_protocol      = (d_port == 5355) ? NDPI_PROTOCOL_LLMNR : NDPI_PROTOCOL_DNS;

    if(invalid) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

	    /* extract host name server from 'question section' */
    max_len = sizeof(flow->host_server_name)-1;
    off = sizeof(struct ndpi_dns_packet_header) + payload_offset;
	
#ifdef __DNS_H__
	// printf("DBG(ndpi_search_dns): max len: %d, offset: %u\n", max_len, off);
	parseDnsName( flow->host_server_name, max_len, (int*)&off, flow->packet.payload, flow->packet.payload_packet_len );	
	j = strlen((const char*)flow->host_server_name);
	
	//printf("DBG(ndpi_search_dns): len: %d, [%s]\n", j, flow->host_server_name);
#else
    
    while(j < max_len && off < flow->packet.payload_packet_len && flow->packet.payload[off] != '\0') {
      uint8_t c, cl = flow->packet.payload[off++];	//init label counter

      if( (cl & 0xc0) != 0 || // we not support compressed names in query
			off + cl  >= flow->packet.payload_packet_len) {
		j = 0;	
		break;
      }

      if(j && j < max_len) flow->host_server_name[j++] = '.';	// replace the label length with dot, except the at first 

	  while(j < max_len && cl != 0) {
		u_int32_t shift;
		
		c = flow->packet.payload[off++];
		shift = ((u_int32_t) 1) << (c & 0x1f);
		flow->host_server_name[j++] = tolower((dns_validchar[c >> 5] & shift) ? c : '_');
		cl--;
      }
    }

    flow->host_server_name[j] = '\0';	
#endif	
    
    if(j > 0) {
      ndpi_protocol_match_result ret_match;

	  /* check for domain generation algorithm using */
      ndpi_check_dga_name(ndpi_struct, flow, (char*)flow->host_server_name);
      
      ret.app_protocol = ndpi_match_host_subprotocol(ndpi_struct, flow,
						     (char *)flow->host_server_name,
						     strlen((const char*)flow->host_server_name),
						     &ret_match,
						     NDPI_PROTOCOL_DNS);

      if(ret_match.protocol_category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
		flow->category = ret_match.protocol_category;

      if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN)
		ret.master_protocol = (d_port == 5355) ? NDPI_PROTOCOL_LLMNR : NDPI_PROTOCOL_DNS;
      else
		ret.master_protocol = NDPI_PROTOCOL_DNS;
    }

    /* Report if this is a DNS query or reply */
    flow->protos.dns.is_query = is_query;
	
	flow->protos.dns.num_queries = (u_int8_t)dns_header.num_queries;	// always set!
	
    if(is_query) {
      /* In this case we say that the protocol has been detected just to let apps carry on with their activities */
      ndpi_set_detected_protocol(ndpi_struct, flow, ret.app_protocol, ret.master_protocol);

      /* This is necessary to inform the core to call this dissector again */
      flow->check_extra_packets = 1;

      /* Don't use just 1 as in TCP DNS more packets could be returned (e.g. ACK). */
      flow->max_extra_packets_to_check = 5;
      flow->extra_packets_func = search_dns_again;
      return; /* The response will set the verdict */
    }

	flow->protos.dns.num_answers = (u_int8_t) (dns_header.num_answers + dns_header.authority_rrs + dns_header.additional_rrs);
  
#ifdef DNS_DEBUG
    NDPI_LOG_DBG2(ndpi_struct, "[num_queries=%d][num_answers=%d][reply_code=%u][rsp_type=%u][host_server_name=%s]\n",
		  flow->protos.dns.num_queries, flow->protos.dns.num_answers,
		  flow->protos.dns.reply_code, flow->protos.dns.rsp_type, flow->host_server_name
		  );
#endif

    if(flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
      /**
	 Do not set the protocol with DNS if ndpi_match_host_subprotocol() has
	 matched a subprotocol
      **/
      NDPI_LOG_INFO(ndpi_struct, "found DNS\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, ret.app_protocol, ret.master_protocol);
    } else {
      if((flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_DNS)
		|| (flow->packet.detected_protocol_stack[1] == NDPI_PROTOCOL_DNS))
		;
      else
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
  }
}

void init_dns_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("DNS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DNS,
				      ndpi_search_dns,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
