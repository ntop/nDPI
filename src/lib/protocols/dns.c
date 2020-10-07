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
		//printf("DBG(add_RR_elem_to_list): new item: %p\n",retList);	
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
			case DNS_TYPE_NS:
				if (rr->RData.NSDName) ndpi_free(rr->RData.NSDName);
				break;
			case DNS_TYPE_CNAME:
				if (rr->RData.CName) ndpi_free(rr->RData.CName);		
				break;
			case DNS_TYPE_SOA:
				if (rr->RData.SOA.MName) ndpi_free(rr->RData.SOA.MName);
				if (rr->RData.SOA.RName) ndpi_free(rr->RData.SOA.RName);
				break;		
			case DNS_TYPE_PTR:
				if (rr->RData.PTRDName) ndpi_free(rr->RData.PTRDName);		
				break;		
			case DNS_TYPE_HINFO:
				if (rr->RData.HINFO.cpu) ndpi_free(rr->RData.HINFO.cpu);		
				if (rr->RData.HINFO.os) ndpi_free(rr->RData.HINFO.os);		
				break;
			case DNS_TYPE_MX:
				if (rr->RData.MX.exchange) ndpi_free(rr->RData.MX.exchange);
				break;		
			case DNS_TYPE_TXT:
				if (rr->RData.TXT.txtData) ndpi_free(rr->RData.TXT.txtData);		
				break;
			case DNS_TYPE_RP:
				if (rr->RData.RP.mailbox) ndpi_free(rr->RData.RP.mailbox);
				if (rr->RData.RP.respPerson) ndpi_free(rr->RData.RP.respPerson);
				break;
			case DNS_TYPE_AFSDB:
				if (rr->RData.AFSDB.hostname) ndpi_free(rr->RData.AFSDB.hostname);		
				break;	
			case DNS_TYPE_LOC:
				break;
			case DNS_TYPE_SRVS:
				if (rr->RData.SRVS.service) ndpi_free(rr->RData.SRVS.service);
				if (rr->RData.SRVS.protocol) ndpi_free(rr->RData.SRVS.protocol);
				if (rr->RData.SRVS.target) ndpi_free(rr->RData.SRVS.target);
				break;
			case DNS_TYPE_NAPTR:
				if (rr->RData.NAPTR.flags) ndpi_free(rr->RData.NAPTR.flags);
				if (rr->RData.NAPTR.service) ndpi_free(rr->RData.NAPTR.service);
				if (rr->RData.NAPTR.regex) ndpi_free(rr->RData.NAPTR.regex);
				if (rr->RData.NAPTR.replacement) ndpi_free(rr->RData.NAPTR.replacement);
				break;
				
				//TODO: free all other field/structure
		};	
		ndpi_free(rr);
	}
}

// NB: if used again, check to set to NULL
void clear_dns_RR_list(struct dnsRRList_t **list, unsigned char bForward) {	
	//printf("DBG(clear_dns_RR_list): *currList=%p, bForward=%d \n",*currList,bForward);
	struct dnsRRList_t *currList=*list;
	while (currList!=NULL) {
		//printf("DBG(clear_dns_RR_list): currList=%p, item=%p \n",currList,currList->rrItem);
		free_dns_RR(currList->rrItem);
		struct dnsRRList_t* tmp= (bForward) ? currList->nextItem :  currList->prevItem;
		// currList->nextItem=currList->prevItem=NULL;	
		//printf("DBG(clear_dns_RR_list): delete item: %p\n",currList);
		ndpi_free( currList );
		currList= tmp;		
	}
	*list=NULL;
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
  u_int16_t len=0,retLen=0;
   //printf("DBG(getNameLength): off=%d/%d\n",i,payloadLen);
  if(i >= payloadLen) {
    /* Error / Bad packet */
    return(-1);
  } else if(payload[i] == 0x00)
    return(0);
  else if ((payload[i] & 0xc0) != 0) {
	u_int16_t noff = payload[i+1];	// jump to new position
	 //printf("DBG(getNameLength): new off(LO)=%d\n",noff);
	 //printf("DBG(getNameLength): new off(HI)=%d\n",((payload[i] & 0x3f)<<8));
	noff += ((payload[i] & 0x3f)<<8);
	 //printf("DBG(getNameLength): jump to pos=%d\n",noff);
    retLen=getNameLength(noff, payload, payloadLen);
	 //printf("DBG(getNameLength): returned c0 len=%d\n",retLen);
	return (retLen);
  } else {
    len = payload[i]+1;	// word length and dot or termination char
    u_int16_t off = len; // new offset 
	 //printf("DBG(getNameLength): curr len=%d\n",len);

    // if(off == 0) /* Bad packet */
    //   return(0);
    // else {
	   //printf("DBG(getNameLength): delta len=%d\n",len);

	  retLen=getNameLength(i+off, payload, payloadLen);
	  //printf("DBG(getNameLength): returned len=%d\n",retLen);
	  return (len + retLen);
	  
	//}      
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
	static uint8_t wd=0;	// watchdog 
	u_int j= 0, off, cloff= 0, data_len, tmpv;
	
	//printf("DBG(parseDnsName)\n");
	
	//printf("DBG(parseDnsName) initial offset: %d\n",*i);
	off=(u_int)*i;
	data_len= getNameLength(off, payload, payloadLen);
	//printf("DBG(parseDnsName): len %d, space: %d\n",data_len,max_len);
	
	u_char *dnsName= ndpi_calloc(data_len+1,sizeof(u_char));
	if ( return_field && dnsName) {
		
		while(j < data_len && off < payloadLen && payload[off] != '\0') {
		  uint8_t c, cl = payload[off++];	//init label counter

		  //printf("DBG(parseDnsName): j/tot: %d/%u, off: %d, value: %02Xh %c\n",j, data_len, off, cl, cl);
		  if( (cl & 0xc0) != 0 ) {
			cloff=(cloff)?cloff:off+1;		// save return offset, first time

			 //printf("DBG(getNameLength): new off(HI)=%d\n",(cl & 0x3f)<<8);
			 //printf("DBG(getNameLength): new off(LO)=%d\n",payload[off]);	 		 
			tmpv= ( (cl & 0x3f)<<8) + payload[off++];			// change offset
			off = tmpv;
			//printf("DBG(parseDnsName): saved offset %d for jump to new off: %d\n",cloff, off);
			if ((++wd)>=250) {
				// used to exit when the parsing loops!!
				printf("ERR(parseDnsName): parsing: %.*s, j/tot: %d/%u, off: %d, value: %02Xh %c\n", data_len, dnsName, j, data_len, off, cl, cl);		  
				wd=0; 
				return;
			}
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
			//printf("DBG(parseDnsName): offset iniziale: (%d), len:[%d] ? c0_inc_offset:[%d]\n", *i, j, cloff);
			*i= (cloff)?cloff:(j+2+*i);
			strncpy((char*)return_field,(char*)dnsName,j);
			//printf("DBG(parseDnsName): result: (%d) [%s]; new offset:[%d]\n", j, dnsName, *i);
		}
	}
	else if (return_field==NULL && max_len==0) {
		// it could be the case of dns name with 0 length, increment pointer
		(*i)++;
	}
	else
		printf("ERR: input pointer [%p] or failed to allocate memory.\n",return_field);
	
	//printf("DBG(parseDnsName) final offset: %d\n",*i);
	
	ndpi_free(dnsName);	// free memory
	wd=0;
}


/* *********************************************** */

/**
 * this function search for the length of dns name; if finds it and parameters are set, try to allocate memory and return length
 * if there is a packet malformed error, return immediately (-1)
 * if the problem is the memory allocation, set error flag and continue...checking 
 * if it can return the length of dns name, set it before 
 * return the error condition (0=success)
 */
uint8_t checkDnsNameAndAllocate(u_int off, const u_int8_t *payload, const u_int payloadLen, 
								char **pName, size_t *ret_name_len, uint8_t *packetError, 
								const char* labelDnsName) {

	uint8_t error_flag=0;
	if (packetError!=NULL) *packetError=0;	// reset error flag
	
	if ( off<0 || payloadLen<0 || payload==NULL ) {
		printf("ERR(checkDnsNameAndAllocate): invalid input parameters %s: off:%u, lenp: %u, p:%p\n", 
			(labelDnsName!=NULL)?labelDnsName:"", off, payloadLen, payload);
		return -1;	// invalid parameters
	}

	size_t name_len = getNameLength(off, payload, payloadLen);
	if ( name_len<0 ) {
		// error retrieving dns name length
		if (packetError!=NULL) *packetError=1;
		printf("ERR(checkDnsNameAndAllocate): error retrieving dns name %s\n", (labelDnsName!=NULL)?labelDnsName:"");
		return -2;
	}
	
	if( pName!=NULL ) {		
		if ( name_len>0 ) {
			*pName = ndpi_calloc( name_len, sizeof(char) );
			if ( *pName==NULL ) {
				// failed to allocate memory
				printf("ERR(checkDnsNameAndAllocate): fail to allocate memory for dns name %s\n", (labelDnsName!=NULL)?labelDnsName:"");
				error_flag=-3;
			}
		}
		else 
			*pName=NULL; // 0 length name is ok		
	}  
		
	if (ret_name_len!=NULL) {
		*ret_name_len= name_len;
	}

	//printf("DBG(checkDnsNameAndAllocate): OK retrieving dns name %s; err=%d\n", (labelDnsName!=NULL)?labelDnsName:"", error_flag);
	return error_flag;	// success
}


/*
	scan and parse a RR section (Answer,Authority,Additional) of DNS packet
	increment the offset in the payload, after the last rr record successfully parsed

*/
struct dnsRRList_t *parseDnsRRs(u_int8_t nitems, int *i, 
		const u_int8_t *payload, const u_int payloadLen, u_int *notfound, struct ndpi_flow_struct *flow ) {
	
	struct dnsRRList_t *retRRList=NULL, *lastRRListItem=NULL;
	u_int k=0, off= (u_int)*i; // init offset 
	
	//printf("DBG(parseDnsRRs): off initialized = %u\n", off);
	
	for ( k=0; k<nitems; k++) {	
		//printf("DBG(parseDnsRRs): next record start at offset=%u\n", off);
		struct dnsRR_t *currItem= ndpi_calloc( 1, sizeof(struct dnsRR_t) ); 
		if ( currItem ) {
			size_t data_len;
			uint8_t malformed;	// set to 1, for malformed packet error
			char *pstr,*tmpstr;				
			//printf("DBG(parseDnsRRs): extracting data of item no. %d/%d \n",(k+1),nitems);

			/* parse the rrName */
			if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->rrName, &data_len, &malformed, "[rrName]") ) {
				parseDnsName( (u_char*)currItem->rrName, data_len, (int*)&off, payload, payloadLen );
				//printf("DBG(parseDnsRRs): rrName: [%p] (%u) %s\n",currItem->rrName,(u_int)data_len,currItem->rrName);
			} else  {
				printf("ERR(parseDnsRRs): dns name retrieving error: RR NAME \n");
				if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
				ndpi_free(currItem);
				break;
			}
			
			currItem->rrType =  get16((int*)&off, payload); 						// resource type
			currItem->rrClass = get16((int*)&off, payload); 						// class of the resource record
			currItem->rrTTL= get32((int*)&off, payload);							// cache time to live			
			currItem->rrRDL= get16((int*)&off, payload);							// resource data length
			
			int offsaved= off;	// used to mark this offset

			//printf("DBG(parseDnsRRs): type:%u, class:%u, ttl:%u, RDlen: %u\n",currItem->rrType,currItem->rrClass,currItem->rrTTL,currItem->rrRDL);
			switch(currItem->rrType) {
				
				case DNS_TYPE_A:
					memcpy(&currItem->RData.addressIP, &payload[off], sizeof(uint32_t));
					//printf("DBG(parseDnsRRs): A [%p]\n",&currItem->RData.addressIP);
					off+=4;
					break;
				
				case DNS_TYPE_NS:
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.NSDName, &data_len, &malformed, "[NSDName]") ) {
						parseDnsName( (u_char*)currItem->RData.NSDName, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): NS: (%u) %s\n",(u_int)data_len,currItem->RData.NSDName);
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: NS DName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					break;
				
				case DNS_TYPE_CNAME:
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.CName, &data_len, &malformed, "[CName]") ) {
						parseDnsName( (u_char*)currItem->RData.CName, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): CNAME: (%u) %s\n",(u_int)data_len,currItem->RData.CName);
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: CName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 				
					}
					break;
				
				case DNS_TYPE_SOA:
					// extract SOA Master name
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.SOA.MName, &data_len, &malformed, "[SOA.MName]") ) {
						parseDnsName( (u_char*)currItem->RData.SOA.MName, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): SOA.MName: (%u) %s\n",(u_int)data_len, currItem->RData.SOA.MName);
						//TODO: must manage the @ on the first dot.
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: SOA.MName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					} 
					
					// extract SOA Responsible name
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.SOA.RName, &data_len, &malformed, "[SOA.RName]") ) {
						parseDnsName( (u_char*)currItem->RData.SOA.RName, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): SOA.RName: (%u) %s\n",(u_int)data_len,currItem->RData.SOA.RName);
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: SOA.RName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);

						ndpi_free(currItem->RData.SOA.MName);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					} 
					
					currItem->RData.SOA.Serial= get32((int*)&off, payload); 	// serial
					currItem->RData.SOA.Refresh= get32((int*)&off, payload); 	// refresh
					currItem->RData.SOA.Retry= get32((int*)&off, payload); 		// retry
					currItem->RData.SOA.Expire= get32((int*)&off, payload); 	// expire
					currItem->RData.SOA.Minimum= get32((int*)&off, payload); 	// minimum
					break;

				case DNS_TYPE_RP:
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.RP.mailbox, &data_len, &malformed, "[RP mailbox]") ) {
						parseDnsName( (u_char*)currItem->RData.RP.mailbox, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): RP mailbox: (%u) %s\n",(u_int)data_len,currItem->RData.RP.mailbox);	
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: RP mailbox\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);

						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					} 					

					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.RP.respPerson, &data_len, &malformed, "[RP respPerson]") ) {
						parseDnsName( (u_char*)currItem->RData.RP.respPerson, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): RP respPerson: (%u) %s\n",(u_int)data_len,currItem->RData.RP.respPerson);	
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: RP respPerson\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);

						ndpi_free(currItem->RData.RP.mailbox);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					} 
					break;

				case DNS_TYPE_PTR:
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.PTRDName, &data_len, &malformed, "[PTRDName]") ) {
						parseDnsName( (u_char*)currItem->RData.PTRDName, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): PTR: (%u) %s\n",(u_int)data_len,currItem->RData.PTRDName);	
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: PTR DName\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);

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
					} else {
						printf("ERR(parseDnsRRs): fail to allocate memory for HINFO.cpu\n");
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}

					currItem->RData.HINFO.os_len= payload[off++];
					//printf("DBG(parseDnsRRs): DNS_TYPE_HINFO os len: %d\n",currItem->RData.HINFO.os_len);
					currItem->RData.HINFO.os= ndpi_calloc(currItem->RData.HINFO.os_len+1, sizeof(char));
					if (currItem->RData.HINFO.os) {
						memcpy(currItem->RData.HINFO.os, &payload[off],currItem->RData.HINFO.os_len);
						off+=currItem->RData.HINFO.os_len;
						//printf("DBG(parseDnsRRs): DNS_TYPE_HINFO: os: (%d) [%s]\n", currItem->RData.HINFO.os_len, currItem->RData.HINFO.os);
					} else {
						printf("ERR(parseDnsRRs): fail to allocate memory for HINFO.os\n");
						ndpi_free(currItem->RData.HINFO.cpu);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					break;
					
				case DNS_TYPE_MX:
					currItem->RData.MX.preference= get16((int*)&off, payload); 
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.MX.exchange, &data_len, &malformed, "[MX]") ) {
						parseDnsName( (u_char*)currItem->RData.MX.exchange, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): MX: (%u) %s - Pref: %d\n",(u_int)data_len,currItem->RData.MX.exchange,currItem->RData.MX.preference);
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: MX\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					break;
				
				case DNS_TYPE_TXT:
					currItem->RData.TXT.txt_len=payload[off++];
					if( currItem->RData.TXT.txt_len>0) {
						currItem->RData.TXT.txtData= ndpi_calloc((1+currItem->RData.TXT.txt_len), sizeof(char));
						if (currItem->RData.TXT.txtData) {
							strncpy(currItem->RData.TXT.txtData, (char*)&payload[off], currItem->RData.TXT.txt_len);
							currItem->RData.TXT.txtData[currItem->RData.TXT.txt_len]='\0';
							//printf("DBG(parseDnsRRs): TXT [(%u) %s]\n",currItem->RData.TXT.txt_len,currItem->RData.TXT.txtData);
							off+= currItem->RData.TXT.txt_len;
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for TXT [ ]\n");
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}
					} 
					else currItem->RData.TXT.txtData= NULL; 
					break;
				
				case DNS_TYPE_AFSDB:
					//printf("DBG(parseDnsRRs): DNS_TYPE_AFSDB: len: %d\n",currItem->rrRDL);
					currItem->RData.AFSDB.subtype= get16((int*)&off, payload); 
					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.AFSDB.hostname, &data_len, &malformed, "[AFSDBHOST]") ) {
						parseDnsName( (u_char*)currItem->RData.AFSDB.hostname, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): MX: (%u) %s - Pref: %d\n",(u_int)data_len,currItem->RData.MX.exchange,currItem->RData.MX.preference);
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: AFSDB HOST\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					break;
					
				case DNS_TYPE_AAAA:
					memcpy(&currItem->RData.addressIPv6, &payload[off], currItem->rrRDL);
					//printf("DBG(parseDnsRRs): AAAA [%p]\n",&currItem->RData.addressIPv6);
					off+=16;
					break;

				case DNS_TYPE_LOC:
					//printf("DBG(parseDnsRRs): DNS_TYPE_LOC len: %d\n",currItem->rrRDL);
					currItem->RData.LOC.version= payload[off++];					
					currItem->RData.LOC.size= payload[off++];
					currItem->RData.LOC.hprecs= payload[off++];
					currItem->RData.LOC.vprecs= payload[off++];
					currItem->RData.LOC.latit= get32((int*)&off, payload);
					currItem->RData.LOC.longit= get32((int*)&off, payload);
					currItem->RData.LOC.alt= get32((int*)&off, payload);
					/*printf("DBG(parseDnsRRs): DNS_TYPE_LOC: vers:%d, size:%d, H-prex:%d, V-prex:%d, LAT:%u, LONG:%u, ALT:%u\n",
								currItem->RData.LOC.version, currItem->RData.LOC.size,
								currItem->RData.LOC.hprecs,	currItem->RData.LOC.vprecs,
								currItem->RData.LOC.latit, currItem->RData.LOC.longit, currItem->RData.LOC.alt);*/
					if (currItem->RData.LOC.version) {
						// if version 0 ok, otherwise the dissector can fail...
						// so restore the offset for error
						off = offsaved+ currItem->rrRDL;	
					}
					break;
					
				case DNS_TYPE_SRVS:
					//printf("DBG(parseDnsRRs): DNS_TYPE_SRVS:\n");
					data_len= strlen(currItem->rrName);
					tmpstr= ndpi_calloc(data_len+1,sizeof(char));
					if (tmpstr!=NULL) {
						strncpy(tmpstr,currItem->rrName,data_len);
						pstr= strtok(tmpstr,".");
						if ( pstr!=NULL) {
							data_len= strlen(pstr);
							if ( data_len>0 ) {
								currItem->RData.SRVS.service= ndpi_calloc(data_len+1, sizeof(char));
								if ( currItem->RData.SRVS.service ) {
									strncpy(currItem->RData.SRVS.service,pstr,data_len);
									//printf("DBG(parseDnsRRs): SRVS service: (%u) %s \n",(u_int)data_len,currItem->RData.SRVS.service);	
								} else {
									printf("ERR(parseDnsRRs): fail to allocate memory for SRVS:service \n");
									ndpi_free(tmpstr);
									ndpi_free(currItem->rrName);
									ndpi_free(currItem);
									return NULL; 
								}
							}
							else currItem->RData.SRVS.service= NULL;
						}
						pstr= strtok(NULL,".");
						if ( pstr!=NULL) {
							data_len= strlen(pstr);
							if ( data_len>0 ) {
								currItem->RData.SRVS.protocol= ndpi_calloc(data_len+1, sizeof(char));
								if ( currItem->RData.SRVS.protocol ) {
									strncpy(currItem->RData.SRVS.protocol,pstr,data_len);
									//printf("DBG(parseDnsRRs): SRVS protocol: (%u) %s\n",(u_int)data_len,currItem->RData.SRVS.protocol);
								} else {
									printf("ERR(parseDnsRRs): fail to allocate memory for SRVS:protocol \n");
									ndpi_free(currItem->RData.SRVS.service);
									ndpi_free(tmpstr);
									ndpi_free(currItem->rrName);
									ndpi_free(currItem);
									return NULL; 
								}
							} 
							else currItem->RData.SRVS.protocol= NULL;
						}
						ndpi_free(tmpstr);
					} else {
						printf("ERR(parseDnsRRs): fail to allocate memory for parsing rrName (service,protocol) \n");
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					}
					currItem->RData.SRVS.priority= get16((int*)&off, payload);
					currItem->RData.SRVS.weight= get16((int*)&off, payload);
					currItem->RData.SRVS.port= get16((int*)&off, payload);
					//printf("DBG(parseDnsRRs): SRVS: priority: %u, weight: %u, port: %u, \n",(u_int)currItem->RData.SRVS.priority,currItem->RData.SRVS.weight,currItem->RData.SRVS.port);	

					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.SRVS.target, &data_len, &malformed, "[SRVSTARGET]") ) {
						parseDnsName( (u_char*)currItem->RData.SRVS.target, data_len, (int*)&off, payload, payloadLen );
						//printf("DBG(parseDnsRRs): SRVS target: (%u) %s\n",(u_int)data_len,currItem->RData.SRVS.target);
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: SRVS TARGET\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->RData.SRVS.protocol);
						ndpi_free(currItem->RData.SRVS.service);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						return NULL; 
					} 
					break;

				case DNS_TYPE_NAPTR:
					//printf("DBG(parseDnsRRs): DNS_TYPE_NAPTR:\n");					
					currItem->RData.NAPTR.order= get16((int*)&off, payload);
					currItem->RData.NAPTR.preference= get16((int*)&off, payload);
					//printf("DBG(parseDnsRRs): NAPTR order: %u, preference: %u\n",currItem->RData.NAPTR.order,currItem->RData.NAPTR.preference);

					currItem->RData.NAPTR.flags_len= payload[off++];
					if (currItem->RData.NAPTR.flags_len>0) {
						currItem->RData.NAPTR.flags= ndpi_calloc(currItem->RData.NAPTR.flags_len+1, sizeof(char));
						if ( currItem->RData.NAPTR.flags ) {
							memcpy(currItem->RData.NAPTR.flags,&payload[off],currItem->RData.NAPTR.flags_len);
							off+=currItem->RData.NAPTR.flags_len;
							//printf("DBG(parseDnsRRs): NAPTR flags: (%u) %p ->[%02X]\n",(u_int)currItem->RData.NAPTR.flags_len,currItem->RData.NAPTR.flags,*currItem->RData.NAPTR.flags);
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for NAPTR:flags \n");
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}
					}
					else currItem->RData.NAPTR.flags=NULL;

					currItem->RData.NAPTR.service_len= payload[off++];
					if (currItem->RData.NAPTR.service_len>0) {
						currItem->RData.NAPTR.service= ndpi_calloc(1+currItem->RData.NAPTR.service_len, sizeof(char));
						if ( currItem->RData.NAPTR.service ) {
							memcpy(currItem->RData.NAPTR.service,&payload[off],currItem->RData.NAPTR.service_len);
							off+=currItem->RData.NAPTR.service_len;
							//printf("DBG(parseDnsRRs): NAPTR service: (%u) %p ->[%02X]\n",(u_int)currItem->RData.NAPTR.service_len,currItem->RData.NAPTR.service,*currItem->RData.NAPTR.service);
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for NAPTR:service \n");
							ndpi_free(currItem->RData.NAPTR.flags);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}
					}
					else currItem->RData.NAPTR.service=NULL;

					currItem->RData.NAPTR.re_len= payload[off++];
					if (currItem->RData.NAPTR.re_len>0) {
						currItem->RData.NAPTR.regex= ndpi_calloc(currItem->RData.NAPTR.re_len+1, sizeof(char));
						if ( currItem->RData.NAPTR.regex ) {
							memcpy(currItem->RData.NAPTR.regex,&payload[off],currItem->RData.NAPTR.re_len);
							off+=currItem->RData.NAPTR.re_len;
							//printf("DBG(parseDnsRRs): NAPTR regex: (%u) %p ->[%02X]\n",(u_int)currItem->RData.NAPTR.re_len,currItem->RData.NAPTR.regex,*currItem->RData.NAPTR.regex);
						} else {
							printf("ERR(parseDnsRRs): fail to allocate memory for NAPTR:regex \n");
							ndpi_free(currItem->RData.NAPTR.flags);
							ndpi_free(currItem->RData.NAPTR.service);
							ndpi_free(currItem->rrName);
							ndpi_free(currItem);
							return NULL; 
						}
					}
					else currItem->RData.NAPTR.regex= NULL;


					if ( !checkDnsNameAndAllocate(off, payload, payloadLen, &currItem->RData.NAPTR.replacement, &data_len, &malformed, "[NAPTRreplacement]") ) {
						parseDnsName( (u_char*)currItem->RData.NAPTR.replacement, data_len, (int*)&off, payload, payloadLen );
						currItem->RData.NAPTR.re_replace_len=data_len-1;
						//printf("DBG(parseDnsRRs): NAPTR replacement: (%u) %s\n",(u_int)data_len,currItem->RData.NAPTR.replacement);
					} else  {
						printf("ERR(parseDnsRRs): dns name retrieving error: NAPTR:replacement\n");
						if (malformed) NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
						ndpi_free(currItem->RData.NAPTR.flags);
						ndpi_free(currItem->RData.NAPTR.service);
						ndpi_free(currItem->RData.NAPTR.regex);
						ndpi_free(currItem->rrName);
						ndpi_free(currItem);
						break;
					}

					off = offsaved+ currItem->rrRDL;	// restore the offset for error
					break;
					
				case DNS_TYPE_AXFR:
					//memcpy(&currItem->RData.addressIPv6, &payload[off], currItem->rrRDL);
					//printf("DBG(parseDnsRRs): AFXR \n");
					off+=16;
					break;
								
				default:
					printf("RR type: [%02X] not managed (ID:%u]).\n",currItem->rrType, flow->protos.dns.tr_id);
			}
			
			// fill the list
			if ( retRRList ) {
				lastRRListItem= add_RR_elem_to_list(lastRRListItem, currItem);
				if (!lastRRListItem) {
					//ERR
					printf("ERR: failed to add a new element [%s], type:%u, class:%u, ttl:%u, RDlen: %u.\n",
							currItem->rrName,currItem->rrType,currItem->rrClass,currItem->rrTTL,currItem->rrRDL);
					
					clear_dns_RR_list(&retRRList,1);
					free_dns_RR(currItem);
					return NULL;
				}
			} else {
				// list empty: first item
				retRRList= add_RR_elem_to_list(NULL, currItem);
				lastRRListItem= retRRList;
			}
		}
		else 
			printf("ERR(parseDnsRRs): fail to allocate memory for a RR.\n");
		
		//printf("DBG(parseDnsRRs): end of parsing of RR.\n");
	}

	*notfound=nitems-k;	// returns the number of not found

	// if the numbert of retrieved items, is not equal to those waited: not valid packet!!
	if (*notfound>0) {
		printf("ERR(parseDnsRRs): missing %u RR parsing the section!\n", *notfound);
		NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
	}

	*i=off;
	//printf("DBG(parseDnsRRs): returning result=%u, offset=%u, list=%p\n", *notfound,*i, retRRList);
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
 
  //printf("DBG(search_valid_dns): #%02Xh, counters: [%d,%d,%d,%d], flags: %04Xh\n",dns_header->tr_id, dns_header->num_queries, dns_header->num_answers, dns_header->authority_rrs, dns_header->additional_rrs,dns_header->flags);
  
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
	flow->protos.dns.dns_request_complete=0;
	flow->protos.dns.dns_response_complete=0;
	// printf("DBG(search_valid_dns): query processing. \n");
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
			flow->protos.dns.dns_request_complete=1;
			flow->protos.dns.dns_request_seen=flow->protos.dns.dns_request_print=0;
			//printf("DBG(search_valid_dns): query processed and complete. \n");
			break;
		} else
	  		x++;
      }

    } else {
	  printf("DBG(search_valid_dns):malformed/risky? \n");
      NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
      return(1 /* invalid */);
    }
  } else {
	//printf("DBG(search_valid_dns): response processing. \n");
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
	
	  u_int notfound = 1;
      if(dns_header->num_answers > 0) {
		flow->protos.dns.dns_response_complete=1;	// response headers complete!

#ifdef __DNS_H__
		
		//printf("DBG(search_valid_dns): parsing RR records... \n");

	  	/* WARNING: if there is a flow active it need to free allocated memory! */
		flow->protos.dns.dnsAnswerRRList= parseDnsRRs(dns_header->num_answers,&x,flow->packet.payload,flow->packet.payload_packet_len, &notfound, flow);
		//printf("DBG(search_valid_dns): parsing RR answer done... \n");
		flow->protos.dns.dns_response_complete &= !(notfound>0);

		// for compatibility with previous code, set the following variables with the first answer
		struct dnsRRList_t* currList = flow->protos.dns.dnsAnswerRRList;
		while ( currList!=NULL ) {
			struct dnsRR_t* firstRR = currList->rrItem;
			if (firstRR) {
				flow->protos.dns.rsp_type= firstRR->rrType;
				flow->protos.dns.query_class= firstRR->rrClass;

				 ndpi_check_dns_type(ndpi_struct, flow, firstRR->rrType);
				
				if ( (((firstRR->rrType == 0x1) && (firstRR->rrRDL == 4)) /* A */
#ifdef NDPI_DETECTION_SUPPORT_IPV6
					|| ((firstRR->rrType == 0x1c) && (firstRR->rrRDL == 16)) /* AAAA */
#endif
				)) {
					memcpy(&flow->protos.dns.rsp_addr, &firstRR->RData, firstRR->rrRDL);
					break;
				}					
			}
			currList = currList->nextItem;
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

	  rsp_type = get16(&x, flow->packet.payload);

#ifdef DNS_DEBUG
	  printf("[DNS] [response] response_type=%d\n", rsp_type);
#endif

	  ndpi_check_dns_type(ndpi_struct, flow, rsp_type);
	  
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

	  if(dns_header->authority_rrs > 0) {
		flow->protos.dns.dnsAuthorityRRList= parseDnsRRs(dns_header->authority_rrs,&x, flow->packet.payload, flow->packet.payload_packet_len, &notfound,flow);
		flow->protos.dns.dns_response_complete &= !(notfound>0);
		//printf("DBG(search_valid_dns): parsing RR authority done... \n");
	  } else
		  flow->protos.dns.dnsAuthorityRRList= NULL;
		
	  if(dns_header->additional_rrs > 0) {
		flow->protos.dns.dnsAdditionalRRList= parseDnsRRs(dns_header->additional_rrs,&x, flow->packet.payload, flow->packet.payload_packet_len, &notfound,flow);
		flow->protos.dns.dns_response_complete &= !(notfound>0);
		//printf("DBG(search_valid_dns): parsing RR additional done... \n");
	  } else
		  flow->protos.dns.dnsAdditionalRRList= NULL;	
		  
#endif
     //printf("DBG(search_valid_dns): packet processed. \n");
	 flow->protos.dns.dns_response_seen=flow->protos.dns.dns_response_print=0;

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
	//printf("DBG(search_valid_dns): response processed. \n");
  }

  //printf("DBG(search_valid_dns): exiting req:%d, resp:%d. \n",flow->protos.dns.dns_request_complete,flow->protos.dns.dns_response_complete);

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

void init_dns_tcp_memory(struct ndpi_flow_struct *flow) {
	message_t *dns_segments_buf = &(flow->l4.tcp.dns_segments_buf[flow->packet.packet_direction]);	
	if (dns_segments_buf->buffer) free(dns_segments_buf->buffer);
	dns_segments_buf->buffer=NULL;
	dns_segments_buf->buffer_used=dns_segments_buf->buffer_len=dns_segments_buf->max_expected=0;
	//printf("DBG(init_dns_tcp_memory): dns buffer initialized\n");
}

void ndpi_search_dns_tcp_memory(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  message_t *dns_segments_buf = &(flow->l4.tcp.dns_segments_buf[packet->packet_direction]);

  /* TCP */
#ifdef DEBUG_DNS_MEMORY
  printf("[DNS Mem] Handling TCP/DNS flow [payload_len: %u][buffer_len: %u][direction: %u]\n",
	 packet->payload_packet_len,
	 dns_segments_buf->buffer_len,
	 packet->packet_direction);
#endif
  
  //printf("DBG(ndpi_search_dns_tcp_memory): buffer[dir:%d]: %p\n", packet->packet_direction,dns_segments_buf->buffer);

  if(dns_segments_buf->buffer == NULL) {
    /* Allocate buffer */
    dns_segments_buf->buffer_len = 2048, dns_segments_buf->buffer_used = 0;
    dns_segments_buf->buffer = (u_int8_t*)ndpi_calloc(dns_segments_buf->buffer_len, sizeof(u_int8_t));
	//printf("DBG(ndpi_search_dns_tcp_memory): allocated %d bytes -> %p\n", dns_segments_buf->buffer_len,dns_segments_buf->buffer);
 
    if(dns_segments_buf->buffer == NULL) {
      dns_segments_buf->buffer_len = 0;
      return;
    }
	
#ifdef DEBUG_DNS_MEMORY
    printf("[DNS Mem] Allocating %u buffer\n", dns_segments_buf->buffer_len);
#endif
  }

  if(flow->packet.tcp != NULL 
	&& packet->payload_packet_len>2 
	&& dns_segments_buf->buffer_used == 0) {
		int off=0;
		// only tcp and the first time!!
		dns_segments_buf->max_expected = get16(&off, packet->payload);
  }

  u_int avail_bytes = dns_segments_buf->buffer_len - dns_segments_buf->buffer_used;
  if(avail_bytes < packet->payload_packet_len) {
    u_int new_len = dns_segments_buf->buffer_len + packet->payload_packet_len+1;
    void *newbuf  = ndpi_realloc(dns_segments_buf->buffer, dns_segments_buf->buffer_len, new_len);
    //void *newbuf  = realloc(dns_segments_buf->buffer, new_len);
    if(!newbuf) return;

#ifdef DEBUG_DNS_MEMORY
    printf("[DNS Mem] Enlarging %u -> %u buffer\n", dns_segments_buf->buffer_len, new_len);
#endif

    dns_segments_buf->buffer = (u_int8_t*)newbuf, 
	dns_segments_buf->buffer_len = new_len;
    avail_bytes = dns_segments_buf->buffer_len - dns_segments_buf->buffer_used;
  }

  if(avail_bytes >= packet->payload_packet_len) {
    memcpy(&dns_segments_buf->buffer[dns_segments_buf->buffer_used],
	    packet->payload, packet->payload_packet_len);

    dns_segments_buf->buffer_used += packet->payload_packet_len;
    
    //printf("DBG(ndpi_search_dns_tcp_memory): DNS added: %d bytes to buffer[%d]: %u/%u; limit:%u\n", packet->payload_packet_len,packet->packet_direction,dns_segments_buf->buffer_used,dns_segments_buf->buffer_len, dns_segments_buf->max_expected);
#ifdef DEBUG_DNS_MEMORY
    printf("[DNS Mem] Copied data to buffer [%u/%u bytes]\n",
	   dns_segments_buf->buffer_used, dns_segments_buf->buffer_len);
#endif     
  }
}

static u_int8_t *oldPayload= NULL;
static u_int16_t oldPayloadLen= 0;

static void savePacketPayload(struct ndpi_flow_struct *flow) {
	oldPayload= (u_int8_t *) flow->packet.payload;
	oldPayloadLen= flow->packet.payload_packet_len;
	//printf("DBG(savePacketPayload): saved: p:%p len:%u\n", oldPayload, oldPayloadLen);
}
static void restorePacketPayload(struct ndpi_flow_struct *flow, u_int8_t fInitBuffer) {
	flow->packet.payload= oldPayload;
	flow->packet.payload_packet_len= oldPayloadLen;
	//printf("DBG(restorePacketPayload): restored: p:%p len:%u\n", oldPayload, oldPayloadLen);
	if ( fInitBuffer ) init_dns_tcp_memory(flow);
}
static u_int8_t swap_packet_ref(struct ndpi_flow_struct *flow, int *ploff) {
	//printf("DBG(swap_packet_ref): off:%d\n", *ploff);
	message_t *dns_segments_buf = &(flow->l4.tcp.dns_segments_buf[flow->packet.packet_direction]);
	
	if (dns_segments_buf->buffer==NULL) return 1;	// proceeds without buffer

	flow->packet.payload= &dns_segments_buf->buffer[*ploff];
	flow->packet.payload_packet_len= dns_segments_buf->buffer_used - *ploff;
	*ploff= 0;
	//printf("DBG(swap_packet_ref): set packet payload as p:%p (len:%u bytes); offs:%d; rec:%u; exp:%u\n",		flow->packet.payload,flow->packet.payload_packet_len,*ploff,		dns_segments_buf->buffer_used,dns_segments_buf->max_expected);

	return (dns_segments_buf->buffer_used>=dns_segments_buf->max_expected);
}

/* *********************************************** */

static void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	int payload_offset;
	u_int8_t is_query;
	u_int16_t s_port = 0, d_port = 0;

	// init the temp variables
	oldPayload=NULL;
	oldPayloadLen= 0;

  	NDPI_LOG_DBG(ndpi_struct, "search DNS\n");

	if(flow->packet.udp != NULL) {
		s_port = ntohs(flow->packet.udp->source);
		d_port = ntohs(flow->packet.udp->dest);
		payload_offset = 0;
	} else if(flow->packet.tcp != NULL) /* pkt size > 512 bytes */ {
		s_port = ntohs(flow->packet.tcp->source);
		d_port = ntohs(flow->packet.tcp->dest);
		payload_offset = 2;	// skip the bytes of length
	} else {
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		return;
	}

  	//printf("DBG(ndpi_search_dns): s:%u - d:%u -> payload len: %u\n",s_port,d_port,flow->packet.payload_packet_len); 
  
  	if ((s_port == DNS_PORT) || (d_port == DNS_PORT) 
	  	|| (s_port == MDNS_PORT) || (d_port == MDNS_PORT) 
		|| (d_port == LLMNR_PORT)) {
	  
		// concatene the segments, if not retrasmission ---------
		if ( !flow->packet.tcp_retransmission ) {
			ndpi_search_dns_tcp_memory(ndpi_struct, flow);  
		} 
		// else //printf("DBG(ndpi_search_dns): ALERT: retrasmission!\n");

		// save and swap the pointer to buffer, instead of packet received bytes
		savePacketPayload(flow);
		
		// ------------------------------------------------------

		if ( swap_packet_ref(flow, &payload_offset)  // not yet received all expected bytes...
			  && flow->packet.payload_packet_len > sizeof(struct ndpi_dns_packet_header)+payload_offset) {
			
			struct ndpi_dns_packet_header dns_header;
			int j = 0, max_len, off;
			
			int invalid = search_valid_dns(ndpi_struct, flow, &dns_header, payload_offset, &is_query);
			//printf("DBG(ndpi_search_dns): check for invalid result=%d\n", invalid);
			
			ndpi_protocol ret;

			ret.master_protocol   = NDPI_PROTOCOL_UNKNOWN;
			ret.app_protocol      = (d_port == LLMNR_PORT) ? NDPI_PROTOCOL_LLMNR : ((d_port == MDNS_PORT) ? NDPI_PROTOCOL_MDNS : NDPI_PROTOCOL_DNS);

			if(invalid) {
				// restore packet pointers and free buffer
				restorePacketPayload(flow, 1);
				
				// because of checking every time all buffer, whether invalid exclude it from flow
				NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
				return;
			}

				/* extract host name server from 'question section' */
			max_len = sizeof(flow->host_server_name)-1;
			off = sizeof(struct ndpi_dns_packet_header) + payload_offset;
			
#ifdef __DNS_H__
			//printf("DBG(ndpi_search_dns): host_server_name max len: %d, offset: %u\n", max_len, off);
			parseDnsName( flow->host_server_name, max_len, (int*)&off, flow->packet.payload, flow->packet.payload_packet_len );	
			j = strlen((const char*)flow->host_server_name);

			//printf("DBG(ndpi_search_dns): len: %d, [%s]\n", j, flow->host_server_name);
#else
/* Before continuing let's dissect the following queries to see if they are valid */
    for(idx=off, num_queries=0; (num_queries < dns_header.num_queries) && (idx < flow->packet.payload_packet_len);) {
      u_int8_t name_len = flow->packet.payload[idx];

#ifdef DNS_DEBUG
      printf("[DNS] [name_len: %u]\n", name_len);
#endif

      if(name_len == 0) {
		/* End of query */
		num_queries++;
		idx += 5;
		continue;
      }

      if((name_len+idx) >= flow->packet.payload_packet_len) {
	/* Invalid */
#ifdef DNS_DEBUG
		printf("[DNS] Invalid query len [%u >= %u]\n",
			(name_len+idx),
	    	flow->packet.payload_packet_len);
#endif
		NDPI_SET_BIT(flow->risk, NDPI_MALFORMED_PACKET);
			break;
      	} else
			idx += name_len+1;
      	}			
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
				ndpi_check_dga_name(ndpi_struct, flow, (char*)flow->host_server_name,1);
				
				ret.app_protocol = ndpi_match_host_subprotocol(ndpi_struct, flow,
										(char *)flow->host_server_name,
										strlen((const char*)flow->host_server_name),
										&ret_match,
										NDPI_PROTOCOL_DNS);

				if(ret_match.protocol_category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
					flow->category = ret_match.protocol_category;

				if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN)
					ret.master_protocol = checkDNSSubprotocol(s_port, d_port);
				else
					ret.master_protocol = NDPI_PROTOCOL_DNS;
			}

			/* Report if this is a DNS query or reply */
			flow->protos.dns.is_query = is_query;
			
			flow->protos.dns.num_queries = (u_int8_t)dns_header.num_queries;	// always set!
			
			if(is_query) {
				//flow->protos.dns.dns_request_complete=1;
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
			//printf("DBG(ndpi_search_dns): detected prot: %d.%d\n", flow->packet.detected_protocol_stack[0],flow->packet.detected_protocol_stack[1]);
			if(flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
				/**
				 Do not set the protocol with DNS if ndpi_match_host_subprotocol() has
				matched a subprotocol
				**/
				NDPI_LOG_INFO(ndpi_struct, "found DNS\n");
				ndpi_set_detected_protocol(ndpi_struct, flow, ret.app_protocol, ret.master_protocol);
			} else {
				if((flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_DNS)
					|| (flow->packet.detected_protocol_stack[1] == NDPI_PROTOCOL_DNS)) {					
					// flow is ok, buffer contains all data, 
					// but do not free packet payload because it is managed in other part
				} else {
					// restore packet pointers and free buffer
					restorePacketPayload(flow, 1);					
					NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
				}
			}
	 	}

		// restore packet pointers for other dissectors
		restorePacketPayload(flow, 0);
  	}


	// but require other processing
  	flow->check_extra_packets = 1;

	/* Don't use just 1 as in TCP DNS more packets could be returned (e.g. ACK). */
	flow->max_extra_packets_to_check = 15;
	flow->extra_packets_func = search_dns_again;
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
