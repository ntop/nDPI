/*
 * btlib.c
 *
 * Copyright (C) 2011-15 - ntop.org
 *               Contributed by Vitaly Lavrov <vel21ripn@gmail.com>
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

#ifndef NDPI_NO_STD_INC
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>

typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned long long int u_int64_t;

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#endif

typedef signed long long int i_int64_t;

#include "btlib.h"

int bt_parse_debug = 0;

static char *printXb(char *s,const u_int8_t *b,int l) {
  int i;
  for(i=0; i < l; i++)
    snprintf(&s[i*2],41,"%02x",b[i]);
  return s;
}

static char *print20b(char *s,const u_int8_t *b) {
  snprintf(s,41,"%08x%08x%08x%08x%08x",
	   htonl(*(u_int32_t*)b),
	   htonl(*(u_int32_t*)(b+4)),
	   htonl(*(u_int32_t*)(b+8)),
	   htonl(*(u_int32_t*)(b+12)),
	   htonl(*(u_int32_t*)(b+16)));
  return s;
}

static char *print_id_ip_p(char *s, const struct bt_nodes_data *b) {
  u_int8_t *p = (void*)b;
  print20b(s,b->id);
  snprintf(s+40,39," %d.%d.%d.%d:%u",
	   p[20], p[21], p[22], p[23], htons(b->port));
  return s;
}

static char *print_ip_p(char *s, const struct bt_ipv4p *b,int np) {
  const u_int8_t *p = (const void*)b;
  snprintf(s,39,!np ? "%d.%d.%d.%d:%u":"%d.%d.%d.%d",
	   p[0], p[1], p[2], p[3], htons(b->port));
  return s;
}

static char *print_ip6_p(char *s, const struct bt_ipv6p *b,int np) {
  u_int16_t *p = (void*)b;
  snprintf(s,79,!np ? "%x:%x:%x:%x:%x:%x:%x:%x.%u":"%x:%x:%x:%x:%x:%x:%x:%x",
	   htons(p[0]), htons(p[1]), htons(p[2]), htons(p[3]),
	   htons(p[4]), htons(p[5]), htons(p[6]), htons(p[7]),
	   htons(b->port));
  return s;
}

static char *print_id_ip6_p(char *s,const struct bt_nodes6_data *b) {
  return print_ip6_p(s,(struct bt_ipv6p *)&b->ip,0);
}


void dump_bt_proto_struct(struct bt_parse_protocol *p) {
  char b20h[128];
  int i;

  if(p->y_e && p->e_msg)  {
    printf("Error %s/%u\n", p->e_msg, p->e_len);
  }
  if(p->y_q) {
    printf("Query ");
    if(p->q_ping) printf("ping\n");
    if(p->q_g_peers) printf("get_peers\n");
    if(p->q_f_node) printf("find_node\n");
    if(p->q_a_peer) printf("announce_peer\n");
  }
  if(p->y_r)
    printf("Reply\n");

  if(p->t) printf("\tt\t%llx\n",p->t);
  if(p->v) printf("\tv\t%llx\n",p->v);
  if(p->ip) printf("\tIP\t%s\n",print_ip_p(b20h,p->ip,0));

  if(p->a.port) printf("\tport\t%d\n",htons(p->a.port));
  if(p->a.id) printf("\tID\t%s\n",print20b(b20h,p->a.id));
  if(p->a.target) printf("\ttarget\t%s\n",print20b(b20h,p->a.target));
  if(p->a.token) printf("\ttoken\t%s\n",printXb(b20h,p->a.token,p->a.t_len));
  if(p->a.info_hash) printf("\ti_hash\t%s\n",print20b(b20h,p->a.info_hash));
  if(p->a.name && p->a.name_len) printf("\tname\t%.*s\n",p->a.name_len,p->a.name);

  if(p->r.ip) printf("\tip\t%s\n",print_ip_p(b20h,p->r.ip,1));
  if(p->r.port) printf("\tport\t%d\n",htons(p->r.port));
  if(p->r.id) printf("\tID\t%s\n",print20b(b20h,p->r.id));
  if(p->r.token) printf("\ttoken\t%s\n",printXb(b20h,p->r.token,p->r.t_len));
  if(p->r.name && p->r.name_len) printf("\tname\t%.*s\n",p->r.name_len,p->r.name);
  if(p->r.values && p->r.nv) {
    struct bt_ipv4p2 *n = (struct bt_ipv4p2 *)p->r.values;
    for(i=0;i < p->r.nv; i++,n++) {
      printf("\tvalues\t%s\n", print_ip_p(b20h,&n->d,0));
    }
  }
  if(p->r.values6 && p->r.nv6) {
    struct bt_ipv6p2 *n = (struct bt_ipv6p2 *)p->r.values6;
    for(i=0;i < p->r.nv6; i++,n++) {
      printf("\tvalues6\t%s\n", print_ip6_p(b20h,&n->d,0));
    }
  }
  if(p->r.nodes && p->r.nn) {
    for(i=0;i < p->r.nn; i++) {
      printf("\tnodes\t%s\n",print_id_ip_p(b20h,p->r.nodes+i));
    }
  }
  if(p->r.nodes6 && p->r.nn6) {
    for(i=0;i < p->r.nn6; i++) {
      printf("\tnodes6\t%s\n",print_id_ip6_p(b20h,p->r.nodes6+i));
    }
  }

  if(p->peers && p->n_peers) {
    for(i=0;i < p->n_peers; i++) {
      printf("\tpeers\t%s\n",print_ip_p(b20h,p->peers+i,0));
    }
  }

  if(p->interval) printf("\tinterval\t%d\n",p->interval);
  if(p->min_interval) printf("\tmin interval\t%d\n",p->min_interval);
}

static void _print_safe_str(char *msg,char *k,const u_int8_t *s,size_t l) {
  static const char *th="0123456789abcdef?";
  char *buf = (char*)ndpi_malloc((size_t)(l*3+2));

  int sl = l;
  if(buf) {
    char *b = buf;
    for(;l > 0; s++,l--) {
      if(*s < ' ' || *s >= 127) {
	*b++ = '%';
	*b++ = th[(*s >> 4)&0xf];
	*b++ = th[(*s)&0xf];
      } else *b++ = *s;
    }
    *b = 0;
  
    printf("%s %s %s len %d\n",msg,k,buf ? buf:"",sl);

    ndpi_free(buf);
  }
}

static void print_safe_str(char *msg,bt_parse_data_cb_t *cbd) {
  _print_safe_str(msg,cbd->buf,cbd->v.s.s,cbd->v.s.l);
}

#define DEBUG_TRACE(cmd) { if(bt_parse_debug) cmd; }
#define STREQ(a,b) !strcmp(a,b)


void cb_data(bt_parse_data_cb_t *cbd,int *ret) {
  struct bt_parse_protocol *p = &(cbd->p);
  const u_int8_t *s;
  const char *ss;

  if(cbd->t == 0)  return;

  if(cbd->t == 1) {

    DEBUG_TRACE(printf("%s %lld\n",cbd->buf,cbd->v.i));

    if(STREQ(cbd->buf,"a.port")) {
      p->a.port = (u_int16_t)(cbd->v.i & 0xffff);
      return;
    }
    if(
       STREQ(cbd->buf,"a.implied_port") ||
       STREQ(cbd->buf,"a.noseed") ||
       STREQ(cbd->buf,"a.scrape") ||
       STREQ(cbd->buf,"a.seed") ||
       STREQ(cbd->buf,"a.vote")
       ) {
      return;
    }
    if(STREQ(cbd->buf,"r.port") || STREQ(cbd->buf,"r.p")) {
      p->r.port = (u_int16_t)(cbd->v.i & 0xffff);
      return;
    }
    if(STREQ(cbd->buf,"interval")) {
      p->interval = (u_int16_t)(cbd->v.i & 0x7fffffff);
      p->h_int = 1;
      return;
    }
    if(STREQ(cbd->buf,"min interval")) {
      p->min_interval = (u_int16_t)(cbd->v.i & 0x7fffffff);
      p->h_mint = 1;
      return;
    }
    DEBUG_TRACE(printf("UNKNOWN %s %lld\n",cbd->buf,cbd->v.i));
    return;
  }
  if(cbd->t != 2) {
    DEBUG_TRACE(printf("BUG! t=%d %s\n",cbd->t,cbd->buf));
    return;
  }
  DEBUG_TRACE(print_safe_str("",cbd));

  s = cbd->v.s.s;
  ss = (char *)s;

  if(STREQ(cbd->buf,"a.id")) {
    p->a.id = s;
    return;
  }
  if(STREQ(cbd->buf,"a.info_hash")) {
    p->a.info_hash = s;
    return;
  }
  if(STREQ(cbd->buf,"a.target")) {
    p->a.target = s;
    return;
  }
  if(STREQ(cbd->buf,"a.token")) {
    p->a.token = s;
    p->a.t_len = cbd->v.s.l;
    return;
  }
  if(STREQ(cbd->buf,"a.name")) {
    p->a.name = s;
    p->a.name_len = cbd->v.s.l;
    return;
  }
  if(STREQ(cbd->buf,"a.want")) {
    return;
  }

  if(STREQ(cbd->buf,"r.id")) {
    p->r.id = s;
    return;
  }
  if(STREQ(cbd->buf,"r.ip")) {
    if(cbd->v.s.l != 4) {
      DEBUG_TRACE(printf("BUG! r.ip with port\n"));
      return;
    }
    p->r.ip = (struct bt_ipv4p *)s;
    return;
  }
  if(STREQ(cbd->buf,"r.token")) {
    p->r.token = s;
    p->r.t_len = cbd->v.s.l;
    return;
  }
  if(STREQ(cbd->buf,"r.values")) {
    if(cbd->v.s.l == 18) {
      if(!p->r.values6) {
	p->r.values6 = s;
	p->r.nv6 = 1;
      } else {
	if(s != p->r.values6+(p->r.nv6*21)) {
	  // DEBUG_TRACE(printf("BUG! r.values6 not in list! %08x %08x \n", p->r.values+(p->r.nv6*21),s));
	  return;
	}
	p->r.nv6++;
      }
      return;
    }
    if(cbd->v.s.l == 6) {
      if(!p->r.values) {
	p->r.values = s;
	p->r.nv = 1;
      } else {
	if(s != p->r.values+(p->r.nv*8)) {
	  // DEBUG_TRACE(printf("BUG! r.values not in list! %u \n",s-p->r.values+(p->r.nv*8)));
	  return;
	}
	p->r.nv++;
      }
      return;
    }
    return;
  }

  if(STREQ(cbd->buf,"r.name") || STREQ(cbd->buf,"r.n")) {
    p->r.name = s;
    p->r.name_len = cbd->v.s.l;
    return;
  }
  if(STREQ(cbd->buf,"r.nodes")) {
    if(cbd->v.s.l % 26) {
      // DEBUG_TRACE(printf("BUG! r.nodes length %d not %% 26\n",cbd->v.s.l));
      return;
    }
    p->r.nodes = (struct bt_nodes_data *)s;
    p->r.nn = cbd->v.s.l / 26;
    return;
  }
  if(STREQ(cbd->buf,"r.nodes6")) {
    if(cbd->v.s.l % 38) {
      // DEBUG_TRACE(printf("BUG! r.nodes length %d not %% 38\n",cbd->v.s.l));
      return;
    }
    p->r.nodes6 = (struct bt_nodes6_data *)s;
    p->r.nn6 = cbd->v.s.l / 38;
    return;
  }

  if(cbd->buf[0] == 'y' && !cbd->buf[1]) {
    if(cbd->v.s.l != 1) return;
    if(*ss == 'q') { p->y_q = 1; return; }
    if(*ss == 'r') { p->y_r = 1; return; }
    if(*ss == 'e') { p->y_e = 1; return; }
    return;
  }
  if(cbd->buf[0] == 'q' && !cbd->buf[1]) {
    if(!strncmp(ss,"announce_peer",13)) {
      p->q_a_peer = 1;
      return;
    }
    if(!strncmp(ss,"find_node",9)) {
      p->q_f_node = 1;
      return;
    }
    if(!strncmp(ss,"get_peers",9)) {
      p->q_g_peers = 1;
      return;
    }
    if(!strncmp(ss,"ping",4)) {
      p->q_ping = 1;
      return;
    }
    if(!strncmp(ss,"vote",4)) {
      return;
    }
  }
  if(STREQ(cbd->buf,"ip")) {
    if(cbd->v.s.l != 6) {
      // DEBUG_TRACE(printf("BUG! r.ip w/o port\n"));
    }
    p->ip = (struct bt_ipv4p *)s;
    p->h_ip = 1;
    return;
  }
  if(STREQ(cbd->buf,"peers")) {
    if(cbd->v.s.l % 6) return;
    p->peers = (struct bt_ipv4p *)s;
    p->n_peers = cbd->v.s.l / 6;
    return;
  }
  if((*cbd->buf == 't' || *cbd->buf == 'v') && !cbd->buf[1]) {
    u_int64_t d = *(u_int64_t*)s;
    switch(cbd->v.s.l) {
    case 2:
      d &= 0xffffllu; d = htons(d); break;
    case 4:
      d &= 0xffffffffllu; d = htonl(d); break;
    case 6:
      d &= 0xffffffffffffllu; d = (htonl(d & 0xffffffff) << 16) |
				(htons(d >> 32) & 0xffff);
      break;
    case 8: d = ((u_int64_t)htonl(d & 0xffffffff) << 32) |
	htonl(d >> 32);
      break;
    default: d = 0;
    }
    if(*cbd->buf == 'v') cbd->p.v = d;
    else cbd->p.t = d;
    return;
  }

  if(cbd->buf[0] == 'e') {
    p->e_msg = s;
    p->e_len = cbd->v.s.l;
    return;
  }
  // DEBUG_TRACE(print_safe_str("UNKNOWN",cbd));
}


const u_int8_t *bt_decode(const u_int8_t *b, size_t *l, int *ret, bt_parse_data_cb_t *cbd) {

  unsigned int n=0,neg=0;
  i_int64_t d = 0;
  register u_int8_t c;

  if(*l == 0) return NULL;
  if(cbd->level > BDEC_MAXDEPT) goto bad_data;
  c = *b++; (*l)--;
  if(c == 'i') { // integer
    while(*l) {
      c = *b++; (*l)--;
      n++;
      if(c == '-') {
	if(n != 1) goto bad_data;
	n--;
	neg=1;
	continue;
      }
      if(c >= '0' && c <= '9') {
	if(c == '0' && n > 1 && !d && *b != 'e') goto bad_data;
	d *= 10;
	d += c-'0';
	continue;
      }
      if(c != 'e') goto bad_data;
      break;
    }
    if(neg) d=-d;
    cbd->t = 1;
    cbd->v.i = neg ? -d:d;
    return b;
  }
  if(c >= '1' && c <= '9') { //string
    d=c-'0';
    while(*l) {
      c = *b++; (*l)--;
      n++;
      if(c >= '0' && c <= '9') {
	if(c == '0' && n > 1 && d == 0) goto bad_data;
	d *= 10;
	d += c-'0';
	continue;
      }
      if(c != ':') goto bad_data;
      break;
    }
    if(d > *l) goto bad_data;
    cbd->t = 2;
    cbd->v.s.s = b;
    cbd->v.s.l = d;
    b += d;
    *l -= d;
    return b;
  }
  if(c == 'l') {
    cbd->level++;
    do {
      b = bt_decode(b,l,ret,cbd);
      if(*ret < 0 || *l == 0) goto bad_data;
      cb_data(cbd,ret);
      if(*ret < 0) goto bad_data;
      cbd->t = 0;
    } while (*b != 'e' && *l != 0);
    b++; (*l)--;
    cbd->level--;
    return b;
  }
  if(c == 'd') {
    cbd->level++;
    do {
      char *ls = cbd->buf + strlen(cbd->buf);
      int l1 = ls != cbd->buf ? 1:0;
      if(!(*b >= '1' && *b <= '9')) goto bad_data;
      b = bt_decode(b,l,ret,cbd);
      if(*ret < 0 || *l == 0) goto bad_data;
      if(ls+cbd->v.s.l+l1 < &cbd->buf[sizeof(cbd->buf)-1]) {
	if(l1)	ls[0]='.';
	strncpy(ls+l1,(char *)cbd->v.s.s,cbd->v.s.l);
	ls[cbd->v.s.l+l1]=0;
      }
      b = bt_decode(b,l,ret,cbd);
      if(*ret < 0 || *l == 0) goto bad_data;
      cb_data(cbd,ret);
      if(*ret < 0) goto bad_data;
      cbd->t = 0;
      *ls = 0;
    } while (*b != 'e' && l != 0);

    b++; (*l)--;
    cbd->level--;
    return b;
  }
 bad_data:
  *ret=-1;
  return b;
}
