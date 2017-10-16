/*
 * btlib.h
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

#define BDEC_MAXDEPT 8

#ifdef WIN32
#include "ndpi_win32.h"
#endif

typedef struct b_elem_s {
	const u_int8_t *s;
	size_t   l;
} b_elem_s_t;

#ifdef WIN32
// enable 1 byte packing on Windows
#include <pshpack1.h>
#endif

struct
#ifndef WIN32
	__attribute__((__packed__))
#endif
	bt_nodes_data {
	u_int8_t  id[20];
	u_int32_t ip;
	u_int16_t port;
};

struct
#ifndef WIN32
	__attribute__((__packed__))
#endif
	bt_ipv4p {
	u_int32_t ip;
	u_int16_t port;
};

struct
#ifndef WIN32
	__attribute__((__packed__))
#endif
	bt_ipv4p2 {
	struct bt_ipv4p d;
	u_int8_t	pad[2];
};

struct
#ifndef WIN32
	__attribute__((__packed__))
#endif
	bt_nodes6_data {
	u_int8_t  id[20];
	u_int32_t ip[4];
	u_int16_t port;
};

struct
#ifndef WIN32
	__attribute__((__packed__))
#endif
	bt_ipv6p {
	u_int32_t ip[4];
	u_int16_t port;
};

struct
#ifndef WIN32
	__attribute__((__packed__))
#endif
	bt_ipv6p2 {
	struct bt_ipv6p d;
	u_int8_t	pad[3];
};

#ifdef WIN32
// disable 1 byte packing
#include <poppack.h>
#endif

/*
 
  a.id S		r.id S
  a.info_hash S		r.ip ipv4
  a.name S		r.nodes x(id,ipv4,port)
 -a.noseed 0|1		r.n S        name of file
  a.port N		r.p          port
 -a.scrape 0|1		r.token S
 -a.seed 0|1		r.values x(ipv4,port)
  a.target S
  a.token S		-a.vote N
 -a.want n4|n6
 
  q announce_peer	q find_node
  q get_peers		q ping
 -q vote
 
  ip ipv4+port		interval N
  min interval N	peers x(ipv4,port)
  t 2/4/8b		v 4/6b
 
  e S			y e	y r	y q
 
  */

struct bt_parse_protocol {
	u_int16_t y_e:1, y_r:1, y_q:1,
		  q_a_peer:1,q_f_node:1,
		  q_g_peers:1,q_ping:1,
		  h_int:1,h_mint:1,h_ip:1;
	struct {
		const u_int8_t	*id,		// 20
			 	*info_hash,	// 20
			 	*target,	// 20
				*token,		// 20|8
			 	*name;		// varlen
		u_int16_t name_len;
		u_int16_t port;
		u_int16_t	t_len;
	} a;
	struct {
		const u_int8_t 	*id,		// 20
			 	*token,		// 20|8
				*values,	// (6+2)*x
				*values6,	// (18_3)*x
			 	*name;		// varlen
		struct bt_ipv4p	*ip;
		struct bt_nodes_data *nodes;
		struct bt_nodes6_data *nodes6;
		u_int16_t	name_len;
		u_int16_t	nn;		// nodes num
		u_int16_t	nv;		// values num
		u_int16_t	nn6;		// nodes6 num
		u_int16_t	nv6;		// values6 num
		u_int16_t	port;
		u_int16_t	t_len;
	} r;
	int			interval,min_interval;
	struct bt_ipv4p		*peers;
	int			n_peers;
	struct bt_ipv4p		*ip;
	const u_int8_t		*e_msg;
	u_int16_t		e_len;
	u_int64_t		t,v;
};

typedef struct bt_parse_data_cb {
	struct bt_parse_protocol p;
	char	buf[64];
	int	level;
	int	t;
	union {
		i_int64_t i;
		b_elem_s_t s;
	} v;
} bt_parse_data_cb_t;

extern int bt_parse_debug;
void dump_bt_proto_struct(struct bt_parse_protocol *p);
const u_int8_t *bt_decode(const u_int8_t *b, size_t *l, int *ret, bt_parse_data_cb_t *cbd);
