/*
 * ndpi_patricia_typedef.h
 *
 * Copyright (C) 2011-22 - ntop.org
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

/*
 * $Id: ndpi_patricia.h,v 1.6 2005/12/07 20:53:01 dplonka Exp $
 * Dave Plonka <plonka@doit.wisc.edu>
 *
 * This product includes software developed by the University of Michigan,
 * Merit Network, Inc., and their contributors.
 *
 * This file had been called "radix.h" in the MRT sources.
 *
 * I renamed it to "ndpi_patricia.h" since it's not an implementation of a general
 * radix trie.  Also, pulled in various requirements from "mrt.h" and added
 * some other things it could be used as a standalone API.

 https://github.com/deepfield/MRT/blob/master/COPYRIGHT

 Copyright (c) 1999-2013

 The Regents of the University of Michigan ("The Regents") and Merit
 Network, Inc.

 Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _NDPI_PATRICIA_TYPEDEF_H_
#define _NDPI_PATRICIA_TYPEDEF_H_

/* pointer to usr data (ex. route flap info) */
union ndpi_patricia_node_value_t { 
  /* User-defined values */
  union {
    struct {
      u_int32_t user_value, additional_user_value;
    } uv32;
    
    u_int64_t uv64;

    void *user_data;
  } u;
};

typedef struct _ndpi_prefix_t {
  u_int16_t family;		/* AF_INET | AF_INET6 */
  u_int16_t bitlen;		/* same as mask? */
  int ref_count;		/* reference count */
  union {
    struct in_addr sin;
    struct in6_addr sin6;
    u_int8_t mac[6];
  } add;
} ndpi_prefix_t;

typedef struct _ndpi_patricia_node_t {
  u_int16_t bit;			/* flag if this node used */
  ndpi_prefix_t *prefix;		/* who we are in patricia tree */
  struct _ndpi_patricia_node_t *l, *r;	/* left and right children */
  struct _ndpi_patricia_node_t *parent;/* may be used */
  void *data;			/* pointer to data */
  union ndpi_patricia_node_value_t value;
} ndpi_patricia_node_t;

typedef struct _ndpi_patricia_tree_t {
  ndpi_patricia_node_t 	*head;
  u_int16_t		maxbits;	/* for IP, 32 bit addresses */
  int num_active_node;		/* for debug purpose */
} ndpi_patricia_tree_t;

#endif /* _NDPI_PATRICIA_TYPEDEF_H_ */
