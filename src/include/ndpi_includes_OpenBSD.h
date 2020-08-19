/*
 * ndpi_includes_OpenBSD.h
 *
 * Copyright (C) 2011-16 - ntop.org
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

#ifndef __NDPI_INCLUDES_OPENBSD_H__
#define __NDPI_INCLUDES_OPENBSD_H__

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif /* IPPROTO_SCTP */

#include <net/bpf.h>

typedef struct bpf_timeval pkt_timeval;

#endif /* __NDPI_INCLUDES_OPENBSD_H__ */
