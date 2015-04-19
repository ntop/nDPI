/*
 * ndpi_unix.h
 *
 * Copyright (C) 2011-15 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
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

#ifndef __NDPI_UNIX_INCLUDE_FILE__
#define __NDPI_UNIX_INCLUDE_FILE__

#include "linux_compat.h"

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <netinet/in.h>
#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <netinet/in_systm.h>
#if defined(__OpenBSD__)
#include <pthread.h>
#endif
#endif
#endif

#ifndef WIN32
#ifndef __KERNEL__

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#else
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#endif
#endif

#endif /* __NDPI_UNIX_INCLUDE_FILE__ */
