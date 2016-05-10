/*
 * ndpi_includes.h
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

#ifndef __NDPI_INCLUDES_H__
#define __NDPI_INCLUDES_H__

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>

#ifdef WIN32
#include "ndpi_win32.h"
#else
#include <sys/types.h>
#include <sys/param.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#if !defined __APPLE__ && !defined __FreeBSD__ && !defined __NetBSD__ && !defined __OpenBSD__
#include <endian.h>
#include <byteswap.h>

#if defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__
#include <netinet/in.h>

#if defined __NetBSD__ || defined __OpenBSD__
#include <netinet/in_systm.h>

#ifdef __OpenBSD__
#include <pthread.h>

#endif
#endif
#endif
#endif

#endif	/* Win32 */

#endif /* __NDPI_INCLUDES_H__ */
