/*
 * ndpi_win32.h
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

#ifndef __NDPI_WIN32_H__
#define __NDPI_WIN32_H__

#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <io.h>
#include <getopt.h>   /* getopt from: http://www.pwilson.net/sample.html. */
#include <process.h>  /* for getpid() and the exec..() family */
#include <stdint.h>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define _WS2TCPIP_H_ /* Avoid compilation problems */

#define	IPVERSION	4 /* on *nix it is defined in netinet/ip.h */ 

extern char* strsep(char **sp, const char *sep);

typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   uint;
typedef unsigned long  u_long;
typedef u_char         u_int8_t;
typedef u_short        u_int16_t;
typedef uint           u_int32_t;
typedef uint           u_int;
typedef unsigned       __int64 u_int64_t;

#define pthread_t                HANDLE
#define pthread_mutex_t          HANDLE
#define pthread_rwlock_t         pthread_mutex_t
#define pthread_rwlock_init      pthread_mutex_init
#define pthread_rwlock_wrlock    pthread_mutex_lock
#define pthread_rwlock_rdlock    pthread_mutex_lock
#define pthread_rwlock_unlock    pthread_mutex_unlock
#define pthread_rwlock_destroy	 pthread_mutex_destroy

#define gmtime_r(a, b)           memcpy(b, gmtime(a), sizeof(struct tm))

extern unsigned long waitForNextEvent(unsigned long ulDelay /* ms */);

#define sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)

#endif /* __NDPI_WIN32_H__ */
