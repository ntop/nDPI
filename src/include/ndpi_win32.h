/*
 * ndpi_win32.h
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

#ifndef __NDPI_WIN32_INCLUDE_FILE__
#define __NDPI_WIN32_INCLUDE_FILE__

#ifdef WIN32
#include <Winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <getopt.h> /* getopt from: http://www.pwilson.net/sample.html. */
#include <process.h> /* for getpid() and the exec..() family */

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#define snprintf	_snprintf

extern char* strsep(char **stringp, const char *delim);

#define __attribute__(x)
#include <stdint.h>
#ifndef __GNUC__
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   uint;
typedef unsigned long  u_long;
#endif
typedef u_char  u_int8_t;
typedef u_short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned __int64 u_int64_t;


#define pthread_t                HANDLE
#define pthread_mutex_t          HANDLE
#define pthread_rwlock_t         pthread_mutex_t
#define pthread_rwlock_init      pthread_mutex_init
#define pthread_rwlock_wrlock    pthread_mutex_lock
#define pthread_rwlock_rdlock    pthread_mutex_lock
#define pthread_rwlock_unlock    pthread_mutex_unlock
#define pthread_rwlock_destroy	 pthread_mutex_destroy

#define gmtime_r(a, b)           gmtime(a) /* Already thread safe on windows */

extern unsigned long waitForNextEvent(unsigned long ulDelay /* ms */);

#define sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)

#endif /* Win32 */

#endif /* __NDPI_WIN32_INCLUDE_FILE__ */
