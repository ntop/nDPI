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

// fix a MinGW build issue "error: multiple storage classes in declaration specifiers" due to MinGW
// defining extern for __forceinline types
#if (defined(__MINGW32__) || defined(__MINGW64__)) && defined(__GNUC__)
#define MINGW_GCC
#define __mingw_forceinline __inline__ __attribute__((__always_inline__,__gnu_inline__))
#endif

#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN8
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <process.h>
#include <io.h>
#include <getopt.h>   /* getopt from: http://www.pwilson.net/sample.html. */
#include <process.h>  /* for getpid() and the exec..() family */
#include <stdint.h>
#include <time.h>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define _WS2TCPIP_H_ /* Avoid compilation problems */

#define	IPVERSION	4 /* on *nix it is defined in netinet/ip.h */ 

#ifndef MIN
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#if defined(__MINGW32__) || defined(__MINGW64__)
#undef gettimeofday
#define gettimeofday mingw_gettimeofday
#endif

extern char* strsep(char **sp, char *sep);

typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   uint;
typedef unsigned long  u_long;
typedef u_char         u_int8_t;
typedef u_short        u_int16_t;
typedef uint           u_int32_t;
typedef uint           u_int;
typedef unsigned       __int64 u_int64_t;

#define gmtime_r(a, b)                  memcpy(b, gmtime(a), sizeof(struct tm))

#define timegm                          _mkgmtime

#define sleep(a /* sec */)              Sleep(1000*a /* ms */)

#endif /* __NDPI_WIN32_H__ */
