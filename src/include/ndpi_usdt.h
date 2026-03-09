/*
 *
 * Copyright (C) 2011-26 - ntop.org
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

#ifndef __NDPI_USDT_H__
#define __NDPI_USDT_H__

#ifdef HAVE_USDT
  #include <sys/sdt.h>
  #define NDPI_DTRACE0(name)              DTRACE_PROBE(ndpi, name)
  #define NDPI_DTRACE1(name, a)           DTRACE_PROBE1(ndpi, name, a)
  #define NDPI_DTRACE2(name, a, b)        DTRACE_PROBE2(ndpi, name, a, b)
  #define NDPI_DTRACE3(name, a, b, c)     DTRACE_PROBE3(ndpi, name, a, b, c)
  #define NDPI_DTRACE4(name, a, b, c, d)     DTRACE_PROBE4(ndpi, name, a, b, c, d)
  #define NDPI_DTRACE5(name, a, b, c, d, e)  DTRACE_PROBE5(ndpi, name, a, b, c, d, e)
#else
  #define NDPI_DTRACE0(name)                 ((void)0)
  #define NDPI_DTRACE1(name, a)              ((void)0)
  #define NDPI_DTRACE2(name, a, b)           ((void)0)
  #define NDPI_DTRACE3(name, a, b, c)        ((void)0)
  #define NDPI_DTRACE4(name, a, b, c, d)     ((void)0)
  #define NDPI_DTRACE5(name, a, b, c, d, e)  ((void)0)
#endif

#endif /* __NDPI_USDT_H__ */
