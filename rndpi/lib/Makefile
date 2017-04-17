#
# rndpi - a C library for deep packet inspection on top of nDPI
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Build the static and dynamic libraries
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
#


# The name of the games
LIB       = librndpi.a
SHLIB     = $(patsubst %.a,%.so, ${LIB})
PROGRAM   = trylink

# C source files
LIBSRCS   = rndpi.c wrapper-ndpi.c varrays.c
MAINSRCS  = trylink.c

# Static private libraries
USRLIBS  += ${LIB}

# nDPI
NDPIDIR   = ../../src
INCLUDE  += -I${NDPIDIR}/include
LIBNDPI   = ${NDPIDIR}/lib/.libs/libndpi.a
USRLIBS  += ${LIBNDPI}

# Object and depend files
LIBOBJS   = $(patsubst %.c,%.o, ${LIBSRCS})
MAINOBJS  = $(patsubst %.c,%.o, ${MAINSRCS})
DEPS      = $(patsubst %.c,%.M, ${LIBSRCS} ${MAINSRCS})
OBJS      = ${LIBOBJS} ${MAINOBJS}

# C compiler and flags
INCLUDES  = -I. ${INCLUDE}
CC        = gcc
AR        = ar
LD        = gcc
CFLAGS    = -g -Wall -fPIC ${INCLUDES}
ARFLAGS   = rv
SHFLAGS  = -shared
LDFLAGS   =

# Operating System libraries
SYSLIBS   =

# The main target is responsible to make all
all: ${LIB} ${SHLIB} ${PROGRAM}

# Static Library
${LIB}: ${LIBOBJS}
	@echo "=*= making static library $@ =*="
	@${AR} ${ARFLAGS} $@ $^ 1> /dev/null 2>& 1

# Dynamic Library
${SHLIB}: ${OBJS}
	@echo "=*= making dynamic library $@ =*="
	@${CC} ${SHFLAGS} $^ -o $@

# Binary program
${PROGRAM}: ${MAINOBJS} ${USRLIBS}
	@echo "=*= making program $@ =*="
	@${LD} ${LDFLAGS} $^ ${SYSLIBS} -o $@

# Cleanup rules
clean:
	@rm -f ${PROGRAM}
	@rm -f ${LIB} ${SHLIB}
	@rm -f ${OBJS}
	@rm -f *~

distclean: clean
	@rm -f ${DEPS}

# How to make an object file from a C source
%.o: %.c
	@echo "=*= making object $@ =*="
	@${CC} -c ${CFLAGS} $<

# How to make a depend file from a C source
%.M: %.c
	@-${CC} -MM -MT $(<:.c=.o) ${CFLAGS} $< -o $@ 1> /dev/null 2>& 1

-include ${DEPS}
