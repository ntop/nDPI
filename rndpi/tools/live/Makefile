#
# Makefile to compile rndpi application
#


# The name of the games
PROGRAM   = live

# C source files
SRCS      = live.c

# rnDPI
RNDPIDIR  = ../../lib
INCLUDE  += -I${RNDPIDIR}
LIBRNDPI  = ${RNDPIDIR}/librndpi.a
USRLIBS  += ${LIBRNDPI}

# nDPI
NDPIDIR   = ../../../src
INCLUDE  += -I${NDPIDIR}/include
LIBNDPI   = ${NDPIDIR}/lib/.libs/libndpi.a
USRLIBS  += ${LIBNDPI}

# Object and depend files
OBJS      = $(patsubst %.c,%.o, ${SRCS})
DEPS      = $(patsubst %.c,%.M, ${SRCS})

# C compiler and flags
INCLUDES  = -I. ${INCLUDE}
CC        = gcc
AR        = ar
LD        = gcc
CFLAGS    = -g -Wall ${INCLUDES}
ARFLAGS   = rv
LDFLAGS   =

# Operating System libraries
SYSLIBS   = -lpcap

# The main target is responsible to make all
all: ${PROGRAM}

# Binary program
${PROGRAM}: ${OBJS} ${USRLIBS}
	@echo "=*= making program $@ =*="
	@${LD} ${LDFLAGS} $^ ${SYSLIBS} -o $@

# Cleanup rules
clean:
	@rm -f ${PROGRAM}
	@rm -f ${LIB}
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
