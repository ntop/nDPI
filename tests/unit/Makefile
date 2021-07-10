CC=gcc
CXX=clang++

SRCHOME=../../src

CFLAGS=-g -fPIC -DPIC -I$(SRCHOME)/include -I/usr/local/Cellar/json-c/0.15/include -I/usr/local/Cellar/json-c/0.15/include/json-c  -g -O2 -I/usr/local/Cellar/json-c/0.15/include -I/usr/local/Cellar/json-c/0.15/include/json-c
LIBNDPI=$(SRCHOME)/lib/libndpi.a
LDFLAGS=$(LIBNDPI) -lpcap  -L/usr/local/Cellar/json-c/0.15/lib -ljson-c  -L/usr/local/Cellar/json-c/0.15/lib -ljson-c -lpthread -lm 
HEADERS=$(SRCHOME)/include/ndpi_api.h $(SRCHOME)/include/ndpi_typedefs.h $(SRCHOME)/include/ndpi_protocol_ids.h
OBJS=unit
PREFIX?=/usr

all: unit

EXECUTABLE_SOURCES := unit.c
COMMON_SOURCES := $(filter-out $(EXECUTABLE_SOURCES),$(wildcard *.c ))

unit: $(LIBNDPI) unit.o
	$(CC) $(CFLAGS) unit.o -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	/bin/rm -f *.o unit
	/bin/rm -f .*.o.cmd .*.o.d
	/bin/rm -rf build

install:
	echo ""

distdir:


distclean: clean
	/bin/rm -f Makefile
