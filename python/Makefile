CC=gcc
CFLAGS=-I. -I../src/include -I./src/lib/third_party/include -g -O2 -I/usr/include/json-c   -shared
#LIBNDPI=../src/lib/libndpi.so.3.5.0
LIBNDPI=../src/lib/libndpi.a
LDFLAGS=$(CFILE) $(LIBNDPI) -lpcap   -ljson-c  
SHARE = -soname,ndpi_wrap
SO=ndpi_wrap.so
OBJS = ndpi_wrap.o
CFILE = ndpi_wrap.c
PIC = -fPIC
PREFIX?=/usr/local
.PHONY: all

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)#do something for linux
	SHARE=-install_name,ndpiReader.so
endif

all: $(SO)

$(SO): $(CFILE) $(LIBNDPI) Makefile
	$(CC) $(CFLAGS) -Wl,$(SHARE) -o $@ $(PIC) $(LDFLAGS)
#	ln -s $(LIBNDPI) .

clean:
	/bin/rm -f $(SO)
