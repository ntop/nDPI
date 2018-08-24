#
# Simple non-autotools dependent makefile
#
# ./autogen.sh
# cd src/lib
# make -f Makefile.simple
#
CFLAGS += -fPIC -DPIC -I../include -Ithird_party/include -DNDPI_LIB_COMPILATION -g
RANLIB  = ranlib

OBJECTS = $(patsubst protocols/%.c, protocols/%.o, $(wildcard protocols/*.c)) $(patsubst third_party/src/%.c, third_party/src/%.o, $(wildcard third_party/src/*.c)) ndpi_main.o
HEADERS = $(wildcard ../include/*.h)

all: libndpi.a

ndpi_main.c: ndpi_content_match.c.inc

libndpi.a: $(OBJECTS)
	   ar rc $@ $(OBJECTS)
	   $(RANLIB) $@	       

%.o: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	/bin/rm -f libndpi.a $(OBJECTS)
