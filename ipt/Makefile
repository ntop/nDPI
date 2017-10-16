NDPI_PATH2 := ${NDPI_PATH}/src
NDPI_SRC := ndpi_cpy
NDPI_PRO := ${NDPI_SRC}/lib/protocols

CFLAGS = -fPIC -I${NDPI_SRC}/include -I${NDPI_SRC}/lib -I../src -DOPENDPI_NETFILTER_MODULE -O2 -Wall -DNDPI_IPTABLES_EXT

all:
	if test -d ${NDPI_SRC}; then \
		cp ${NDPI_PATH2}/* ${NDPI_SRC} -R; \
	else \
		mkdir ${NDPI_SRC}; \
		cp ${NDPI_PATH2}/* ${NDPI_SRC} -R; \
	fi
	make libxt_ndpi.so
	rm -r ${NDPI_SRC}
lib%.so: lib%.o
	$(CC) -shared -o $@ $^;
lib%.o: lib%.c
	$(CC) ${CFLAGS} -D_INIT=lib$*_init -c -o $@ $<;
clean:
	rm -rf libxt_ndpi.so ${NDPI_SRC}
