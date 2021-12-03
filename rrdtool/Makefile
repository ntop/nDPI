
INC=-I ../src/include
LIBDPI=../src/lib/libndpi.a
LIB=$(LIBDPI) -lrrd -lm -lmaxminddb -lgcrypt

rrd_anomaly: rrd_anomaly.c Makefile $(LIBDPI)
	$(CC) -g $(INC) rrd_anomaly.c -o rrd_anomaly $(LIB)
