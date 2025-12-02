INCLUDE=-I../../include
LIB=
#CDEF=-fno-color-diagnostics

myproto_plugin.so: myproto_plugin.c
	$(CC) $(CDEF) $(INCLUDE) -DNDPI_LIB_COMPILATION -fPIC -shared myproto_plugin.c -o myproto_plugin.so -L.. -lndpi

clean:
	/bin/rm *~ *.so
