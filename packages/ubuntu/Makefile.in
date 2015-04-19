#
# Change it according to your setup
#
NDPI_HOME=$(PWD)/../..
NDPI_BUILD=${NDPI_HOME}/packages/ubuntu

all: clean ndpi

ndpi:
	\rm -rf ./usr ./debian/tmp ./debian/ndpi-dev
	mkdir -p ./usr/local ./debian/ndpi-dev
	mkdir -p  ./usr/local/ndpi/lib ./usr/local/ndpi/bin ./ndpi-dev/usr/local/include/ndpi/
	cd ${NDPI_HOME}; ./autogen.sh; ./configure; make
	cp  $(NDPI_HOME)/lib/libndpi.a $(NDPI_HOME)/lib/libndpi.so*  ./usr/local/ndpi/lib/
	cp  $(NDPI_HOME)/example/ndpiReader   ./usr/local/ndpi/bin/
	cp  $(NDPI_HOME)/src/include/*.h  ndpi-dev/usr/local/include/ndpi/
	-rm -fr ndpi-dev/usr/local/include/nprobe/ndpi/.svn ndpi-dev/usr/local/include/ndpi/Makefile* ndpi-dev/usr/local/include/ndpi/ndpi_win32.h* ndpi-dev/usr/local/include/ndpi/include
	-find ./usr/local/lib -name "*.la" -exec /bin/rm {} ';'
	@echo
	@find . -name "*~" -exec /bin/rm {} ';'
	dpkg-buildpackage -rfakeroot -d -us -uc
	dpkg-sig --sign builder -k 7921DF34 ../ndpi*deb
	@\rm -f ../ndpi*dsc ../ndpi*.gz ../ndpi*changes
	@/bin/mv ../ndpi*deb .
	@echo
	@echo "Package built."
	@/bin/ls ndpi*deb
	@echo "-------------------------------"
	-dpkg --contents ndpi*amd64.deb
	@echo "-------------------------------"
	@echo "-------------------------------"
	-dpkg --contents ndpi*all.deb
	@echo "-------------------------------"

distclean:
	echo "dummy distclean"

install:
	echo "dummy install"

clean:
	-rm -rf *~ *deb debian/tmp ./usr
