NDPI_PATH2 := ${NDPI_PATH}/src
NDPI_SRC := ndpi_cpy
NDPI_PRO := ${NDPI_SRC}/lib/protocols

ccflags-y += -I${src}/${NDPI_SRC}/include -I${src}/${NDPI_SRC}/lib -DOPENDPI_NETFILTER_MODULE -DNDPI_IPTABLES_EXT

MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

obj-m := xt_ndpi.o
xt_ndpi-y := main.o \
                ${NDPI_SRC}/lib/ndpi_main.o \
                ${NDPI_SRC}/lib/ahocorasick.o \
                ${NDPI_SRC}/lib/node.o \
                ${NDPI_SRC}/lib/sort.o \
                ${NDPI_PRO}/afp.o \
                ${NDPI_PRO}/aimini.o \
                ${NDPI_PRO}/applejuice.o \
                ${NDPI_PRO}/armagetron.o \
                ${NDPI_PRO}/battlefield.o \
                ${NDPI_PRO}/bgp.o \
                ${NDPI_PRO}/bittorrent.o \
                ${NDPI_PRO}/citrix.o \
                ${NDPI_PRO}/ciscovpn.o \
                ${NDPI_PRO}/corba.o \
                ${NDPI_PRO}/crossfire.o \
                ${NDPI_PRO}/dcerpc.o \
                ${NDPI_PRO}/dhcp.o \
                ${NDPI_PRO}/dhcpv6.o \
                ${NDPI_PRO}/directconnect.o \
                ${NDPI_PRO}/directdownloadlink.o \
                ${NDPI_PRO}/dns.o \
                ${NDPI_PRO}/dofus.o \
                ${NDPI_PRO}/drda.o \
                ${NDPI_PRO}/dropbox.o \
                ${NDPI_PRO}/edonkey.o \
                ${NDPI_PRO}/git.o \
                ${NDPI_PRO}/gtp.o \
                ${NDPI_PRO}/lotus_notes.o \
                ${NDPI_PRO}/fasttrack.o \
                ${NDPI_PRO}/fiesta.o \
                ${NDPI_PRO}/filetopia.o \
                ${NDPI_PRO}/florensia.o \
                ${NDPI_PRO}/ftp_control.o \
                ${NDPI_PRO}/ftp_data.o \
                ${NDPI_PRO}/gnutella.o \
                ${NDPI_PRO}/guildwars.o \
                ${NDPI_PRO}/hangout.o \
                ${NDPI_PRO}/halflife2_and_mods.o \
                ${NDPI_PRO}/h323.o \
                ${NDPI_PRO}/http.o \
                ${NDPI_PRO}/http_activesync.o \
                ${NDPI_PRO}/iax.o \
                ${NDPI_PRO}/icecast.o \
                ${NDPI_PRO}/ipp.o \
                ${NDPI_PRO}/irc.o \
                ${NDPI_PRO}/jabber.o \
                ${NDPI_PRO}/kerberos.o \
                ${NDPI_PRO}/kontiki.o \
                ${NDPI_PRO}/ldap.o \
                ${NDPI_PRO}/mail_imap.o \
                ${NDPI_PRO}/mail_pop.o \
                ${NDPI_PRO}/mail_smtp.o \
                ${NDPI_PRO}/maplestory.o \
                ${NDPI_PRO}/mdns.o \
                ${NDPI_PRO}/mgcp.o \
                ${NDPI_PRO}/mms.o \
                ${NDPI_PRO}/msn.o \
                ${NDPI_PRO}/mssql_tds.o \
                ${NDPI_PRO}/mysql.o \
                ${NDPI_PRO}/whoisdas.o \
                ${NDPI_PRO}/netbios.o \
                ${NDPI_PRO}/netflow.o \
                ${NDPI_PRO}/nfs.o \
                ${NDPI_PRO}/noe.o \
                ${NDPI_PRO}/non_tcp_udp.o \
                ${NDPI_PRO}/ntp.o \
                ${NDPI_PRO}/openft.o \
                ${NDPI_PRO}/openvpn.o \
                ${NDPI_PRO}/oracle.o \
                ${NDPI_PRO}/oscar.o \
                ${NDPI_PRO}/pando.o \
                ${NDPI_PRO}/pcanywhere.o \
                ${NDPI_PRO}/postgres.o \
                ${NDPI_PRO}/pplive.o \
                ${NDPI_PRO}/ppstream.o \
                ${NDPI_PRO}/pptp.o \
                ${NDPI_PRO}/qq.o \
                ${NDPI_PRO}/quake.o \
                ${NDPI_PRO}/quic.o \
                ${NDPI_PRO}/eaq.o \
                ${NDPI_PRO}/kakaotalk_voice.o \
                ${NDPI_PRO}/mpegts.o \
                ${NDPI_PRO}/starcraft.o \
                ${NDPI_PRO}/teredo.o \
                ${NDPI_PRO}/hep.o \
                ${NDPI_PRO}/ubntac2.o \
                ${NDPI_PRO}/radius.o \
                ${NDPI_PRO}/rdp.o \
                ${NDPI_PRO}/rtp.o \
                ${NDPI_PRO}/rtsp.o \
                ${NDPI_PRO}/rtmp.o \
                ${NDPI_PRO}/rtcp.o \
                ${NDPI_PRO}/rsync.o \
                ${NDPI_PRO}/sflow.o \
                ${NDPI_PRO}/shoutcast.o \
                ${NDPI_PRO}/sip.o \
                ${NDPI_PRO}/zeromq.o \
                ${NDPI_PRO}/skinny.o \
                ${NDPI_PRO}/skype.o \
                ${NDPI_PRO}/smb.o \
                ${NDPI_PRO}/snmp.o \
                ${NDPI_PRO}/coap.o \
                ${NDPI_PRO}/socrates.o \
                ${NDPI_PRO}/socks45.o \
                ${NDPI_PRO}/sopcast.o \
                ${NDPI_PRO}/soulseek.o \
                ${NDPI_PRO}/spotify.o \
                ${NDPI_PRO}/ssdp.o \
                ${NDPI_PRO}/ssh.o \
                ${NDPI_PRO}/ssl.o \
                ${NDPI_PRO}/stealthnet.o \
                ${NDPI_PRO}/steam.o \
                ${NDPI_PRO}/stun.o \
                ${NDPI_PRO}/syslog.o \
                ${NDPI_PRO}/tcp_udp.o \
                ${NDPI_PRO}/teamviewer.o \
                ${NDPI_PRO}/telnet.o \
                ${NDPI_PRO}/teamspeak.o \
                ${NDPI_PRO}/tftp.o \
                ${NDPI_PRO}/thunder.o \
                ${NDPI_PRO}/tvants.o \
                ${NDPI_PRO}/tvuplayer.o \
                ${NDPI_PRO}/tor.o \
                ${NDPI_PRO}/usenet.o \
                ${NDPI_PRO}/viber.o \
                ${NDPI_PRO}/vmware.o \
                ${NDPI_PRO}/vnc.o \
                ${NDPI_PRO}/warcraft3.o \
                ${NDPI_PRO}/world_of_kung_fu.o \
                ${NDPI_PRO}/world_of_warcraft.o \
                ${NDPI_PRO}/xbox.o \
                ${NDPI_PRO}/xdmcp.o \
                ${NDPI_PRO}/yahoo.o \
                ${NDPI_PRO}/megaco.o \
                ${NDPI_PRO}/redis_net.o \
                ${NDPI_PRO}/vhua.o \
                ${NDPI_PRO}/ayiya.o \
                ${NDPI_PRO}/zattoo.o \
                ${NDPI_PRO}/rx.o \
                ${NDPI_PRO}/mqtt.o

all:
	if test -d ${NDPI_SRC}; then \
		cp ${NDPI_PATH2}/* ${NDPI_SRC} -R; \
	else \
		mkdir ${NDPI_SRC}; \
		cp ${NDPI_PATH2}/* ${NDPI_SRC} -R; \
	fi
	cp ${NDPI_SRC}/../../nDPI-patch/src/* ${NDPI_SRC}/ -R;
	cp ${NDPI_SRC}/lib/third_party/src/*.c ${NDPI_SRC}/lib -R;
	cp ${NDPI_SRC}/lib/third_party/include/*.h ${NDPI_SRC}/lib -R;
	cp ${NDPI_SRC}/lib/third_party/include/*.h ${NDPI_SRC}/include -R;
	sed -i "s/^\s*void ndpi_free_flow/\/\/void ndpi_free_flow/" ${NDPI_SRC}/include/ndpi_api.h;
	make -C ${KERNEL_DIR} M=$$PWD;
	rm -r ${NDPI_SRC}
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	depmod -a;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -rf modules.order ${NDPI_SRC}
