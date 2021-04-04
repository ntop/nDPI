bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_with_main

BUILD_SRC=../src
BUILD_EXAMPLE=../example

fuzz_process_packet_SOURCES = fuzz_process_packet.c
fuzz_process_packet_CFLAGS = -I$(top_srcdir)/example -I$(top_srcdir)/src/include -I$(BUILD_SRC)/include
fuzz_process_packet_LDADD = $(BUILD_SRC)/.libs/libndpi.a
fuzz_process_packet_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_process_packet_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_process_packet_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_process_packet_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
	$(fuzz_process_packet_LDFLAGS) $(LDFLAGS) -o $@

fuzz_ndpi_reader_SOURCES = fuzz_ndpi_reader.c
fuzz_ndpi_reader_CFLAGS = -I$(top_srcdir)/example -I$(top_srcdir)/src/include -I$(BUILD_SRC)/include
fuzz_ndpi_reader_LDADD = $(BUILD_EXAMPLE)/libndpiReader.a $(BUILD_SRC)/.libs/libndpi.a
fuzz_ndpi_reader_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
	$(fuzz_ndpi_reader_LDFLAGS) $(LDFLAGS) -o $@

fuzz_ndpi_reader_with_main_SOURCES = fuzz_ndpi_reader.c
fuzz_ndpi_reader_with_main_CFLAGS = -I$(top_srcdir)/example -I$(top_srcdir)/src/include -I$(BUILD_SRC)/include -DBUILD_MAIN
fuzz_ndpi_reader_with_main_LDADD = $(BUILD_SRC)/.libs/libndpi.a
fuzz_ndpi_reader_with_main_LDFLAGS = $(BUILD_EXAMPLE)/libndpiReader.a $(PCAP_LIB) $(LIBS)
# force usage of CXX for linker
fuzz_ndpi_reader_with_main_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
	$(fuzz_ndpi_reader_with_main_LDFLAGS) $(LDFLAGS) -o $@

# required for Google oss-fuzz
# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi
TESTPCAPS = \
	./1kxun.pcap \
	./443-chrome.pcap \
	./443-curl.pcap \
	./443-firefox.pcap \
	./443-git.pcap \
	./443-opvn.pcap \
	./443-safari.pcap \
	./4in4tunnel.pcap \
	./4in6tunnel.pcap \
	./6in4tunnel.pcap \
	./6in6tunnel.pcap \
	./aimini-http.pcap \
	./ajp.pcap \
	./alexa-app.pcapng \
	./among_us.pcap \
	./amqp.pcap \
	./android.pcap \
	./anyconnect-vpn.pcap \
	./anydesk-2.pcap \
	./anydesk.pcap \
	./avast_securedns.pcapng \
	./bad-dns-traffic.pcap \
	./badpackets.pcap \
	./BGP_Cisco_hdlc_slarp.pcap \
	./BGP_redist.pcap \
	./bitcoin.pcap \
	./bittorrent_ip.pcap \
	./bittorrent.pcap \
	./bittorrent_utp.pcap \
	./bt_search.pcap \
	./capwap.pcap \
	./check_mk_new.pcap \
	./chrome.pcap \
	./coap_mqtt.pcap \
	./cpha.pcap \
	./dcerpc.pcap \
	./diameter.pcap \
	./dlt_ppp.pcap \
	./dnp3.pcap \
	./dns_ambiguous_names.pcap \
	./dnscrypt_skype_false_positive.pcapng \
	./dnscrypt-v1-and-resolver-pings.pcap \
	./dnscrypt-v2-doh.pcap \
	./dns_doh.pcap \
	./dns_dot.pcap \
	./dns_exfiltration.pcap \
	./dns_long_domainname.pcap \
	./dns-tunnel-iodine.pcap \
	./doq_adguard.pcapng \
	./doq.pcapng \
	./dos_win98_smb_netbeui.pcap \
	./drda_db2.pcap \
	./dropbox.pcap \
	./dtls2.pcap \
	./dtls_certificate_fragments.pcap \
	./dtls.pcap \
	./dtls_session_id_and_coockie_both.pcap \
	./EAQ.pcap \
	./encrypted_sni.pcap \
	./ethereum.pcap \
	./exe_download_as_png.pcap \
	./exe_download.pcap \
	./facebook.pcap \
	./firefox.pcap \
	./fix.pcap \
	./forticlient.pcap \
	./ftp_failed.pcap \
	./ftp.pcap \
	./fuzz-2006-06-26-2594.pcap \
	./fuzz-2006-09-29-28586.pcap \
	./fuzz-2020-02-16-11740.pcap \
	./fuzz-2021-06-07-c6c72a0a56.pcap \
	./genshin-impact.pcap \
	./git.pcap \
	./googledns_android10.pcap \
	./google_ssl.pcap \
	./gquic.pcap \
	./h323-overflow.pcap \
	./hangout.pcap \
	./hpvirtgrp.pcap \
	./http-crash-content-disposition.pcap \
	./http_ipv6.pcap \
	./http-lines-split.pcap \
	./IEC104.pcap \
	./iec60780-5-104.pcap \
	./imaps.pcap \
	./instagram.pcap \
	./ip_fragmented_garbage.pcap \
	./iphone.pcap \
	./ipv6_in_gtp.pcap \
	./irc.pcap \
	./ja3_lots_of_cipher_suites_2_anon.pcap \
	./ja3_lots_of_cipher_suites.pcap \
	./KakaoTalk_chat.pcap \
	./KakaoTalk_talk.pcap \
	./kerberos.pcap \
	./long_tls_certificate.pcap \
	./malformed_dns.pcap \
	./malformed_icmp.pcap \
	./malware.pcap \
	./modbus.pcap \
	./monero.pcap \
	./mongodb.pcap \
	./mpeg.pcap \
	./mpegts.pcap \
	./mssql_tds.pcap \
	./mysql-8.pcap \
	./nats.pcap \
	./ndpi_match_string_subprotocol__error.pcapng \
	./nest_log_sink.pcap \
	./netbios.pcap \
	./netbios_wildcard_dns_query.pcap \
	./netflix.pcap \
	./netflow-fritz.pcap \
	./netflowv9.pcap \
	./nintendo.pcap \
	./no_sni.pcap \
	./NTPv2.pcap \
	./NTPv3.pcap \
	./NTPv4.pcap \
	./ocs.pcap \
	./ookla.pcap \
	./openvpn.pcap \
	./Oscar.pcap \
	./os_detected.pcapng \
	./pinterest.pcap \
	./pps.pcap \
	./ps_vue.pcap \
	./quic046.pcap \
	./quic_0RTT.pcap \
	./quic-23.pcap \
	./quic-24.pcap \
	./quic-27.pcap \
	./quic-28.pcap \
	./quic-29.pcap \
	./quic-33.pcapng \
	./quic_frags_ch_in_multiple_packets.pcapng \
	./quic_frags_ch_out_of_order_same_packet_craziness.pcapng \
	./quic_interop_V.pcapng \
	./quickplay.pcap \
	./quic-mvfst-22_decryption_error.pcap \
	./quic-mvfst-22.pcap \
	./quic-mvfst-27.pcapng \
	./quic-mvfst-exp.pcap \
	./quic.pcap \
	./quic_q39.pcap \
	./quic_q43.pcap \
	./quic_q46_b.pcap \
	./quic_q46.pcap \
	./quic_q50.pcap \
	./quic_t50.pcap \
	./quic_t51.pcap \
	./rdp.pcap \
	./reasm_crash_anon.pcapng \
	./reasm_segv_anon.pcapng \
	./reddit.pcap \
	./rtsp_setup_http.pcapng \
	./rx.pcap \
	./s7comm.pcap \
	./safari.pcap \
	./selfsigned.pcap \
	./signal.pcap \
	./simple-dnscrypt.pcap \
	./sip.pcap \
	./skype-conference-call.pcap \
	./skype_no_unknown.pcap \
	./skype.pcap \
	./skype_udp.pcap \
	./smb_deletefile.pcap \
	./smbv1.pcap \
	./smpp_in_general.pcap \
	./snapchat_call.pcapng \
	./snapchat.pcap \
	./ssdp-m-search.pcap \
	./ssh.pcap \
	./ssl-cert-name-mismatch.pcap \
	./starcraft_battle.pcap \
	./steam_datagram_relay_ping.pcapng \
	./steam.pcap \
	./synscan.pcap \
	./teams.pcap \
	./teamspeak3.pcap \
	./telegram.pcap \
	./teredo.pcap \
	./tftp.pcap \
	./tinc.pcap \
	./tk.pcap \
	./tls_certificate_too_long.pcap \
	./tls-esni-fuzzed.pcap \
	./tls_esni_sni_both.pcap \
	./tls_invalid_reads.pcap \
	./tls_long_cert.pcap \
	./tls-rdn-extract.pcap \
	./tls_verylong_certificate.pcap \
	./tor.pcap \
	./trickbot.pcap \
	./tumblr.pcap \
	./ubntac2.pcap \
	./upnp.pcap \
	./viber.pcap \
	./vnc.pcap \
	./wa_video.pcap \
	./wa_voice.pcap \
	./waze.pcap \
	./WebattackRCE.pcap \
	./WebattackSQLinj.pcap \
	./WebattackXSS.pcap \
	./webex.pcap \
	./websocket.pcap \
	./wechat.pcap \
	./weibo.pcap \
	./whatsappfiles.pcap \
	./whatsapp_login_call.pcap \
	./whatsapp_login_chat.pcap \
	./whatsapp_voice_and_message.pcap \
	./wireguard.pcap \
	./youtube_quic.pcap \
	./youtubeupload.pcap \
	./z3950.pcapng \
	./zabbix.pcap \
	./zcash.pcap \
	./zoom.pcap

fuzz_ndpi_reader_seed_corpus.zip: $(TESTPCAPS)
	zip -r fuzz_ndpi_reader_seed_corpus.zip $(TESTPCAPS)
