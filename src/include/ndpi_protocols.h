/*
 * ndpi_protocols.h
 *
 * Copyright (C) 2011-15 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifndef __NDPI_PROTOCOLS_INCLUDE_FILE__
#define __NDPI_PROTOCOLS_INCLUDE_FILE__

#include "ndpi_main.h"


/* TCP/UDP protocols */
u_int ndpi_search_tcp_or_udp_raw(struct ndpi_detection_module_struct *ndpi_struct,
				 u_int8_t protocol,
				 u_int32_t saddr, u_int32_t daddr,
				 u_int16_t sport, u_int16_t dport);

void ndpi_search_tcp_or_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);

/* Applications and other protocols. */
void ndpi_search_bittorrent(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_bittorrent_init(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t size,u_int32_t timeout);
void ndpi_bittorrent_done(struct ndpi_detection_module_struct *ndpi_struct);
int ndpi_bittorrent_gc(struct hash_ip4p_table *ht,int key,time_t now);

void ndpi_search_edonkey(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_fasttrack_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_gnutella(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_winmx_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_directconnect(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_applejuice_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_i23v5(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_socrates(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_soulseek_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_msn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_yahoo(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_oscar(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_jabber_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_irc_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_sip(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_direct_download_link_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_mail_pop_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_mail_imap_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_mail_smtp_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_http_subprotocol_conf(struct ndpi_detection_module_struct *ndpi_struct, char *attr, char *value, int protocol_id);
void ndpi_search_ftp_control(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ftp_data(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_usenet_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_rtsp_tcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_filetopia_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_vmware(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_imesh_tcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ssl_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_mms_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_icecast_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_shoutcast_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_veohtv_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_openft_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_stun(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_tvants_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_sopcast(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_tvuplayer(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ppstream(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_pplive(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_iax(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_mgcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_zattoo(struct ndpi_detection_module_struct*ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_qq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_feidian(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ssh_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ayiya(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_thunder(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_activesync(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_in_non_tcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_vnc_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_dhcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_steam(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_halflife2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_xbox(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_smb_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_telnet_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ntp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_nfs(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_rtp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ssdp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_worldofwarcraft(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_postgres_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_mysql_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_bgp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_quake(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_battlefield(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_secondlife(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_pcanywhere(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_rdp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_snmp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_kontiki(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_syslog(struct ndpi_detection_module_struct*ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_tds_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_netbios(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_mdns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ipp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ldap(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_warcraft3(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_kerberos(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_xdmcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_tftp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_mssql(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_pptp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_stealthnet(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_dhcpv6_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_meebo(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_afp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_aimini(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_florensia(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_maplestory(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_dofus(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_world_of_kung_fu(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_fiesta(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_crossfire_tcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_guildwars_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_armagetron_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_dropbox(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_citrix(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_dcerpc(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_netflow(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_sflow(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_radius(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_wsus(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_teamview(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_lotus_notes(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_gtp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_spotify(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_h323(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_openvpn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_noe(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_ciscovpn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_viber(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_teamspeak(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_corba(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_collectd(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_oracle(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_rsync(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_rtcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_skinny(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_tor(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_whois_das(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_socks5(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_socks4(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_rtmp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_pando(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_megaco(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_redis(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_zmq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_twitter(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_vhua(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
void ndpi_search_telegram(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);

#endif /* __NDPI_PROTOCOLS_INCLUDE_FILE__ */
