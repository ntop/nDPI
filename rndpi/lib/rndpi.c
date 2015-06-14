/*
 * rndpi - a C library for deep packet inspection on top of nDPI
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * API implementation
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 * Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
 *
 */


/* Library headers */
#include "rndpi.h"
#include "private-rndpi.h"


/* All the external references to nDPI Protocols, Applications, Services and Contents are here */

void ndpi_search_ftp_control (void * ndpi, void * flow);
void ndpi_search_mail_pop_tcp (void * ndpi, void * flow);               /* TCP */
void ndpi_search_mail_imap_tcp (void * ndpi, void * flow);              /* TCP */
void ndpi_search_mail_smtp_tcp (void * ndpi, void * flow);              /* TCP */
void ndpi_search_dns (void * ndpi, void * flow);
void ndpi_search_ipp (void * ndpi, void * flow);
void ndpi_search_http_tcp (void * ndpi, void * flow);                   /* TCP */
void ndpi_search_mdns (void * ndpi, void * flow);
void ndpi_search_ntp_udp (void * ndpi, void * flow);                    /* UDP */
void ndpi_search_netbios (void * ndpi, void * flow);
void ndpi_search_nfs (void * ndpi, void * flow);
void ndpi_search_ssdp (void * ndpi, void * flow);
void ndpi_search_bgp (void * ndpi, void * flow);
void ndpi_search_snmp (void * ndpi, void * flow);
void ndpi_search_xdmcp (void * ndpi, void * flow);
void ndpi_search_smb_tcp (void * ndpi, void * flow);                    /* TCP */
void ndpi_search_syslog (void * ndpi, void * flow);
void ndpi_search_dhcp_udp (void * ndpi, void * flow);                   /* UDP */
void ndpi_search_postgres_tcp (void * ndpi, void * flow);               /* TCP */
void ndpi_search_mysql_tcp (void * ndpi, void * flow);                  /* TCP */
void ndpi_search_tds_tcp (void * ndpi, void * flow);                    /* TCP */
void ndpi_search_direct_download_link_tcp (void * ndpi, void * flow);   /* TCP */
void ndpi_search_mail_pops (void * ndpi, void * flow);
void ndpi_search_applejuice_tcp (void * ndpi, void * flow);             /* TCP */
void ndpi_search_directconnect (void * ndpi, void * flow);
void ndpi_search_socrates (void * ndpi, void * flow);
void ndpi_search_winmx_tcp (void * ndpi, void * flow);                  /* TCP */
void ndpi_search_vmware (void * ndpi, void * flow);
void ndpi_search_mail_smtps (void * ndpi, void * flow);
void ndpi_search_filetopia_tcp (void * ndpi, void * flow);              /* TCP */
void ndpi_search_imesh_tcp_udp (void * ndpi, void * flow);              /* TCP && UDP */
void ndpi_search_kontiki (void * ndpi, void * flow);
void ndpi_search_openft_tcp (void * ndpi, void * flow);                 /* TCP */
void ndpi_search_fasttrack_tcp (void * ndpi, void * flow);              /* TCP */
void ndpi_search_gnutella (void * ndpi, void * flow);
void ndpi_search_edonkey (void * ndpi, void * flow);
void ndpi_search_bittorrent (void * ndpi, void * flow);
void ndpi_search_epp (void * ndpi, void * flow);
void ndpi_content_avi (void * ndpi, void * flow);                       /* content */
void ndpi_content_flash (void * ndpi, void * flow);                     /* content */
void ndpi_content_ogg (void * ndpi, void * flow);                       /* content */
void ndpi_content_mpeg (void * ndpi, void * flow);                      /* content */
void ndpi_content_quicktime (void * ndpi, void * flow);                 /* content */
void ndpi_content_realmedia (void * ndpi, void * flow);                 /* content */
void ndpi_content_windowsmedia (void * ndpi, void * flow);              /* content */
void ndpi_content_mms (void * ndpi, void * flow);                       /* content */
void ndpi_search_xbox (void * ndpi, void * flow);
void ndpi_search_qq (void * ndpi, void * flow);
void ndpi_search_move (void * ndpi, void * flow);
void ndpi_search_rtsp_tcp_udp (void * ndpi, void * flow);               /* TCP && UDP */
void ndpi_search_mail_imaps (void * ndpi, void * flow);
void ndpi_search_icecast_tcp (void * ndpi, void * flow);                /* TCP */
void ndpi_search_pplive (void * ndpi, void * flow);
void ndpi_search_ppstream (void * ndpi, void * flow);
void ndpi_search_zattoo (void * ndpi, void * flow);
void ndpi_search_shoutcast_tcp (void * ndpi, void * flow);              /* TCP */
void ndpi_search_sopcast (void * ndpi, void * flow);
void ndpi_search_tvants_udp (void * ndpi, void * flow);                 /* UDP */
void ndpi_search_tvuplayer (void * ndpi, void * flow);
void ndpi_search_veohtv_tcp (void * ndpi, void * flow);                 /* TCP */
void ndpi_search_qqlive (void * ndpi, void * flow);
void ndpi_search_thunder (void * ndpi, void * flow);
void ndpi_search_soulseek_tcp (void * ndpi, void * flow);               /* TCP */
void ndpi_search_ssl_no_cert (void * ndpi, void * flow);
void ndpi_search_irc_tcp (void * ndpi, void * flow);                    /* TCP */
void ndpi_search_ayiya (void * ndpi, void * flow);
void ndpi_search_jabber_tcp (void * ndpi, void * flow);                 /* TCP */
void ndpi_search_msn (void * ndpi, void * flow);
void ndpi_search_oscar (void * ndpi, void * flow);
void ndpi_search_yahoo (void * ndpi, void * flow);
void ndpi_search_battlefield (void * ndpi, void * flow);
void ndpi_search_quake (void * ndpi, void * flow);
void ndpi_search_ip_vrrp (void * ndpi, void * flow);
void ndpi_search_steam (void * ndpi, void * flow);
void ndpi_search_halflife2 (void * ndpi, void * flow);
void ndpi_search_worldofwarcraft (void * ndpi, void * flow);
void ndpi_search_telnet_tcp (void * ndpi, void * flow);                 /* TCP */
void ndpi_search_stun (void * ndpi, void * flow);
void ndpi_search_ip_ipsec (void * ndpi, void * flow);
void ndpi_search_ip_gre (void * ndpi, void * flow);
void ndpi_search_ip_icmp (void * ndpi, void * flow);
void ndpi_search_ip_igmp (void * ndpi, void * flow);
void ndpi_search_ip_egp (void * ndpi, void * flow);
void ndpi_search_ip_sctp (void * ndpi, void * flow);
void ndpi_search_ip_ospf (void * ndpi, void * flow);
void ndpi_search_ip_ip_in_ip (void * ndpi, void * flow);
void ndpi_search_rtp (void * ndpi, void * flow);
void ndpi_search_rdp (void * ndpi, void * flow);
void ndpi_search_vnc_tcp (void * ndpi, void * flow);
void ndpi_search_pcanywhere (void * ndpi, void * flow);
void ndpi_search_ssl_tcp (void * ndpi, void * flow);                    /* TCP */
void ndpi_search_ssh_tcp (void * ndpi, void * flow);                    /* TCP */
void ndpi_search_usenet_tcp (void * ndpi, void * flow);                 /* TCP */
void ndpi_search_mgcp (void * ndpi, void * flow);
void ndpi_search_iax (void * ndpi, void * flow);
void ndpi_search_tftp (void * ndpi, void * flow);
void ndpi_search_afp (void * ndpi, void * flow);
void ndpi_search_stealthnet (void * ndpi, void * flow);
void ndpi_search_aimini (void * ndpi, void * flow);
void ndpi_search_sip (void * ndpi, void * flow);
void ndpi_search_truphone (void * ndpi, void * flow);
void ndpi_search_ip_icmpv6 (void * ndpi, void * flow);
void ndpi_search_dhcpv6_udp (void * ndpi, void * flow);                 /* UDP */
void ndpi_search_armagetron_udp (void * ndpi, void * flow);             /* UDP */
void ndpi_search_crossfire_tcp_udp (void * ndpi, void * flow);          /* TCP && UDP */
void ndpi_search_dofus (void * ndpi, void * flow);
void ndpi_search_fiesta (void * ndpi, void * flow);
void ndpi_search_florensia (void * ndpi, void * flow);
void ndpi_search_guildwars_tcp (void * ndpi, void * flow);              /* TCP */
void ndpi_search_activesync (void * ndpi, void * flow);
void ndpi_search_kerberos (void * ndpi, void * flow);
void ndpi_search_ldap (void * ndpi, void * flow);
void ndpi_search_maplestory (void * ndpi, void * flow);
void ndpi_search_mssql (void * ndpi, void * flow);
void ndpi_search_pptp (void * ndpi, void * flow);
void ndpi_search_warcraft3 (void * ndpi, void * flow);
void ndpi_search_world_of_kung_fu (void * ndpi, void * flow);
void ndpi_search_meebo (void * ndpi, void * flow);
void ndpi_service_facebook (void * ndpi, void * flow);                  /* service */
void ndpi_service_twitter (void * ndpi, void * flow);                   /* service */
void ndpi_search_dropbox (void * ndpi, void * flow);
void ndpi_service_gmail (void * ndpi, void * flow);                     /* service */
void ndpi_service_google_maps (void * ndpi, void * flow);               /* service */
void ndpi_service_youtube (void * ndpi, void * flow);                   /* service */
void ndpi_search_skype (void * ndpi, void * flow);
void ndpi_service_google (void * ndpi, void * flow);                    /* service */
void ndpi_search_dcerpc (void * ndpi, void * flow);
void ndpi_search_netflow (void * ndpi, void * flow);
void ndpi_search_sflow (void * ndpi, void * flow);
void ndpi_search_http_connect (void * ndpi, void * flow);
void ndpi_search_http_proxy (void * ndpi, void * flow);
void ndpi_search_citrix (void * ndpi, void * flow);
void ndpi_service_netflix (void * ndpi, void * flow);                   /* service */
void ndpi_service_lastfm (void * ndpi, void * flow);                    /* service */
void ndpi_service_grooveshark (void * ndpi, void * flow);               /* service */
void ndpi_search_skyfile_prepaid (void * ndpi, void * flow);
void ndpi_search_skyfile_rudics (void * ndpi, void * flow);
void ndpi_search_skyfile_postpaid (void * ndpi, void * flow);
void ndpi_search_citrix_online (void * ndpi, void * flow);
void ndpi_service_apple (void * ndpi, void * flow);                     /* service */
void ndpi_search_webex (void * ndpi, void * flow);
void ndpi_service_whatsapp (void * ndpi, void * flow);                  /* service */
void ndpi_service_apple_icloud (void * ndpi, void * flow);              /* service */
void ndpi_search_viber (void * ndpi, void * flow);
void ndpi_service_apple_itunes (void * ndpi, void * flow);              /* service */
void ndpi_search_radius (void * ndpi, void * flow);
void ndpi_search_teamviewer (void * ndpi, void * flow);
void ndpi_service_tuenti (void * ndpi, void * flow);                    /* service */
void ndpi_search_lotus_notes (void * ndpi, void * flow);
void ndpi_search_sap (void * ndpi, void * flow);
void ndpi_search_gtp (void * ndpi, void * flow);
void ndpi_search_upnp (void * ndpi, void * flow);
void ndpi_search_llmnr (void * ndpi, void * flow);
void ndpi_search_remote_scan (void * ndpi, void * flow);
void ndpi_search_spotify (void * ndpi, void * flow);
void ndpi_content_webm (void * ndpi, void * flow);                      /* content */
void ndpi_search_h323 (void * ndpi, void * flow);
void ndpi_search_openvpn (void * ndpi, void * flow);
void ndpi_search_noe (void * ndpi, void * flow);
void ndpi_search_ciscovpn (void * ndpi, void * flow);
void ndpi_search_teamspeak (void * ndpi, void * flow);
void ndpi_search_tor (void * ndpi, void * flow);
void ndpi_search_skinny (void * ndpi, void * flow);
void ndpi_search_rtcp (void * ndpi, void * flow);
void ndpi_search_rsync (void * ndpi, void * flow);
void ndpi_search_oracle (void * ndpi, void * flow);
void ndpi_search_corba (void * ndpi, void * flow);
void ndpi_search_ubuntuone (void * ndpi, void * flow);
void ndpi_search_whois_das (void * ndpi, void * flow);
void ndpi_search_collectd (void * ndpi, void * flow);
void ndpi_search_socks5 (void * ndpi, void * flow);
void ndpi_search_socks4 (void * ndpi, void * flow);
void ndpi_search_rtmp (void * ndpi, void * flow);
void ndpi_search_ftp_data (void * ndpi, void * flow);
void ndpi_service_wikipedia (void * ndpi, void * flow);                /* service */
void ndpi_search_zmq (void * ndpi, void * flow);
void ndpi_service_amazon (void * ndpi, void * flow);                   /* service */
void ndpi_service_ebay (void * ndpi, void * flow);                     /* service */
void ndpi_service_cnn (void * ndpi, void * flow);                      /* service */
void ndpi_search_megaco (void * ndpi, void * flow);
void ndpi_search_redis (void * ndpi, void * flow);
void ndpi_search_pando (void * ndpi, void * flow);
void ndpi_search_vhua (void * ndpi, void * flow);
void ndpi_search_telegram (void * ndpi, void * flow);
void ndpi_service_vevo (void * ndpi, void * flow);                    /* service */
void ndpi_service_pandora (void * ndpi, void * flow);                 /* service */
void ndpi_search_quic (void * ndpi, void * flow);



/* The table with all the supported protocols */
static rndpi_protocol_t all_protocols [] =
{
  { RNDPI_PROTOCOL_FTP_CONTROL,                 "FTP_CONTROL",                 NULL, ndpi_search_ftp_control              },
  { RNDPI_PROTOCOL_MAIL_POP,                    "POP3",                        NULL, ndpi_search_mail_pop_tcp             },
  { RNDPI_PROTOCOL_MAIL_SMTP,                   "SMTP",                        NULL, ndpi_search_mail_smtp_tcp            },
  { RNDPI_PROTOCOL_MAIL_IMAP,                   "IMAP",                        NULL, ndpi_search_mail_imap_tcp            },
  { RNDPI_PROTOCOL_DNS,                         "DNS",                         NULL, ndpi_search_dns                      },
  { RNDPI_PROTOCOL_IPP,                         "IPP",                         NULL, ndpi_search_ipp                      },
  { RNDPI_PROTOCOL_HTTP,                        "HTTP",                        NULL, ndpi_search_http_tcp                 },
  { RNDPI_PROTOCOL_MDNS,                        "MDNS",                        NULL, ndpi_search_mdns                     },
  { RNDPI_PROTOCOL_NTP,                         "NTP",                         NULL, ndpi_search_ntp_udp                  },
  { RNDPI_PROTOCOL_NETBIOS,                     "NetBIOS",                     NULL, ndpi_search_netbios                  },
  { RNDPI_PROTOCOL_NFS,                         "NFS",                         NULL, ndpi_search_nfs                      },
  { RNDPI_PROTOCOL_SSDP,                        "SSDP",                        NULL, ndpi_search_ssdp                     },
  { RNDPI_PROTOCOL_BGP,                         "BGP",                         NULL, ndpi_search_bgp                      },
  { RNDPI_PROTOCOL_SNMP,                        "SNMP",                        NULL, ndpi_search_snmp                     },
  { RNDPI_PROTOCOL_XDMCP,                       "XDMCP",                       NULL, ndpi_search_xdmcp                    },
  { RNDPI_PROTOCOL_SMB,                         "SMB",                         NULL, ndpi_search_smb_tcp                  },
  { RNDPI_PROTOCOL_SYSLOG,                      "Syslog",                      NULL, ndpi_search_syslog                   },
  { RNDPI_PROTOCOL_DHCP,                        "DHCP",                        NULL, ndpi_search_dhcp_udp                 },
  { RNDPI_PROTOCOL_POSTGRES,                    "PostgreSQL",                  NULL, ndpi_search_postgres_tcp             },
  { RNDPI_PROTOCOL_MYSQL,                       "MySQL",                       NULL, ndpi_search_mysql_tcp                },
  { RNDPI_PROTOCOL_TDS,                         "TDS",                         NULL, ndpi_search_tds_tcp                  },
  { RNDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK,        "Direct_Download_Link",        NULL, ndpi_search_direct_download_link_tcp },
  { RNDPI_PROTOCOL_MAIL_POPS,                   "POPS",                        NULL, NULL },
  { RNDPI_PROTOCOL_APPLEJUICE,                  "AppleJuice",                  NULL, ndpi_search_applejuice_tcp           },
  { RNDPI_PROTOCOL_DIRECTCONNECT,               "DirectConnect",               NULL, ndpi_search_directconnect            },
  { RNDPI_PROTOCOL_SOCRATES,                    "Socrates",                    NULL, ndpi_search_socrates                 },
  { RNDPI_PROTOCOL_WINMX,                       "WinMX",                       NULL, ndpi_search_winmx_tcp                },
  { RNDPI_PROTOCOL_VMWARE,                      "VMware",                      NULL, ndpi_search_vmware                   },
  { RNDPI_PROTOCOL_MAIL_SMTPS,                  "SMTPS",                       NULL, NULL },
  { RNDPI_PROTOCOL_FILETOPIA,                   "Filetopia",                   NULL, ndpi_search_filetopia_tcp            },
  { RNDPI_PROTOCOL_IMESH,                       "iMESH",                       NULL, ndpi_search_imesh_tcp_udp            },
  { RNDPI_PROTOCOL_KONTIKI,                     "Kontiki",                     NULL, ndpi_search_kontiki                  },
  { RNDPI_PROTOCOL_OPENFT,                      "OpenFT",                      NULL, ndpi_search_openft_tcp               },
  { RNDPI_PROTOCOL_FASTTRACK,                   "FastTrack",                   NULL, ndpi_search_fasttrack_tcp            },
  { RNDPI_PROTOCOL_GNUTELLA,                    "Gnutella",                    NULL, ndpi_search_gnutella                 },
  { RNDPI_PROTOCOL_EDONKEY,                     "eDonkey",                     NULL, ndpi_search_edonkey                  },
  { RNDPI_PROTOCOL_BITTORRENT,                  "BitTorrent",                  NULL, ndpi_search_bittorrent               },
  { RNDPI_PROTOCOL_EPP,                         "EPP",                         NULL, NULL },
  { RNDPI_CONTENT_AVI,                          "AVI",                         NULL, NULL },
  { RNDPI_CONTENT_FLASH,                        "Flash",                       NULL, NULL },
  { RNDPI_CONTENT_OGG,                          "OggVorbis",                   NULL, NULL },
  { RNDPI_CONTENT_MPEG,                         "MPEG",                        NULL, NULL },
  { RNDPI_CONTENT_QUICKTIME,                    "QuickTime",                   NULL, NULL },
  { RNDPI_CONTENT_REALMEDIA,                    "RealMedia",                   NULL, NULL },
  { RNDPI_CONTENT_WINDOWSMEDIA,                 "WindowsMedia",                NULL, NULL },
  { RNDPI_CONTENT_MMS,                          "MMS",                         NULL, NULL },
  { RNDPI_PROTOCOL_XBOX,                        "Xbox",                        NULL, ndpi_search_xbox                     },
  { RNDPI_PROTOCOL_QQ,                          "QQ",                          NULL, ndpi_search_qq                       },
  { RNDPI_PROTOCOL_MOVE,                        "Move",                        NULL, NULL },
  { RNDPI_PROTOCOL_RTSP,                        "RTSP",                        NULL, ndpi_search_rtsp_tcp_udp             },
  { RNDPI_PROTOCOL_MAIL_IMAPS,                  "IMAPS",                       NULL, NULL },
  { RNDPI_PROTOCOL_ICECAST,                     "IceCast",                     NULL, ndpi_search_icecast_tcp              },
  { RNDPI_PROTOCOL_PPLIVE,                      "PPLive",                      NULL, ndpi_search_pplive                   },
  { RNDPI_PROTOCOL_PPSTREAM,                    "PPStream",                    NULL, ndpi_search_ppstream                 },
  { RNDPI_PROTOCOL_ZATTOO,                      "Zattoo",                      NULL, ndpi_search_zattoo                   },
  { RNDPI_PROTOCOL_SHOUTCAST,                   "ShoutCast",                   NULL, ndpi_search_shoutcast_tcp            },
  { RNDPI_PROTOCOL_SOPCAST,                     "Sopcast",                     NULL, ndpi_search_sopcast                  },
  { RNDPI_PROTOCOL_TVANTS,                      "Tvants",                      NULL, ndpi_search_tvants_udp               },
  { RNDPI_PROTOCOL_TVUPLAYER,                   "TVUplayer",                   NULL, ndpi_search_tvuplayer                },
  { RNDPI_PROTOCOL_QQLIVE_VEOHTV,               "HTTP_APPLICATION_VEOHTV",     NULL, ndpi_search_veohtv_tcp               },
  { RNDPI_PROTOCOL_QQLIVE,                      "QQLive",                      NULL, NULL },
  { RNDPI_PROTOCOL_THUNDER,                     "Thunder",                     NULL, ndpi_search_thunder                  },
  { RNDPI_PROTOCOL_SOULSEEK,                    "Soulseek",                    NULL, ndpi_search_soulseek_tcp             },
  { RNDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV,     "SSL_No_Cert",                 NULL, NULL },
  { RNDPI_PROTOCOL_IRC,                         "IRC",                         NULL, ndpi_search_irc_tcp                  },
  { RNDPI_PROTOCOL_AYIYA,                       "Ayiya",                       NULL, ndpi_search_ayiya                    },
  { RNDPI_PROTOCOL_UNENCRYPED_JABBER,           "Unencryped_Jabber",           NULL, ndpi_search_jabber_tcp               },
  { RNDPI_PROTOCOL_MSN ,                        "MSN",                         NULL, ndpi_search_msn                      },
  { RNDPI_PROTOCOL_OSCAR,                       "Oscar",                       NULL, ndpi_search_oscar                    },
  { RNDPI_PROTOCOL_YAHOO,                       "Yahoo",                       NULL, ndpi_search_yahoo                    },
  { RNDPI_PROTOCOL_BATTLEFIELD,                 "BattleField",                 NULL, ndpi_search_battlefield              },
  { RNDPI_PROTOCOL_QUAKE,                       "Quake",                       NULL, ndpi_search_quake                    },
  { RNDPI_PROTOCOL_IP_VRRP,                     "VRRP",                        NULL, NULL },
  { RNDPI_PROTOCOL_STEAM,                       "Steam",                       NULL, ndpi_search_steam                    },
  { RNDPI_PROTOCOL_HALFLIFE2,                   "HalfLife2",                   NULL, ndpi_search_halflife2                },
  { RNDPI_PROTOCOL_WORLDOFWARCRAFT,             "WorldOfWarcraft",             NULL, ndpi_search_worldofwarcraft          },
  { RNDPI_PROTOCOL_TELNET,                      "Telnet",                      NULL, ndpi_search_telnet_tcp               },
  { RNDPI_PROTOCOL_STUN,                        "STUN",                        NULL, ndpi_search_stun                     },
  { RNDPI_PROTOCOL_IP_IPSEC,                    "IPsec",                       NULL, NULL },
  { RNDPI_PROTOCOL_IP_GRE,                      "GRE",                         NULL, NULL },
  { RNDPI_PROTOCOL_IP_ICMP,                     "ICMP",                        NULL, NULL },
  { RNDPI_PROTOCOL_IP_IGMP,                     "IGMP",                        NULL, NULL },
  { RNDPI_PROTOCOL_IP_EGP,                      "EGP",                         NULL, NULL },
  { RNDPI_PROTOCOL_IP_SCTP,                     "SCTP",                        NULL, NULL },
  { RNDPI_PROTOCOL_IP_OSPF,                     "OSPF",                        NULL, NULL },
  { RNDPI_PROTOCOL_IP_IP_IN_IP,                 "IP_in_IP",                    NULL, NULL },
  { RNDPI_PROTOCOL_RTP,                         "RTP",                         NULL, ndpi_search_rtp                      },
  { RNDPI_PROTOCOL_RDP,                         "RDP",                         NULL, ndpi_search_rdp                      },
  { RNDPI_PROTOCOL_VNC,                         "VNC",                         NULL, ndpi_search_vnc_tcp                  },
  { RNDPI_PROTOCOL_PCANYWHERE,                  "PcAnywhere",                  NULL, ndpi_search_pcanywhere               },
  { RNDPI_PROTOCOL_SSL,                         "SSL",                         NULL, ndpi_search_ssl_tcp                  },
  { RNDPI_PROTOCOL_SSH,                         "SSH",                         NULL, ndpi_search_ssh_tcp                  },
  { RNDPI_PROTOCOL_USENET,                      "Usenet",                      NULL, ndpi_search_usenet_tcp               },
  { RNDPI_PROTOCOL_MGCP,                        "MGCP",                        NULL, ndpi_search_mgcp                     },
  { RNDPI_PROTOCOL_IAX,                         "IAX",                         NULL, ndpi_search_iax                      },
  { RNDPI_PROTOCOL_TFTP,                        "TFTP",                        NULL, ndpi_search_tftp                     },
  { RNDPI_PROTOCOL_AFP,                         "AFP",                         NULL, ndpi_search_afp                      },
  { RNDPI_PROTOCOL_STEALTHNET,                  "Stealthnet",                  NULL, ndpi_search_stealthnet               },
  { RNDPI_PROTOCOL_AIMINI,                      "Aimini",                      NULL, ndpi_search_aimini                   },
  { RNDPI_PROTOCOL_SIP,                         "SIP",                         NULL, ndpi_search_sip                      },
  { RNDPI_PROTOCOL_TRUPHONE,                    "TruPhone",                    NULL, NULL },
  { RNDPI_PROTOCOL_IP_ICMPV6,                   "ICMPV6",                      NULL, NULL },
  { RNDPI_PROTOCOL_DHCPV6,                      "DHCPV6",                      NULL, ndpi_search_dhcpv6_udp               },
  { RNDPI_PROTOCOL_ARMAGETRON,                  "Armagetron",                  NULL, ndpi_search_armagetron_udp           },
  { RNDPI_PROTOCOL_CROSSFIRE,                   "Crossfire",                   NULL, ndpi_search_crossfire_tcp_udp        },
  { RNDPI_PROTOCOL_DOFUS,                       "Dofus",                       NULL, ndpi_search_dofus                    },
  { RNDPI_PROTOCOL_FIESTA,                      "Fiesta",                      NULL, ndpi_search_fiesta                   },
  { RNDPI_PROTOCOL_FLORENSIA,                   "Florensia",                   NULL, ndpi_search_florensia                },
  { RNDPI_PROTOCOL_GUILDWARS,                   "Guildwars",                   NULL, ndpi_search_guildwars_tcp            },
  { RNDPI_PROTOCOL_HTTP_APPLICATION_ACTIVESYNC, "HTTP_Application_ActiveSync", NULL, ndpi_search_activesync               },
  { RNDPI_PROTOCOL_KERBEROS,                    "Kerberos",                    NULL, ndpi_search_kerberos                 },
  { RNDPI_PROTOCOL_LDAP,                        "LDAP",                        NULL, ndpi_search_ldap                     },
  { RNDPI_PROTOCOL_MAPLESTORY,                  "MapleStory",                  NULL, ndpi_search_maplestory               },
  { RNDPI_PROTOCOL_MSSQL,                       "MsSQL",                       NULL, ndpi_search_mssql                    },
  { RNDPI_PROTOCOL_PPTP,                        "PPTP",                        NULL, ndpi_search_pptp                     },
  { RNDPI_PROTOCOL_WARCRAFT3,                   "Warcraft3",                   NULL, ndpi_search_warcraft3                },
  { RNDPI_PROTOCOL_WORLD_OF_KUNG_FU,            "WorldOfKungFu",               NULL, ndpi_search_world_of_kung_fu         },
  { RNDPI_PROTOCOL_MEEBO,                       "Meebo",                       NULL, ndpi_search_meebo                    },
  { RNDPI_SERVICE_FACEBOOK,                     "Facebook",                    NULL, NULL },
  { RNDPI_SERVICE_TWITTER,                      "Twitter",                     NULL, NULL },
  { RNDPI_PROTOCOL_DROPBOX,                     "DropBox",                     NULL, ndpi_search_dropbox                  },
  { RNDPI_SERVICE_GMAIL,                        "GMail",                       NULL, NULL },
  { RNDPI_SERVICE_GOOGLE_MAPS,                  "GoogleMaps",                  NULL, NULL },
  { RNDPI_SERVICE_YOUTUBE,                      "YouTube",                     NULL, NULL },
  { RNDPI_PROTOCOL_SKYPE,                       "Skype",                       NULL, ndpi_search_skype                    },
  { RNDPI_SERVICE_GOOGLE,                       "Google",                      NULL, NULL },
  { RNDPI_PROTOCOL_DCERPC,                      "DCE_RPC",                     NULL, ndpi_search_dcerpc                   },
  { RNDPI_PROTOCOL_NETFLOW,                     "NetFlow",                     NULL, ndpi_search_netflow                  },
  { RNDPI_PROTOCOL_SFLOW,                       "sFlow",                       NULL, ndpi_search_sflow                    },
  { RNDPI_PROTOCOL_HTTP_CONNECT,                "HTTP_Connect",                NULL, NULL },
  { RNDPI_PROTOCOL_HTTP_PROXY,                  "HTTP_Proxy",                  NULL, NULL },
  { RNDPI_PROTOCOL_CITRIX,                      "Citrix",                      NULL, ndpi_search_citrix                   },
  { RNDPI_SERVICE_NETFLIX,                      "NetFlix",                     NULL, NULL },
  { RNDPI_SERVICE_LASTFM,                       "LastFM",                      NULL, NULL },
  { RNDPI_SERVICE_GROOVESHARK,                  "GrooveShark",                 NULL, NULL },
  { RNDPI_PROTOCOL_SKYFILE_PREPAID,             "SkyFile_PrePaid",             NULL, NULL },
  { RNDPI_PROTOCOL_SKYFILE_RUDICS,              "SkyFile_Rudics",              NULL, NULL },
  { RNDPI_PROTOCOL_SKYFILE_POSTPAID,            "SkyFile_PostPaid",            NULL, NULL },
  { RNDPI_PROTOCOL_CITRIX_ONLINE,               "Citrix_Online",               NULL, ndpi_search_citrix                   },
  { RNDPI_SERVICE_APPLE,                        "Apple",                       NULL, NULL },
  { RNDPI_PROTOCOL_WEBEX,                       "Webex",                       NULL, NULL },
  { RNDPI_SERVICE_WHATSAPP,                     "WhatsApp",                    NULL, NULL },
  { RNDPI_SERVICE_APPLE_ICLOUD,                 "AppleiCloud",                 NULL, NULL },
  { RNDPI_PROTOCOL_VIBER,                       "Viber",                       NULL, ndpi_search_viber                    },
  { RNDPI_SERVICE_APPLE_ITUNES,                 "AppleiTunes",                 NULL, NULL },
  { RNDPI_PROTOCOL_RADIUS,                      "Radius",                      NULL, ndpi_search_radius                   },
  { RNDPI_PROTOCOL_WINDOWS_UPDATE,              "WindowsUpdate",               NULL, NULL },
  { RNDPI_PROTOCOL_TEAMVIEWER,                  "TeamViewer",                  NULL, NULL },
  { RNDPI_SERVICE_TUENTI,                       "Tuenti",                      NULL, NULL },
  { RNDPI_PROTOCOL_LOTUS_NOTES,                 "LotusNotes",                  NULL, ndpi_search_lotus_notes              },
  { RNDPI_PROTOCOL_SAP,                         "SAP",                         NULL, NULL },
  { RNDPI_PROTOCOL_GTP,                         "GTP",                         NULL, ndpi_search_gtp                      },
  { RNDPI_PROTOCOL_UPNP,                        "UPnP",                        NULL, NULL },
  { RNDPI_PROTOCOL_LLMNR,                       "LLMNR",                       NULL, NULL },
  { RNDPI_PROTOCOL_REMOTE_SCAN,                 "RemoteScan",                  NULL, NULL },
  { RNDPI_PROTOCOL_SPOTIFY,                     "Spotify",                     NULL, ndpi_search_spotify                  },
  { RNDPI_CONTENT_WEBM,                         "WebM",                        NULL, NULL },
  { RNDPI_PROTOCOL_H323,                        "H323",                        NULL, ndpi_search_h323                     },
  { RNDPI_PROTOCOL_OPENVPN,                     "OpenVPN",                     NULL, ndpi_search_openvpn                  },
  { RNDPI_PROTOCOL_NOE,                         "NOE",                         NULL, ndpi_search_noe                      },
  { RNDPI_PROTOCOL_CISCOVPN,                    "CiscoVPN",                    NULL, ndpi_search_ciscovpn                 },
  { RNDPI_PROTOCOL_TEAMSPEAK,                   "TeamSpeak",                   NULL, ndpi_search_teamspeak                },
  { RNDPI_PROTOCOL_TOR,                         "TOR",                         NULL, ndpi_search_tor                      },
  { RNDPI_PROTOCOL_SKINNY,                      "CiscoSkinny",                 NULL, ndpi_search_skinny                   },
  { RNDPI_PROTOCOL_RTCP,                        "RTCP",                        NULL, ndpi_search_rtcp                     },
  { RNDPI_PROTOCOL_RSYNC,                       "RSYNC",                       NULL, ndpi_search_rsync                    },
  { RNDPI_PROTOCOL_ORACLE,                      "Oracle",                      NULL, ndpi_search_oracle                   },
  { RNDPI_PROTOCOL_CORBA,                       "Corba",                       NULL, ndpi_search_corba                    },
  { RNDPI_PROTOCOL_UBUNTUONE,                   "UbuntuONE",                   NULL, NULL },
  { RNDPI_PROTOCOL_WHOIS_DAS,                   "Whois-DAS",                   NULL, ndpi_search_whois_das                },
  { RNDPI_PROTOCOL_COLLECTD,                    "Collectd",                    NULL, ndpi_search_collectd                 },
  { RNDPI_PROTOCOL_SOCKS5,                      "SOCKS5",                      NULL, ndpi_search_socks5                   },
  { RNDPI_PROTOCOL_SOCKS4,                      "SOCKS4",                      NULL, ndpi_search_socks4                   },
  { RNDPI_PROTOCOL_RTMP,                        "RTMP",                        NULL, ndpi_search_rtmp                     },
  { RNDPI_PROTOCOL_FTP_DATA,                    "FTP_DATA",                    NULL, ndpi_search_ftp_data                 },
  { RNDPI_SERVICE_WIKIPEDIA,                    "Wikipedia",                   NULL, NULL },
  { RNDPI_PROTOCOL_ZMQ,                         "ZeroMQ",                      NULL, ndpi_search_zmq                      },
  { RNDPI_SERVICE_AMAZON,                       "Amazon",                      NULL, NULL },
  { RNDPI_SERVICE_EBAY,                         "eBay",                        NULL, NULL },
  { RNDPI_SERVICE_CNN,                          "CNN",                         NULL, NULL },
  { RNDPI_PROTOCOL_MEGACO,                      "Megaco",                      NULL, ndpi_search_megaco                   },
  { RNDPI_PROTOCOL_REDIS,                       "Redis",                       NULL, ndpi_search_redis                    },
  { RNDPI_PROTOCOL_PANDO,                       "Pando_Media_Booster",         NULL, ndpi_search_pando                    },
  { RNDPI_PROTOCOL_VHUA,                        "VHUA",                        NULL, ndpi_search_vhua                     },
  { RNDPI_PROTOCOL_TELEGRAM,                    "Telegram",                    NULL, ndpi_search_telegram                 },
  { RNDPI_SERVICE_VEVO,                         "Vevo",                        NULL, NULL },
  { RNDPI_SERVICE_PANDORA,                      "Pandora",                     NULL, NULL },
  { RNDPI_PROTOCOL_QUIC,                        "Quic",                        NULL, ndpi_search_quic                     },
  { RNDPI_PROTOCOL_WHATSAPP_VOICE,              "WhatsApp Voice",              NULL, NULL },
};
#define RNDPI_PROTOCOLS alen(all_protocols)


/* Lookup for a protocol by id in the table */
static rndpi_protocol_t * lookup_by_id (rndpi_id id)
{
  unsigned i;
  for (i = 0; i < RNDPI_PROTOCOLS; i ++)
    if (all_protocols [i] . id == id)
      return & all_protocols [i];
  return NULL;
}


/* Lookup for a protocol by name in the table */
static rndpi_protocol_t * lookup_by_name (char * name)
{
  unsigned i;
  for (i = 0; i < RNDPI_PROTOCOLS; i ++)
    if (! strcmp (all_protocols [i] . name, name))
      return & all_protocols [i];
  return NULL;
}


/* =-=-=-=-=-=-=-=-=-=-=-=- API -=-=-=-=-=-=-=-=-=-=-=-= */


/* =-=-=-=- Protocols -=-=-=-= */

/* Return # of protocols implemented */
unsigned rndpi_protocol_count (void)
{
  return RNDPI_PROTOCOLS;
}


/* Return the protocol name */
char * rndpi_protocol_name (unsigned id)
{
  rndpi_protocol_t * p;

  if (id == RNDPI_PROTOCOL_UNKNOWN)
    return "Unknown";

  p = lookup_by_id (id);
  return p ? p -> name : NULL;
}


/* Return the protocol id */
int rndpi_protocol_id (char * name)
{
  rndpi_protocol_t * p = lookup_by_name (name);
  return p ? p -> id : -1;
}


/* Return the protocol description */
char * rndpi_protocol_description (unsigned id)
{
  rndpi_protocol_t * p = lookup_by_id (id);
  return p && p -> description ? p -> description : "To be defined";
}


/* Return an indication if protocol is implemented */
bool rndpi_protocol_is_implemented (unsigned id)
{
  rndpi_protocol_t * p = lookup_by_id (id);
  return p && p ->  bless;
}


/* Return all protocol names in a NULL terminated array */
char ** rndpi_protocol_names (void)
{
  char ** names = NULL;
  unsigned i;
  for (i = 0; i < RNDPI_PROTOCOLS; i ++)
    names = argsadd (names, all_protocols [i] . name);
  return names;
}


/* Return only not yet implementesd protocols in a NULL terminated array */
char ** rndpi_protocol_not_implemented (void)
{
  char ** names = NULL;
  unsigned i;
  for (i = 0; i < RNDPI_PROTOCOLS; i ++)
    if (! all_protocols [i] . bless)
      names = argsadd (names, all_protocols [i] . name);
  return names;
}


/* Return all protocol name in a list */
rndpi_protocol_list_t * rndpi_protocol_list_alloc (void)
{
  /* Allocate and initialize a list */
  rndpi_protocol_list_t * list = calloc (1, sizeof (rndpi_protocol_list_t));
  TAILQ_INIT (list);
  unsigned i;

  /* Iterate over all protocols */
  for (i = 0; i < RNDPI_PROTOCOLS; i ++)
    {
      /* Allocate and initialize an item */
      rndpi_protocol_item_t * item = calloc (1, sizeof (rndpi_protocol_item_t));
      item -> name = all_protocols [i] . name;
      TAILQ_INSERT_TAIL (list, item, next);
    }

  return list;
}


/* Print all protocol names in a list */
rndpi_protocol_list_t * rndpi_protocol_list_print (rndpi_protocol_list_t * list)
{
  unsigned i = 0;
  rndpi_protocol_item_t * item;
  rndpi_protocol_item_t * next;

  if (! list)
    return NULL;

  /* Iterate over all items of the list */
  for (item = TAILQ_FIRST (list); item; item = next)
    {
      printf ("%3u: %s\n", ++ i, item -> name);
      next = TAILQ_NEXT (item, next);
    }
  return list;
}


/* Free all memory allocated to keep protocol names in a list */
rndpi_protocol_list_t * rndpi_protocol_list_free (rndpi_protocol_list_t * list)
{
  rndpi_protocol_item_t * item;
  rndpi_protocol_item_t * next;

  if (! list)
    return NULL;

  /* Iterate over all items of the list */
  for (item = TAILQ_FIRST (list); item; item = next)
    {
      next = TAILQ_NEXT (item, next);
      free (item);
    }
  free (list);
  return NULL;
}


#if defined(ROCCO)

/* Bless an IPv4 packet */
unsigned rndpi_bless_ipv4_pkt (void * pkt, uint32_t len)
{
  unsigned i;

  for (i = 0; i < RNDPI_PROTOCOLS; i ++)
    {
      /* Initialize nDPI library */
      void * ndpi = ndpi_init ();

      if (all_protocols [i] . guess)
	{
	  uint16_t deep;

	  /* Alloc flow */
	  void * flow = ndpi_flow_alloc ();

	  /* Bind the packet to the flow */
	  ndpi_bind_ipv4_packet (pkt, len, flow);

	  printf ("Trying %s ...\n", all_protocols [i] . name);

	  (* all_protocols [i] . guess) (ndpi, flow);

	  deep = ndpi_protocol (flow);
	  if (deep)
	    ;

	  /* Free flow */
	  ndpi_flow_free (free);

	}

      /* Terminate nDPI library */
      ndpi_term (ndpi);
    }

  return RNDPI_PROTOCOL_UNKNOWN;
}

#else

/* Bless an IPv4 packet */
int rndpi_bless_ipv4_pkt (void * ipv4, uint32_t len)
{
  void * ndpi;
  void * flow;

  if (! ipv4 || len <= sizeof (struct iphdr))
    return -1;

  /* Initialize nDPI library */
  ndpi = ndpi_init ();
  flow = ndpi_flow_alloc ();         /* A flow is alwyas required by the underlaying nDPI functions */

  /* Attempt to bless the IPv4 packet */
  uint16_t deep = ndpi_ipv4_pkt (ipv4, len, ndpi, flow);

  /* Free flow and terminate nDPI library */
  ndpi_flow_free (flow);
  ndpi_term (ndpi);

  return deep;
}

#endif /* ROCCO */


/* Get rnNDPI handle */
rndpi_t * rndpi_alloc (void)
{
  rndpi_t * rndpi = calloc (1, sizeof (struct rndpi));
  rndpi -> handle = ndpi_init ();                      /* Initialize nDPI library */
  return rndpi;
}


/* Release rnNDPI handle */
void rndpi_free (rndpi_t * rndpi)
{
  if (! rndpi)
    return;

  ndpi_term (rndpi -> handle);                         /* Terminate nDPI library */
  free (rndpi);
}


/* Deep an IPv4 packet over a handle */
int rndpi_deep_ipv4_pkt (rndpi_t * rndpi, void * ipv4, uint32_t len)
{
  void * flow;
  uint16_t deep;

  if (! rndpi || ! ipv4 || len <= sizeof (struct iphdr))
    return -1;

  /* A flow is alwyas required by the underlaying nDPI functions */
  flow = ndpi_flow_alloc ();

  /* Attempt to bless the IPv4 packet */
  deep = ndpi_ipv4_pkt (ipv4, len, rndpi -> handle, flow);

  /*
   * Warning:
   *  Identifiers need to be mapped due to different position of UNKNOWN in the tables
   */
  if (! deep)
    deep = RNDPI_PROTOCOL_UNKNOWN;
  else
    deep = deep - 1;

  /* Free flow */
  ndpi_flow_free (flow);

  return deep;
}
