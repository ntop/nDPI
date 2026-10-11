/*
  TCP fingerprints (NDPI_NATIVE_TCP_FINGERPRINT) -> OS hint

  The comment reports the raw options string (metadata.tcp_fingerprint_raw)
  of each fingerprint: please keep it also for new entries, so that the
  database can be recomputed if the fingerprint format changes.
*/
static struct os_fingerprint tcp_fps[] = {
  { "2_64_65535_2b9b4c52",     ndpi_os_freebsd      }, /* 2,1,3:6,4,8 - fp_tcp_freebsd15.pcap */

  { "2_64_64240_789c1d1f",     ndpi_os_linux        }, /* 2,4,8,1,3:7 - fp_tcp_linux_ubuntu24.pcap */

  { "2_64_65535_58b6a464",     ndpi_os_android      }, /* 2,4,8,1,3:10 - fp_tcp_android13.pcapng / fp_tcp_android16.pcapng */

  { "194_64_65535_e76f0f14",   ndpi_os_apple        }, /* 2,1,3:6,1,1,8,4,0 - fp_tcp_macos27.pcapng / fp_tcp_iPadOS27.pcapng */
  { "2_64_65535_e76f0f14",     ndpi_os_apple        }, /* 2,1,3:6,1,1,8,4,0 - fp_tcp_iOS27_iphone.pcapng / fp_tcp_iOS18_iPad.pcapng */
  { "194_64_65535_2b6d3038",   ndpi_os_apple        }, /* 2,1,3:5,1,1,8,4,0 - fp_tcp_iOS15_iPhone.pcapng */

  { "2_128_64240_47466ece",    ndpi_os_windows      }, /* 2,1,3:8,1,1,4 - fp_tcp_win10.pcapng */
  { "2_128_65535_47466ece",    ndpi_os_windows      }, /* 2,1,3:8,1,1,4 - fp_tcp_win11.pcapng */

  { NULL,                      ndpi_os_unknown     },
};
