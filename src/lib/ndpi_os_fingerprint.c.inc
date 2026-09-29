/*
  TCP fingerprints (NDPI_NATIVE_TCP_FINGERPRINT) -> OS hint

  The comment reports the raw options string (metadata.tcp_fingerprint_raw)
  of each fingerprint: please keep it also for new entries, so that the
  database can be recomputed if the fingerprint format changes.

  Note: 96500ba614e1 is used by both macOS and iOS/iPadOS
*/
static struct os_fingerprint tcp_fps[] = {
    { "2_64_65535_defa183edeca",     ndpi_os_freebsd      }, /* 020103060408 */

    { "2_64_64800_5ec4846073b9",     ndpi_os_linux        }, /* 020408010307 */
    { "2_64_64240_5ec4846073b9",     ndpi_os_linux        }, /* 020408010307 */
    { "2_64_29200_5ec4846073b9",     ndpi_os_linux        }, /* 020408010307 */
    { "2_64_29200_96f084d7f50c",     ndpi_os_linux        }, /* 020408010305 */
    { "2_64_14600_b88686e220ac",     ndpi_os_linux        }, /* 020408010306 */
    { "2_64_32120_5ec4846073b9",     ndpi_os_linux        }, /* 020408010307 */
    { "2_64_64240_9ade5ea639dd",     ndpi_os_linux        }, /* 020408010308 */

    { "2_64_65535_8b4e598a2ef6",     ndpi_os_android      }, /* 02040801030a */
    { "2_64_65535_25d42dd21321",     ndpi_os_android      }, /* 020408010309 */
    { "2_64_65535_9ade5ea639dd",     ndpi_os_android      }, /* 020408010308 */
    { "2_64_65535_5ec4846073b9",     ndpi_os_android      }, /* 020408010307 */

    { "2_128_64240_e035a9f8f3a0",    ndpi_os_windows      }, /* 02010308010104 */
    { "2_128_8192_4973d993fb4a",     ndpi_os_windows      }, /* 02010302010104 */
    { "194_128_64240_e035a9f8f3a0",  ndpi_os_windows      }, /* 02010308010104 */
    { "194_128_32768_6b34051d2fbf",  ndpi_os_windows      }, /* 02010300010104 */
    { "2_128_32768_6b34051d2fbf",    ndpi_os_windows      }, /* 02010300010104 */
    { "2_128_65535_e035a9f8f3a0",    ndpi_os_windows      }, /* 02010308010104 */
    { "194_128_32_6b34051d2fbf",     ndpi_os_windows      }, /* 02010300010104 */
    { "194_128_64954_e035a9f8f3a0",  ndpi_os_windows      }, /* 02010308010104 */
    { "194_128_65160_55a079b2ce62",  ndpi_os_windows      }, /* 020103080408 */
    { "194_128_65340_e035a9f8f3a0",  ndpi_os_windows      }, /* 02010308010104 */
    { "194_128_65535_a717f7945d0a",  ndpi_os_windows      }, /* 02010303010104 */
    { "194_128_65535_e035a9f8f3a0",  ndpi_os_windows      }, /* 02010308010104 */
    { "194_128_65535_da2db3bc812e",  ndpi_os_windows      }, /* 02010305010104 */
    { "194_128_8192_6b34051d2fbf",   ndpi_os_windows      }, /* 02010300010104 */
    { "2_128_62636_55a079b2ce62",    ndpi_os_windows      }, /* 020103080408 */
    { "2_128_62720_e035a9f8f3a0",    ndpi_os_windows      }, /* 02010308010104 */
    { "2_128_64390_55a079b2ce62",    ndpi_os_windows      }, /* 020103080408 */
    { "2_128_64512_55a079b2ce62",    ndpi_os_windows      }, /* 020103080408 */
    { "2_128_64668_e035a9f8f3a0",    ndpi_os_windows      }, /* 02010308010104 */
    { "2_128_64872_e035a9f8f3a0",    ndpi_os_windows      }, /* 02010308010104 */
    { "2_128_65010_e035a9f8f3a0",    ndpi_os_windows      }, /* 02010308010104 */
    { "2_128_65088_e035a9f8f3a0",    ndpi_os_windows      }, /* 02010308010104 */
    { "2_128_65160_55a079b2ce62",    ndpi_os_windows      }, /* 020103080408 */
    { "2_128_65312_55a079b2ce62",    ndpi_os_windows      }, /* 020103080408 */
    { "2_128_65424_e035a9f8f3a0",    ndpi_os_windows      }, /* 02010308010104 */
    { "2_128_65520_55a079b2ce62",    ndpi_os_windows      }, /* 020103080408 */
    { "2_128_65535_3623b899804f",    ndpi_os_windows      }, /* 02010307010104 */
    { "2_128_65535_55a079b2ce62",    ndpi_os_windows      }, /* 020103080408 */
    { "2_128_65535_e2026928e080",    ndpi_os_windows      }, /* 02010301010104 */

    { "194_64_65535_fa6f8edaadeb",   ndpi_os_ios_ipad_os  }, /* 020103050101080400 */

    { "194_64_65535_96500ba614e1",   ndpi_os_macos        }, /* 020103060101080400 */
    { "2_64_65535_96500ba614e1",     ndpi_os_macos        }, /* 020103060101080400 */
    { "2_64_0_96500ba614e1",         ndpi_os_macos        }, /* 020103060101080400 */
    { "2_64_65535_4fcd627e5690",     ndpi_os_macos        }, /* 020103040101080400 */

    { NULL,                         ndpi_os_unknown     },
  };
