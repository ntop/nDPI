#ifndef _NDPI_CRC_
#define _NDPI_CRC_

u_int16_t ndpi_crc16_ccit(const void* data, size_t n_bytes);
u_int16_t ndpi_crc16_ccit_false(const void *data, size_t n_bytes);
u_int16_t ndpi_crc16_xmodem(const void *data, size_t n_bytes);

#endif
