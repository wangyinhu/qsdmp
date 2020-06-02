#ifndef YLIB_H
#define YLIB_H

#include <netdb.h>
#include <stdint.h>

char *addrtostr(const sockaddr &_addr);

size_t hex2raw(uint8_t *raw, const char *hex, size_t hexsize = UINT64_MAX);

void raw2hex(char *hex, const uint8_t *raw, size_t rawsize);

uint8_t xor_checksum(uint8_t xorvalue, const uint8_t *msg_ptr, uint32_t len);

int make_socket_non_blocking(const int _fd);

int setrcvtimeo(int fd, time_t sec, suseconds_t usec);

uint32_t crc32(uint32_t init, const uint8_t *buf, int len);

#endif // YLIB_H


