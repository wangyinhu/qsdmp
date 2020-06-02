#include "Ypacker.h"
#include "Ylog.h"
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <immintrin.h>


#ifdef YPACKMEMORYLEAKDEBUG
uint64_t packmemcount = 0;
#endif //YPACKMEMORYLEAKDEBUG


//=================================================================================

#ifdef YPACKERMEMORYLEAKDEBUG
static uint64_t packercounter = 0;
#endif //YPACKERMEMORYLEAKDEBUG


Ypacker::Ypacker(const int _fd) {
	fd = _fd;
#ifdef YPACKERMEMORYLEAKDEBUG
	PRINTLOGF(YLOG_DEBUG, "Ypacker construct fd=%d, packernumber=%lu\n", fd, ++packercounter);
#endif //YPACKERMEMORYLEAKDEBUG
}

Ypacker::~Ypacker() {
#ifdef YPACKERMEMORYLEAKDEBUG
	PRINTLOGF(YLOG_DEBUG, "Ypacker distruct fd=%d, packernumber=%lu\n", fd, --packercounter);
#endif //YPACKERMEMORYLEAKDEBUG
}

/**
 *
 * @param _pack: accept CBC as length
 * @return
 */
Ypollact_Type Ypacker::sendPack(Ypack<0xFF0> *_pack) {
	auto sizep = packup(_pack);
	PRINTLOGF(YLOG_DEBUG, "Ypacker sendPack fd=%d, data length=%d, data=\n", fd, sizep);
	PRINTLOGB(YLOG_DEBUG, _pack, sizep);
	if (outbuff.size() == 0) {
		auto count = write(fd, _pack, sizep);
		if (count < 0) {
			if (errno == EAGAIN) {
				outbuff.append((uint8_t *) _pack, sizep);
				return YPA_OUTSWON;
			} else {
				PRINTLOGF(YLOG_NOTICE, "In Ypacker::sendPack() write()  error=%s\n", strerror(errno));
				return YPA_TERMINATE;
			}
		} else {
			if (count == sizep) {
				return YPA_NULL;
			} else {
				outbuff.append(((uint8_t *) _pack) + count, sizep - count);
				return YPA_OUTSWON;
			}
		}
	} else {
		outbuff.append((uint8_t *)_pack, sizep);
		return YPA_NULL;
	}
}

Ypollact_Type Ypacker::readyWrite(void) {
	if (not outbuff.empty()) {
		auto count = write(fd, outbuff.data(), outbuff.size());
		if (count < 0) {
			if (errno == EAGAIN) {
				return YPA_NULL;
			} else {
				PRINTLOGF(YLOG_NOTICE, "In Ypacker::readyWrite() write() error=%s\n", strerror(errno));
				return YPA_TERMINATE;
			}
		} else if ((unsigned) count == outbuff.size()) {
			outbuff.clear();
			return YPA_OUTSWOFF;
		} else {
			outbuff.cuthead(count);
			return YPA_NULL;
		}
	} else {
		return YPA_OUTSWOFF;
	}
}


/**
 * @return total length of encrypted pack. including header length
 */
uint32_t packup(Ypack<0xFF0> *_pack) {
	Yphead headmem;
	headmem.cid = _pack->cid;
	headmem.did = _pack->did;
	if (_pack->CBC_lowLen <= 0xF) {
		headmem.ver = YPVER_TINY;
	} else if (_pack->CBC_lowLen <= 0xFF) {
		headmem.ver = YPVER_BASIC;
	} else {
		headmem.ver = YPVER_EXT;
	}
	headmem.bnc = _pack->CBC_lowLen;
	headmem.ZERO = 0;
	unsigned long long longRand;
	_rdrand64_step(&longRand);
	headmem.VAR = (uint16_t)longRand;
	AES_encrypt(headmem.bytes, _pack->head_bytes, &Ypacker::ek);            //encrypt pack->header
	return headmem.bnc * 16u + sizeof(Yphead);
}

Ypollact_Type Ypacker::getSecPacks(std::list<Ypack<0xFF0> *> &packlist) {
	while (true) {
		auto buf = new Ypack<0xFF0>;
		auto count = read(fd, buf, sizeof(Ypack<0xFF0>));
		if (count > 0) {
			if (0 == getPacksFromData(packlist, buf, count)) {
				if (count != sizeof(Ypack<0xFF0>)) {
					//For stream-oriented files, For example, if you call read(2) by
					//asking to read a certain amount of data and read(2) returns a
					//lower number of bytes, you can be sure of having exhausted the
					//read I/O space for the file descriptor. 
					return YPA_NULL;
				} else {
					int leftsize;
					ioctl(fd, FIONREAD, &leftsize);
					if (leftsize) {
						continue;
					} else {
						return YPA_NULL;
					}
				}

			} else {
				return YPA_TERMINATE;
			}
		} else if (count < 0) {
			delete buf;
			/* If errno == EAGAIN, that means we have read all data. So go back to the main loop. */
			if (errno == EAGAIN) {
				//read complete
				return YPA_NULL;
			} else {
				PRINTLOGF(YLOG_DEBUG, "error reading device connection error=%s\n", strerror(errno));
				return YPA_TERMINATE;
			}
		} else {
			delete buf;
			/* (count == 0) End of file. The remote has closed the connection. */
			return YPA_TERMINATE;
		}
	}
}

bool isHeadValid(const Yphead &headmem) {
	return (((headmem.ver == YPVER_TINY) and (headmem.bnc <= 0xF))
			or ((headmem.ver == YPVER_BASIC) and (headmem.bnc <= 0xFF))
			or ((headmem.ver == YPVER_EXT) and (headmem.bnc > 0xFF))) and headmem.ZERO == 0;
}

/**
 *
 * @param _data pack header data pointer
 * @return on success return the total length of the whole pack, on fail return -1;
 */
int headDecrypt(uint8_t *_data) {
	Yphead headMem;
	AES_decrypt(_data, headMem.bytes, &Ypacker::dk);
	if (isHeadValid(headMem)) {
		((Ypack<0xFF0> *) _data)->did = headMem.did;
		((Ypack<0xFF0> *) _data)->cid = headMem.cid;
		((Ypack<0xFF0> *) _data)->CBC_lowLen = headMem.bnc;
		((Ypack<0xFF0> *) _data)->sessionID = 0;
		return headMem.bnc * 16U + 16U;            // data cipher size + header block size.
	} else {
		return -1;
	}
}

/**
 * 		, memory is located outside the function
 * @param packlist
 * @param _data
 * @param len
 * @return
 */
int Ypacker::getPacksFromData(std::list<Ypack<0xFF0> *> &packlist, Ypack<0xFF0> *_data, uint32_t len) {
	if (len >= sizeof(Yphead)) {
		auto packLength = headDecrypt((uint8_t *) _data);
		if (packLength == -1) {
			if (inbuff.empty()) {
				PRINTLOGF(YLOG_WARNING, "error! encrypted pack header not valid.1\n"
										"inbuff is empty, incoming data size > sizeof(Yphead),"
										"incoming data header decryption fail.\ndata=");
				PRINTLOGB(YLOG_WARNING, _data, len);
				delete _data;
				return -1;
			} else if (inbuff.size() >= sizeof(Yphead)) {        //in buffer header already decrypted.
				inbuff.append((uint8_t *)_data, len);
				return getPacksFromBuffer(packlist, _data);
			} else {    // older buffer too small to decrypt,
				inbuff.append((uint8_t *)_data, len);
				//after append new data, buffer is big enough to decrypt. because len >= sizeof(Yphead)
				if (-1 == headDecrypt((uint8_t *) inbuff.data())) {
					delete _data;
					PRINTLOGF(YLOG_WARNING, "error! encrypted pack header not valid.2\n"
											"inbuff not empty, small inbuff, after add new data, "
											"inbuff header decryption fail.\ndata=\n");
					PRINTLOGB(YLOG_WARNING, inbuff.data(), inbuff.size());
					inbuff.clear();
					return -1;
				} else {
					return getPacksFromBuffer(packlist, _data);
				}
			}
		} else {
			inbuff.clear();
			if (len >= packLength) {		//ok because len > 0
				packlist.push_back(_data);
				auto leftLength = len - packLength;
				if (leftLength) {
					auto buf = new Ypack<0xFF0>;
					memcpy(buf, ((uint8_t *) _data) + packLength, leftLength);
					return getPacksFromData(packlist, buf, leftLength);
				} else {
					return 0;
				}
			} else {
				inbuff.append((uint8_t *)_data, len);
				delete _data;
				return 0;
			}
		}
	} else {
		//small pack received
		if (inbuff.size() >= sizeof(Yphead)) {
			inbuff.append((uint8_t *)_data, len);
			return getPacksFromBuffer(packlist, _data);
		} else {
			inbuff.append((uint8_t *)_data, len);
			if (inbuff.size() >= sizeof(Yphead)) {
				if (-1 == headDecrypt((uint8_t *) inbuff.data())) {
					PRINTLOGF(YLOG_WARNING, "error! encrypted pack header not valid.3"
											"small inbuff, after append small new data, len >= sizeof(Yphead),"
											"inbuff header decryption fail.\ndata=");
					PRINTLOGB(YLOG_WARNING, inbuff.data(), inbuff.size());
					inbuff.clear();
					delete _data;
					return -1;
				} else {
					return getPacksFromBuffer(packlist, _data);
				}
			} else {
				delete _data;
				return 0;
			}
		}
	}
}

/**
 * Now inbuff is bigger than sizeof(Yphead),and head is decrypted.
 * @param packlist
 * @param buf
 * @return
 */
int Ypacker::getPacksFromBuffer(std::list<Ypack<0xFF0> *> &packlist, Ypack<0xFF0> *buf) {
	while (true) {
		auto bufpack = (Ypack<0xFF0> *) inbuff.data();
		auto packLength = bufpack->CBC_lowLen * 16u + sizeof(Yphead);
		if (packLength <= inbuff.size()) {
			memcpy(buf, bufpack, packLength);
			inbuff.cuthead(packLength);
			packlist.push_back(buf);
			if (inbuff.size() < sizeof(Yphead)) {
				return 0;
			} else {
				if (headDecrypt((uint8_t *) inbuff.data())) {
					buf = new Ypack<0xFF0>;
					continue;
				} else {
					return -1;
				}
			}
		} else {
			delete buf;     // no pack extracted wait next data in
			return 0;
		}
	}
}

AES_KEY Ypacker::ek;
AES_KEY Ypacker::dk;

void Ypacker::loadHeaderKey(const uint8_t *aesk) {
	AES_set_encrypt_key(aesk, 128, &ek);
	AES_set_decrypt_key(aesk, 128, &dk);
}

