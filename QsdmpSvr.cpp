#include "QsdmpSvr.h"
#include "Ylog.h"
#include "rediscli.h"
#include <immintrin.h>
#include <cstring>

QsdmpSvr::QsdmpSvr(const uint64_t &_did) :
		did(_did) {
	auto rtn = loadk();
	if (1 == rtn) {
		defaultK = true;
	} else if (0 == rtn) {
		defaultK = false;
	} else {
		PRINTLOGF(YLOG_ALERT, "QsdmpSvr::QsdmpSvr unable to get aesk!did=0x%016lX\n", did);
		exit(-1);
	}
}

QsdmpSvr::~QsdmpSvr() {

}

size_t QsdmpSvr::rmport(const int _fd) {
	portTable.erase(_fd);
	return portTable.size();
}

size_t QsdmpSvr::rmport(const sockaddr_in &addr) {
	auto key = addrToKey(addr);
	UDPportTable.erase(key);
	return UDPportTable.size();
}

extern uint64_t SuperDID;

QsdmpSvr::lnk_event QsdmpSvr::SecPackHandle(encryption &port, Ypack<0xFF0> *packin, Ypack<0xFF0> *&packBack) {
	if ((packin->cid & CID_VAL_MASK) <= CID_AUTH_END and packin->did == this->did) {
		switch (packin->cid & CID_VAL_MASK) {
			case (CID_AUTH_REQ): {
				if (packin->CBC_lowLen == 2) {
					if (0 == port.authReqAsr(packin->data)) {
						packBack = packin;
						packBack->cid = CID_AUTH_ASR;
						packBack->CBC_lowLen = 2;
						return LNK_EVENT_NUN;
					} else {
						return LNK_EVENT_ERROR;
					}
				} else {
					return LNK_EVENT_ERROR;
				}
			}
				break;

			case (CID_AUTH_ACK): {
				if (packin->CBC_lowLen == 1) {
					if (0 == port.authAck(packin->data)) {
						return LNK_EVENT_UP;
					} else {
						return LNK_EVENT_ERROR;
					}
				} else {
					return LNK_EVENT_ERROR;
				}
			}
				break;

			case (CID_AUTH_TCK): {
				if (port.auth > AUTH_NA) {
					if (packin->CBC_lowLen == 1) {
						packBack = packin;
						auto timeNow = time(nullptr);
						memcpy(packBack->data, &timeNow, sizeof(timeNow));
						memcpy(packBack->data + 8, &timeNow, sizeof(timeNow));
						return LNK_EVENT_NUN;
					} else {
						return LNK_EVENT_ERROR;
					}
				} else {
					return LNK_EVENT_ERROR;
				}
			}
				break;

			case (CID_AUTH_UDK): {
				if (port.auth > AUTH_NA) {
					if (packin->cid & CID_ERR_MASK) {
						return LNK_EVENT_SETAESKFAIL;
					} else {
						return LNK_EVENT_SETAESKOK;
					}
				} else {
					return LNK_EVENT_ERROR;
				}
			}
				break;

			case (CID_AUTH_SSW): {
				if (port.auth > AUTH_NA) {
					if (packin->cid & CID_ERR_MASK) {
						return LNK_EVENT_SWSVRFAIL;
					} else {
						return LNK_EVENT_SWSVROK;
					}
				} else {
					return LNK_EVENT_ERROR;
				}
			}
				break;

			case (CID_AUTH_STR): {
				if (port.auth > AUTH_NA) {
					return LNK_EVENT_SETTCKRATEOK;
				} else {
					return LNK_EVENT_SETTCKRATEFAIL;
				}
			}
				break;

			default: {
				return LNK_EVENT_ERROR;
			}
				break;
		}
	} else {
		if (port.auth > AUTH_NA and (packin->cid & CID_VAL_MASK) > CID_AUTH_END) {
			auto packLength = port.Decrypt(packin->data, packin->CBC_lowLen, packin->sessionID);
			if (packLength > 0) {
				packin->set_length((uint32_t) packLength);
				return LNK_EVENT_APPDATAIN;
			} else {
				PRINTLOGF(YLOG_WARNING, "Decrypt fail! did=0x%016lX, cid=0x%02X\n", packin->did, packin->cid);
				return LNK_EVENT_ERROR;
			}
		} else {
			PRINTLOGF(YLOG_WARNING, "un authorized app packin did=0x%016lX, cid=0x%02X\n", packin->did, packin->cid);
			return LNK_EVENT_ERROR;
		}
	}
}


QsdmpSvr::lnk_event QsdmpSvr::SecPackHandle(const int &_fd, Ypack<0xFF0> *packin, Ypack<0xFF0> *&packBack) {
	if (portTable.count(_fd)) {
		return SecPackHandle(portTable[_fd], packin, packBack);
	} else {
		if (packin->cid == CID_AUTH_REQ and packin->did == this->did) {
			if (packin->CBC_lowLen == 2) {
				auto &port = portTable[_fd];
				port.loadKey(&ek, &dk);        //create port in portTable
				if (0 == port.authReqAsr(packin->data)) {
					packBack = packin;
					packBack->cid = CID_AUTH_ASR;
					packBack->CBC_lowLen = 2;
					return LNK_EVENT_NUN;
				} else {
					return LNK_EVENT_ERROR;
				}
			} else {
				return LNK_EVENT_ERROR;
			}
		} else {
			return LNK_EVENT_ERROR;
		}
	}
}

QsdmpSvr::lnk_event QsdmpSvr::SecPackHandle(const sockaddr_in &addr, Ypack<0xFF0> *packin, Ypack<0xFF0> *&packBack) {
	auto key = addrToKey(addr);
	if (UDPportTable.count(key)) {
		return SecPackHandle(UDPportTable[key], packin, packBack);
	} else {
		if (packin->cid == CID_AUTH_REQ and packin->did == this->did) {
			if (packin->CBC_lowLen == 2) {
				auto &port = UDPportTable[key];
				port.loadKey(&ek, &dk);        //create port in portTable
				if (0 == port.authReqAsr(packin->data)) {
					packBack = packin;
					packBack->cid = CID_AUTH_ASR;
					packBack->CBC_lowLen = 2;
					return LNK_EVENT_NUN;
				} else {
					return LNK_EVENT_ERROR;
				}
			} else {
				return LNK_EVENT_ERROR;
			}
		} else {
			return LNK_EVENT_ERROR;
		}
	}
}

int QsdmpSvr::loadk(void) {
	int rtn;
	uint8_t aesk[16];
	if (rdb.getaesk(aesk, did) == 0) {
		rtn = 0;
	} else if (rdb.getaesk(aesk, DEFAULTAESKDID) == 0) {
		rtn = 1;
	} else {
		rtn = -1;
	}
	AES_set_encrypt_key(aesk, 128, &ek);
	AES_set_decrypt_key(aesk, 128, &dk);
	return rtn;
}

bool QsdmpSvr::isdefaultk(void) const {
	return defaultK;
}

int QsdmpSvr::dataEncrypt(const int _fd, const uint8_t *textdata, const uint32_t &textsize, uint8_t *chpherdata,
						  uint16_t &outCBC, uint32_t sessionID) {
	if (portTable.count(_fd)) {
		return portTable[_fd].Encrypt(textdata, textsize, chpherdata, outCBC, sessionID);
	}
	return -1;
}

int
QsdmpSvr::dataEncrypt(const sockaddr_in &addr, const uint8_t *textdata, const uint32_t &textsize, uint8_t *chpherdata,
					  uint16_t &outCBC, uint32_t sessionID) {
	auto key = addrToKey(addr);
	if (UDPportTable.count(key)) {
		return UDPportTable[key].Encrypt(textdata, textsize, chpherdata, outCBC, sessionID);
	}
	return -1;
}

int QsdmpSvr::setEvtPort(const int _fd) {
	if (portTable.count(_fd)) {
		if (portTable[_fd].auth >= AUTH_OK) {
			portTable[_fd].auth = AUTH_EVTPORT;
			return 0;
		}
	}
	return -1;
}

uint64_t addrToKey(const sockaddr_in &addr) {
	return addr.sin_port * 0x100000000U + addr.sin_addr.s_addr;
}

sockaddr_in keyToAddr(const uint64_t &key) {
	sockaddr_in local_sin;
	local_sin.sin_family = AF_INET;
	local_sin.sin_port = (uint16_t) (key >> 32U);
	local_sin.sin_addr.s_addr = (uint32_t) (key & 0xffffffff);
	return local_sin;
}

