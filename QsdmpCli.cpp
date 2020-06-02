#include "QsdmpCli.h"
#include "Ylog.h"
#include <cstring>
#include <immintrin.h>


#define CLIENTTICKRATE        40

QsdmpCli::QsdmpCli(const int _fd, const DID_Type &_did, const CID_Type &_cid, const uint8_t *devk,
				   const uint8_t *headerk)
		:
		Ypacker(_fd),
		did(_did),
		cid(_cid) {
	lastactive = time(nullptr);
	loadHeaderKey(headerk);
	loadDevk(devk);
}

QsdmpCli::~QsdmpCli() {

}

Ypollact_Type QsdmpCli::sendReq(void) {
	Ypack<0xFF0> pack;
	pack.did = did;
	pack.cid = CID_AUTH_REQ;
	pack.CBC_lowLen = 2;
	pack.sessionID = 0;
	pack.highLen = 0;
//	pack.print(YLOG_DEBUG);
	authReq(pack.data);
	PRINTLOGF(YLOG_DEBUG, "QsdmpCli::auth request send did=0x%016lX\n", did);
	return sendPack(&pack);
}

Ypollact_Type QsdmpCli::sendTck(void) {
	auto timenow = time(nullptr);
	if (lastactive + CLIENTTICKRATE <= timenow) {
		lastactive = timenow;
		Ypack<0xFF0> pack;
		pack.did = did;
		pack.cid = CID_AUTH_TCK;
		pack.CBC_lowLen = 1;
		pack.sessionID = 0;
		pack.highLen = 0;
		auto pt = (unsigned long long *)pack.data;
		_rdrand64_step(pt++);
		_rdrand64_step(pt);
		return sendPack(&pack);
	} else {
		return YPA_NULL;
	}
}

Ypollact_Type
QsdmpCli::sendto(const DID_Type &_did, const CID_Type &_cid, const uint8_t *data, uint32_t len, uint32_t sessionID) {
	lastactive = time(nullptr);
	Ypack<0xFF0> pack;
	pack.did = _did;
	pack.cid = _cid;
	uint16_t CBC;
	if (Encrypt(data, len, pack.data, CBC, sessionID) == 0) {
		pack.CBC_lowLen = CBC;
		pack.highLen = 0;
		return sendPack(&pack);
	} else {
		return YPA_SENDFAIL;
	}

}

Ypollact_Type QsdmpCli::send(const uint8_t *data, uint32_t len, uint32_t sessionID) {
	return sendto(did, cid, data, len, sessionID);
}

Ypollact_Type QsdmpCli::packHandle(Ypack<0xFF0> *pack) {
	if (pack->did == did) {
		if ((pack->cid & CID_VAL_MASK) <= CID_AUTH_END) {
			switch (pack->cid & CID_VAL_MASK) {
				case (CID_AUTH_ASR): {
					if (pack->CBC_lowLen == 2) {
						if (authAsrAck(pack->data) == 0) {
							pack->cid = CID_AUTH_ACK;
							pack->CBC_lowLen = 1;
							pack->highLen = 0;
							auto rtn = sendPack(pack);
							upevent_cb();
							return rtn;
						} else {
							return YPA_TERMINATE;
						}
					} else {
						return YPA_TERMINATE;
					}
				}
					break;
				case (CID_AUTH_TCK): {
					if (auth >= AUTH_OK) {
						if (pack->CBC_lowLen == 1) {
							time_t svrtime;
							memcpy(&svrtime, pack->data, sizeof(time_t));
							authTck_cb(svrtime);
							return 0;
						} else {
							return YPA_TERMINATE;
						}
					} else {
						return YPA_TERMINATE;
					}
				}
					break;
				case (CID_AUTH_UDK): {
					if (auth >= AUTH_OK) {
						if (Decrypt(pack->data, pack->CBC_lowLen, pack->sessionID) == 16) {
							pack->CBC_lowLen = 0;
							pack->highLen = 0;
							if (authUDK(pack->data) != 0) {
								pack->cid |= CID_ERR_MASK;
							}
							return sendPack(pack);
						} else {
							return YPA_TERMINATE;
						}
					} else {
						return YPA_TERMINATE;
					}
				}
					break;
				case (CID_AUTH_SSW): {
					if (auth >= AUTH_OK) {
						auto len = Decrypt(pack->data, pack->CBC_lowLen, pack->sessionID);
						if (len >= 5) {
							pack->CBC_lowLen = 0;
							pack->highLen = 0;
							if (authSSW(pack->data, (uint32_t) len) != 0) {
								pack->cid |= CID_ERR_MASK;
							}
							return sendPack(pack);
						} else {
							return YPA_TERMINATE;
						}
					} else {
						return YPA_TERMINATE;
					}
				}
					break;
				case (CID_AUTH_STR): {
					if (auth >= AUTH_OK) {
						pack->cid |= CID_ERR_MASK;
						pack->CBC_lowLen = 0;
						pack->highLen = 0;
						return sendPack(pack);
					} else {
						return YPA_TERMINATE;
					}
				}
					break;
				default: {
					return YPA_TERMINATE;
				}
					break;
			}
		} else if (pack->cid == cid) {
			if (auth >= AUTH_OK) {
				if (packDecrypt(pack) > 0) {
					return mypackdata(pack);
				} else {
					return YPA_TERMINATE;
				}
			} else {
				return YPA_TERMINATE;
			}
		} else {
			return YPA_TERMINATE;
		}
	} else if (auth >= AUTH_OK) {
		if (packDecrypt(pack) > 0) {
			return notmypack(pack);
		} else {
			return YPA_TERMINATE;
		}
	} else {
		return YPA_TERMINATE;
	}
}

void QsdmpCli::loadDevk(const uint8_t *aesk) {
	AES_set_encrypt_key(aesk, 128, &ek);
	AES_set_decrypt_key(aesk, 128, &dk);
	loadKey(&ek, &dk);
}

Ypollact_Type QsdmpCli::mypackdata(Ypack<0xFF0> *pack) {
//	printf("mypackdata, data=%s\n", data);
	return YPA_NULL;
}

Ypollact_Type QsdmpCli::notmypack(Ypack<0xFF0> *pack) {
//	printf("notmypack, data=%s\n", pack->data);
	return YPA_NULL;
}

void QsdmpCli::upevent_cb(void) {
//	printf("upevent_cb\n");
}

void QsdmpCli::authTck_cb(time_t &svrtime) {
	return;
}

