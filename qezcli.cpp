#include "qezcli.h"
#include "Ylog.h"
#include <string.h>
#include <unistd.h>
#include "Ylib.h"
#include "supercmds.h"



qezcli::qezcli(const char *_host, const int _port, const DID_Type &_did, const CID_Type &_cid, const uint8_t *devk,
			   const uint8_t *headerk, const int timeout) :
		QsdmpCli(0, _did, _cid, devk, headerk),
		serverport(_port),
		timeout(timeout) {
	serverhost = strdup(_host);
}

qezcli::~qezcli() {
	if (fd) {
//		printf("close fd=%d\n", fd);
		close(fd);
	}
	free(serverhost);
}

int qezcli::authSSW(uint8_t *_data, uint32_t len) {
	printf("auth switch server request from server received, server=%s\n", (char *) _data);
	return -1;
}

int qezcli::authUDK(uint8_t *_data) {
	printf("auth update aesk request from server received\n");
	return -1;
}

int qezcli::connecttoserver(const char * _TYPE) {
	int sockfd;
	if(strncmp("UDP", _TYPE, 3) == 0){
		sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	} else if(strncmp("TCP", _TYPE, 3) == 0){
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
	} else{
		PRINTLOGF(YLOG_ERR, "socket type not supported\n", strerror(errno));
		return -1;
	}
	printf("connecting to %s> %s:%d\n", _TYPE, serverhost, serverport);
	/* Create a socket point */
	if (sockfd < 0) {
		PRINTLOGF(YLOG_ERR, "Create a socket point  error=%s\n", strerror(errno));
		return -1;
	}

	setrcvtimeo(sockfd, timeout, 0);

	struct hostent *server = gethostbyname(serverhost);

	if (server == NULL) {
		PRINTLOGF(YLOG_ERR, "In gethostbyname  error=%s\n", strerror(errno));
		return -1;
	}

	sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(serverport);

	/* Now connect to the server */
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		PRINTLOGF(YLOG_ERR, "connecting to Qsdmp server fail, host=%s, port=%d, errno=%s\n", serverhost, serverport,
				  strerror(errno));
		return -1;
	}
	fd = sockfd;
	return 0;
}

int qezcli::Auth(const char * _TYPE) {
	if (0 != connecttoserver(_TYPE)) {
		return -1;
	}

	sendReq();
	std::list<Ypack<0xFF0> *> packlist;
	auto rtn1 = getSecPacks(packlist);
	if (rtn1 == YPA_TERMINATE) {
		for (auto &i : packlist) {
			delete i;
		}
		printf("getSecPacks YPA_TERMINATE\n");
		return -1;
	}

	int resulty = 0;
	for (auto &i : packlist) {
		auto rtn2 = packHandle(i);
		if (auth == AUTH_OK) {
			resulty = 1;
		}
		if (rtn2 == YPA_TERMINATE) {
			printf("packHandle return=%d\n", rtn2);
			resulty = 2;
		}
	}
	for (auto &i : packlist) {
		delete i;
	}

	if (resulty == 1) {
		return 0;
	} else {
		return -1;
	}
}

Ypollact_Type qezcli::getpacks(std::list<Ypack<0xFF0> *> &packlist, uint64_t _flags) {
	sendTck();
	std::list<Ypack<0xFF0> *> packlisttemp;
	auto rtn1 = getSecPacks(packlisttemp);
	if (rtn1 == YPA_TERMINATE) {
		for (auto &i : packlisttemp) {
			delete i;
		}
		printf("getSecPacks YPA_TERMINATE\n");
		return YPA_TERMINATE;
	}

	int errorflag = 0;
	for (auto &i : packlisttemp) {
		auto rtn2 = packHandle(i);
		if (rtn2 == YPA_TERMINATE) {
			errorflag = 1;
			break;
		}
		rtn2 &= YPA_MYPACKGOT | YPA_NMPACKGOT;
		if (rtn2 & _flags) {
			packlist.push_back(i);
			i = nullptr;
		}
	}

	for (auto &i : packlisttemp) {
		delete i;
	}

	if (errorflag == 0) {
		return YPA_NULL;
	} else {
		return YPA_TERMINATE;
	}
}

Ypollact_Type qezcli::mypackdata(Ypack<0xFF0> *pack) {
	return YPA_MYPACKGOT;
}

Ypollact_Type qezcli::notmypack(Ypack<0xFF0> *pack) {
	return YPA_NMPACKGOT;
}

Ypollact_Type qezcli::sendto(const DID_Type &_did, const CID_Type &_cid, const uint8_t *data, uint32_t len, uint32_t sessionID) {
	if (_cid > CID_AUTH_END) {
		return QsdmpCli::sendto(_did, _cid, data, len, sessionID);
	} else {
		return YPA_NULL;
	}
}


int qezcli::evtReg(void) {
	SUPERCMD_TYPE superCMD = SUPERIFCMD_EVTREG;
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send((uint8_t *) &superCMD, sizeof(SUPERCMD_TYPE), randnum)) {
		std::list<Ypack<0xFF0> *> packlist;

		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			int resulty = 0;
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						resulty = 1;
					}
				}

				delete i;
			}

			if (resulty) {
				return 0;
			} else {
				return -1;
			}

		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

int qezcli::msgloadlogenable(void) {
	SUPERCMD_TYPE superCMD = SUPERIFCMD_SETMLOADLOGEN;
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send((uint8_t *) &superCMD, sizeof(SUPERCMD_TYPE), randnum)) {
		std::list<Ypack<0xFF0> *> packlist;

		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			int resulty = 0;
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						resulty = 1;
					}
				}

				delete i;
			}

			if (resulty) {
				return 0;
			} else {
				return -1;
			}

		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

int qezcli::msgloadlogdisable(void) {
	SUPERCMD_TYPE superCMD = SUPERIFCMD_SETMLOADLOGDS;
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send((uint8_t *) &superCMD, sizeof(SUPERCMD_TYPE), randnum)) {
		std::list<Ypack<0xFF0> *> packlist;

		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			int resulty = 0;
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						resulty = 1;
					}
				}

				delete i;
			}

			if (resulty) {
				return 0;
			} else {
				return -1;
			}

		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

int qezcli::updatedevK(const DID_Type &_did, const uint8_t *_aesk) {
	uint8_t buff[sizeof(SUPERCMD_TYPE) + sizeof(DID_Type) + DEVAESKSIZE];
	SUPERCMD_TYPE superCMD = SUPERIFCMD_UPDTK;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	memcpy(buff + sizeof(SUPERCMD_TYPE), &_did, sizeof(DID_Type));
	memcpy(buff + sizeof(SUPERCMD_TYPE) + sizeof(DID_Type), _aesk, DEVAESKSIZE);

	auto randnum = (uint32_t)random();
	if (YPA_NULL == send(buff, sizeof(SUPERCMD_TYPE) + sizeof(DID_Type) + DEVAESKSIZE, randnum)) {
		std::list<Ypack<0xFF0> *> packlist;

		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			int resulty = 0;
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						resulty = 1;
					}
				}
				delete i;
			}

			if (resulty) {
				return 0;
			} else {
				return 1;
			}

		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

int qezcli::switchdevsvr(const DID_Type &_did, const char *_hostandport) {
	auto hoststrlen = strlen(_hostandport);
	if (hoststrlen >= 90) {
		return -1;
	}

	uint8_t buff[100];
	SUPERCMD_TYPE superCMD = SUPERIFCMD_SWSVR;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	memcpy(buff + sizeof(SUPERCMD_TYPE), &_did, sizeof(DID_Type));
	strncpy((char *) buff + sizeof(SUPERCMD_TYPE) + sizeof(DID_Type), _hostandport, 90);
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send(buff, sizeof(SUPERCMD_TYPE) + sizeof(DID_Type) + hoststrlen, randnum)) {
		std::list<Ypack<0xFF0> *> packlist;

		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			int resulty = 0;
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						resulty = 1;
					}
				}

				delete i;
			}

			if (resulty) {
				return 0;
			} else {
				return 1;
			}

		} else {
			return -1;
		}
	} else {
		return -1;
	}
}


int qezcli::loadcidroms(uint8_t cid) {
	uint8_t buff[10];
	SUPERCMD_TYPE superCMD = SUPERIFCMD_LOADCIDROMS;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	buff[sizeof(SUPERCMD_TYPE)] = cid;
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send(buff, sizeof(SUPERCMD_TYPE) + 1, randnum)) {
		std::list<Ypack<0xFF0> *> packList;

		if (YPA_NULL == getpacks(packList, YPA_MYPACKGOT)) {
			int resulty = -1;
			for (auto &i : packList) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						memcpy(&resulty, i->data + sizeof(SUPERCMD_TYPE), sizeof(resulty));
					}
				}

				delete i;
			}
			return resulty;
		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

int qezcli::loadcidmakers(){
	uint8_t buff[10];
	SUPERCMD_TYPE superCMD = SUPERIFCMD_LOADCIDMAKERS;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send(buff, sizeof(SUPERCMD_TYPE), randnum)) {
		std::list<Ypack<0xFF0> *> packList;

		if (YPA_NULL == getpacks(packList, YPA_MYPACKGOT)) {
			int resulty = -1;
			for (auto &i : packList) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						resulty = 0;
					}
				}

				delete i;
			}
			return resulty;
		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

int qezcli::setLogLevel(yloglevel _level) {
	if (_level >= YLOG_TOP) {
		return -1;
	}
	uint8_t buff[10];
	SUPERCMD_TYPE superCMD = SUPERIFCMD_SETLOGLVL;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	memcpy(buff + sizeof(SUPERCMD_TYPE), &_level, sizeof(_level));
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send(buff, sizeof(SUPERCMD_TYPE) + sizeof(_level), randnum)) {
		std::list<Ypack<0xFF0> *> packList;

		if (YPA_NULL == getpacks(packList, YPA_MYPACKGOT)) {
			int resulty = 0;
			for (auto &i : packList) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						resulty = 1;
					}
				}

				delete i;
			}

			if (resulty) {
				return 0;
			} else {
				return 1;
			}

		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

int qezcli::queryIP(uint64_t *dids, char IPaddresses[][16], int length, uint32_t sessionID) {
	/**
	 * SUPERCMD_TYPE : 2 bytes
	 * length		 : 2 bytes
	 * gape			 : 4 bytes
	 * dids			 : 8 * length bytes
	 */
	if (length == 0 or length > 200) {
		return -1;
	}
	uint8_t buff[0x1000];
	auto len = (uint16_t) length;
	SUPERCMD_TYPE superCMD = SUPERIFCMD_QUERYIP;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	memcpy(buff + sizeof(SUPERCMD_TYPE), &len, sizeof(len));
	uint32_t gape = 0;
	memcpy(buff + 4, &gape, sizeof(gape));

	memcpy(buff + 8, dids, len * 8u);
	if (YPA_NULL == send(buff, len * 8u + 8u, sessionID)) {
		std::list<Ypack<0xFF0> *> packlist;
		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK) and i->sessionID == sessionID) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						auto iplength = *(uint16_t *) (i->data + sizeof(superCMD));
						if(iplength == length){
							auto str_ip = (char *) (i->data + 8);
							int pos = 0;
							for (auto ip_index = 0U; ip_index < iplength; ip_index++){
								bool found = false;
								int char_index = 0;
								while (str_ip[pos] != ';' and pos < 16 * 200 and str_ip[pos]){
									if(not found){
										if(str_ip[pos] == ','){
											found = true;
										} else{
											IPaddresses[ip_index][char_index++] = str_ip[pos];
										}
									}
									pos++;
								}
								IPaddresses[ip_index][char_index] = 0;
								pos++;
							}
						}
					}
				}
				delete i;
			}

			return 0;

		} else {
			return -1;
		}
	} else {
		return -1;
	}

}


int qezcli::queryStatus(uint64_t * dids, uint8_t *statusArray, int length, uint32_t sessionID) {
	/**
	 * SUPERCMD_TYPE : 2 bytes
	 * length		 : 2 bytes
	 * gape			 : 4 bytes
	 * dids			 : 8 * length bytes
	 */
	if (length == 0 or length > 200) {
		return -1;
	}
	uint8_t buff[0x1000];
	auto len = (uint16_t) length;
	SUPERCMD_TYPE superCMD = SUPERIFCMD_QUERYSTATE;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	memcpy(buff + sizeof(SUPERCMD_TYPE), &len, sizeof(len));
	uint32_t gape = 0;
	memcpy(buff + 4, &gape, sizeof(gape));

	memcpy(buff + 8, dids, len * 8u);
	if (YPA_NULL == send(buff, len * 8u + 8u, sessionID)) {
		std::list<Ypack<0xFF0> *> packlist;

		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK) and i->sessionID == sessionID) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						auto iplength = *(uint16_t *) (i->data + sizeof(superCMD));
						if(iplength == length){
							for (auto _index = 0U; _index < iplength; _index++){
								statusArray[_index] = i->data[_index + 8];
							}
						}
					}
				}

				delete i;
			}

			return 0;

		} else {
			return -1;
		}
	} else {
		return -1;
	}

}


ssize_t qezcli::getnodecount(void) {
	uint8_t buff[10];
	SUPERCMD_TYPE superCMD = SUPERIFCMD_GETNS;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send(buff, sizeof(SUPERCMD_TYPE) + sizeof(uint64_t), randnum)) {
		std::list<Ypack<0xFF0> *> packlist;

		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			ssize_t resulty = -1;
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						memcpy(&resulty, i->data + sizeof(SUPERCMD_TYPE), sizeof(ssize_t));
					}
				}

				delete i;
			}

			return resulty;

		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

ssize_t qezcli::getpackercount(void) {
	uint8_t buff[10];
	SUPERCMD_TYPE superCMD = SUPERIFCMD_GETPS;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send(buff, sizeof(SUPERCMD_TYPE) + sizeof(uint64_t), randnum)) {
		std::list<Ypack<0xFF0> *> packlist;

		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			ssize_t resulty = -1;
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						memcpy(&resulty, i->data + sizeof(SUPERCMD_TYPE), sizeof(ssize_t));
					}
				}

				delete i;
			}

			return resulty;

		} else {
			return -1;
		}
	} else {
		return -1;
	}
}


ssize_t qezcli::getaomsgload1s(void) {
	uint8_t buff[10];
	SUPERCMD_TYPE superCMD = SUPERIFCMD_GETAOMSGLOAD1S;
	memcpy(buff, &superCMD, sizeof(SUPERCMD_TYPE));
	auto randnum = (uint32_t)random();
	if (YPA_NULL == send(buff, sizeof(SUPERCMD_TYPE) + sizeof(uint64_t), randnum)) {
		std::list<Ypack<0xFF0> *> packlist;

		if (YPA_NULL == getpacks(packlist, YPA_MYPACKGOT)) {
			ssize_t resulty = -1;
			for (auto &i : packlist) {
				if (!(i->cid & CID_ERR_MASK)) {
					if (memcmp(i->data, &superCMD, sizeof(SUPERCMD_TYPE)) == 0) {
						memcpy(&resulty, i->data + sizeof(SUPERCMD_TYPE), sizeof(ssize_t));
					}
				}

				delete i;
			}

			return resulty;

		} else {
			return -1;
		}
	} else {
		return -1;
	}
}





