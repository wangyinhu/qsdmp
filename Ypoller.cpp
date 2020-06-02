#include <arpa/inet.h>
#include "Ypoller.h"
#include <cstring>
#include <unistd.h>
#include "Ylog.h"
#include "rediscli.h"
#include "supercmds.h"

#define MAXEVENTS                        2560
#define PERIODCHECKINTERVAL            10
#define CONNECTIONDIEAGE                60
#define CONNMAXEVENTRATE                100
#define NODEECTIONDIEAGE                60
#define NODEMAXEVENTRATE                100
#define MAXSERVEREVENT                    100000
#define MINSVRHOSTPORTSIZE                6
#define DEVAESKSIZE                        16


typedef int (*superCmdHandle)(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack);

static int SUPERIFCMD_SWSVR_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	auto _len = _pack->get_length();
	if (_len < sizeof(SUPERCMD_TYPE) + sizeof(DID_Type) + MINSVRHOSTPORTSIZE) {
		return -1;
	}
	DID_Type devdid;
	memcpy(&devdid, _pack->data + sizeof(SUPERCMD_TYPE), sizeof(DID_Type));
	return poller->send2dev(_al, devdid, CID_AUTH_SSW, _pack->data + sizeof(SUPERCMD_TYPE) + sizeof(DID_Type),
							_len - sizeof(SUPERCMD_TYPE) - sizeof(DID_Type), _pack->sessionID);
}

static int SUPERIFCMD_UPDTK_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	auto _len = _pack->get_length();
	if (_len != sizeof(SUPERCMD_TYPE) + sizeof(DID_Type) + DEVAESKSIZE) {
		return -1;
	}
	DID_Type devdid;
	memcpy(&devdid, _pack->data + sizeof(SUPERCMD_TYPE), sizeof(DID_Type));
	return poller->send2dev(_al, devdid, CID_AUTH_UDK, _pack->data + sizeof(SUPERCMD_TYPE) + sizeof(DID_Type),
							DEVAESKSIZE, _pack->sessionID);
}

static int SUPERIFCMD_EVTREG_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	return poller->setEvtPort(_fd);
}

static int SUPERIFCMD_GETPS_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	auto ps = poller->packerTableSize();
	memcpy(_pack->data + sizeof(SUPERCMD_TYPE), &ps, sizeof(ps));
	_pack->set_length(sizeof(SUPERCMD_TYPE) + sizeof(ps));
	return 0;
}

static int SUPERIFCMD_GETNS_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	auto ns = poller->nodeTableSize();
	memcpy(_pack->data + sizeof(SUPERCMD_TYPE), &ns, sizeof(ns));
	_pack->set_length(sizeof(SUPERCMD_TYPE) + sizeof(ns));
	return 0;
}

static int SUPERIFCMD_SETLOGLVL_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	yloglevel llvl;
	memcpy(&llvl, _pack->data + sizeof(SUPERCMD_TYPE), sizeof(llvl));
	if (llvl < YLOG_TOP) {
		LOGLVLSET(llvl);
		return 0;
	} else {
		return -1;
	}
}

static int SUPERIFCMD_GETLOGLVL_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	auto logLevel = LOGLVLGET();
	memcpy(_pack->data + sizeof(SUPERCMD_TYPE), &logLevel, sizeof(logLevel));
	_pack->set_length(sizeof(SUPERCMD_TYPE) + sizeof(logLevel));
	return 0;
}

static int SUPERIFCMD_SETMLOADLOGEN_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	poller->msgloadenable = true;
	return 0;
}

static int SUPERIFCMD_SETMLOADLOGDS_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	poller->msgloadenable = false;
	return 0;
}

static int SUPERIFCMD_GETAOMSGLOAD1S_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	memcpy(_pack->data + sizeof(SUPERCMD_TYPE), &poller->msgload1s, sizeof(poller->msgload1s));
	_pack->set_length(sizeof(SUPERCMD_TYPE) + sizeof(poller->msgload1s));
	return 0;
}

static int SUPERIFCMD_QUERYIP_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	/**
	 * SUPERCMD_TYPE : 2 bytes
	 * length		 : 2 bytes
	 * gape			 : 4 bytes
	 * dids			 : 8 * length bytes
	 */
	auto did_array_size = *(uint16_t *) (_pack->data + sizeof(SUPERCMD_TYPE));
	if (did_array_size > 200) {
		return -1;
	}

	uint64_t did_array[did_array_size];
	for (auto i = 0u; i < did_array_size; i++) {
		memcpy(did_array + i, _pack->data + 8 + i * 8, 8);
//				PRINTLOGB(YLOG_ERR, _pack->data, _pack->len);
	}
	auto str_ip = (char *) (_pack->data + 8);
	uint32_t pos = 0;
	for (auto i = 0u; i < did_array_size; i++) {
		if (poller->nodeTable.count(did_array[i])) {
			for (auto &port : poller->nodeTable[did_array[i]]->portTable) {
				if (port.second.auth >= AUTH_OK) {
					auto ip = poller->packerTable[port.first]->getIPaddress();
					for (auto ci = 0; ip[ci]; ci++) {
						str_ip[pos++] = ip[ci];
					}
					str_ip[pos++] = ',';
				}
			}
		}
		str_ip[pos++] = ';';
	}
	str_ip[pos] = 0;
	_pack->set_length(pos + 8);
	return 0;
}

static int SUPERIFCMD_QUERYSTATE_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	/**
	 * SUPERCMD_TYPE : 2 bytes
	 * length		 : 2 bytes
	 * gape			 : 4 bytes
	 * dids			 : 8 * length bytes
	 */
	auto did_array_size = *(uint16_t *) (_pack->data + sizeof(SUPERCMD_TYPE));
	if (did_array_size > 200) {
		return -1;
	}

	uint64_t did_array[did_array_size];
	for (auto i = 0u; i < did_array_size; i++) {
		memcpy(did_array + i, _pack->data + 8 + i * 8, 8);
	}
	uint8_t *statusArray = _pack->data + 8;
	for (auto i = 0u; i < did_array_size; i++) {
		if (poller->nodeTable.count(did_array[i])) {
			statusArray[i] = 1;
		} else {
			statusArray[i] = 0;
		}
	}
	_pack->set_length(did_array_size + 8);
	return 0;
}

static int SUPERIFCMD_LOADCIDROMS_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	uint8_t _cid = *(_pack->data + sizeof(SUPERCMD_TYPE));
	auto rtn = Dnode::loadRoms(_cid);
	memcpy(_pack->data + sizeof(SUPERCMD_TYPE), &rtn, sizeof(rtn));
	_pack->set_length(sizeof(SUPERCMD_TYPE) + sizeof(rtn));
	return 0;
}

static int SUPERIFCMD_LOADCIDMAKERS_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	auto rtn = 	Dnode::loadmakers();
	memcpy(_pack->data + sizeof(SUPERCMD_TYPE), &rtn, sizeof(rtn));
	_pack->set_length(sizeof(SUPERCMD_TYPE) + sizeof(rtn));
	return 0;
}

static int SUPERIFCMD_GET1SMAXEVT_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	memcpy(_pack->data + sizeof(SUPERCMD_TYPE), &poller->SecMaxEvent, sizeof(poller->SecMaxEvent));
	_pack->set_length(sizeof(SUPERCMD_TYPE) + sizeof(poller->SecMaxEvent));
	return 0;
}

static int SUPERIFCMD_DEFAULT_handler(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	return -1;
}

static struct {
	SUPERCMD_TYPE cmd;
	superCmdHandle handler;
} SuperCMD_Table[] = {
		{SUPERIFCMD_SWSVR,          SUPERIFCMD_SWSVR_handler},
		{SUPERIFCMD_UPDTK,          SUPERIFCMD_UPDTK_handler},
		{SUPERIFCMD_EVTREG,         SUPERIFCMD_EVTREG_handler},
		{SUPERIFCMD_GETPS,          SUPERIFCMD_GETPS_handler},
		{SUPERIFCMD_GETNS,          SUPERIFCMD_GETNS_handler},
		{SUPERIFCMD_SETLOGLVL,      SUPERIFCMD_SETLOGLVL_handler},
		{SUPERIFCMD_GETLOGLVL,      SUPERIFCMD_GETLOGLVL_handler},
		{SUPERIFCMD_SETMLOADLOGEN,  SUPERIFCMD_SETMLOADLOGEN_handler},
		{SUPERIFCMD_SETMLOADLOGDS,  SUPERIFCMD_SETMLOADLOGDS_handler},
		{SUPERIFCMD_GETAOMSGLOAD1S, SUPERIFCMD_GETAOMSGLOAD1S_handler},
		{SUPERIFCMD_QUERYIP,        SUPERIFCMD_QUERYIP_handler},
		{SUPERIFCMD_QUERYSTATE,     SUPERIFCMD_QUERYSTATE_handler},
		{SUPERIFCMD_GET1SMAXEVT,    SUPERIFCMD_GET1SMAXEVT_handler},
		{SUPERIFCMD_LOADCIDROMS,    SUPERIFCMD_LOADCIDROMS_handler},
		{SUPERIFCMD_LOADCIDMAKERS,  SUPERIFCMD_LOADCIDMAKERS_handler},
};

static superCmdHandle SuperCMD_Finder(SUPERCMD_TYPE cmd) {
	for (auto &i : SuperCMD_Table) {
		if (i.cmd == cmd) {
			return i.handler;
		}
	}
	return SUPERIFCMD_DEFAULT_handler;
}

static void SuperCMD_Runner(Ypoller *poller, alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {

	SUPERCMD_TYPE superCMD;
	memcpy(&superCMD, _pack->data, sizeof(superCMD));
	if (0 != SuperCMD_Finder(superCMD)(poller, _al, _fd, _pack)) {
		superCMD |= SUPERIFCMD_ERRMASK;
	}
	memcpy(_pack->data, &superCMD, sizeof(superCMD));
}

Ypollact_Type Ypoller::superPackHandle(alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	if ((_pack->cid != CID_APPS_SPR) or (_pack->get_length() < sizeof(SUPERCMD_TYPE))) {
		return sprMsgBack(_fd, did, CID_APPS_SPR | CID_ERR_MASK, _pack->data, _pack->get_length(), _pack->sessionID);
	} else {
		SuperCMD_Runner(this, _al, _fd, _pack);
		return sprMsgBack(_fd, did, CID_APPS_SPR, _pack->data, _pack->get_length(), _pack->sessionID);
	}
}


// ***************************************************************************************************
Ypoller::Ypoller(const DID_Type &_did) :
		QsdmpSvr(_did) {
	Dnode::loadmakers();
	uint8_t aesk[16];
	if (rdb.getaesk(aesk, HEADERKEYDID) != 0) {
		PRINTLOGF(YLOG_ERR, "Ypoller load header key fail!\n");
		exit(-1);
	}
	Ypacker::loadHeaderKey(aesk);
}

Ypoller::~Ypoller() {
//-----------------------packer----------------------------
	for (auto &i : packerTable) {
		close(i.first);
		delete i.second;
	}
//----------------------- node ----------------------------
	for (auto &i : nodeTable) {
		delete i.second;
	}
}

void Ypoller::stop(int arg) {
	PRINTLOGF(YLOG_ALERT, "Qpoller::stop \n");
	keepRunning = false;
}

int Ypoller::start(const char *_port) {
	theefd = epoll_create1(0);
	if (theefd == -1) {
		PRINTLOGF(YLOG_ERR, "epoll_create fail.\n");
		exit(EXIT_FAILURE);
	}
	thesfd = create_server(_port);
	if (thesfd < 0) {
		PRINTLOGF(YLOG_ERR, "Ypoller start create_server fail _port=%s\n", _port);
		exit(-1);
	}
	add_epoll(thesfd);

	UDPsfd = createUDPServer(_port);
	if (UDPsfd < 0) {
		PRINTLOGF(YLOG_ERR, "Ypoller start createUDPServer fail _port=%s\n", _port);
		exit(-1);
	}
	add_epoll(UDPsfd);
	UDPPeer::fd = UDPsfd;
	thetfd = timerfd_create_and_arm(PERIODCHECKINTERVAL);
	if (thetfd == -1) {
		PRINTLOGF(YLOG_ERR, "error timerfd_create_and_arm fail\n");
		return -1;
	}
	add_epoll(thetfd);

	PRINTLOGF(YLOG_ALERT, "server started successfully!\nserving on port=%s", _port);
	//------------------ enter poll ---------------------------
	struct epoll_event epollevents[MAXEVENTS];
	/* The event loop */
	while (keepRunning) {
		int n = epoll_wait(theefd, epollevents, MAXEVENTS, -1);
		if (n > maxEvent) {
			maxEvent = n;
		}
		for (int i = 0; i < n; i++) {
			auto fd = epollevents[i].data.fd;
			if (packerTable.count(fd)) {
				clientEventHandle(epollevents + i);
			} else if (thesfd == fd) {
				acceptAddEpoll();
			} else if (UDPsfd == fd) {
				UDPHandler();
			} else if (thetfd == fd) {
				timerhandle();
			} else {
				PRINTLOGF(YLOG_ERR, "error!!! Unknow fd event in poller, fd=%d\n", epollevents[i].data.fd);
			}

			if (thetfd != fd) {
				PRINTLOGF(YLOG_DEBUG, "packerTable.size=%d, UDPPeerTable.size=%d, nodeTable.size=%d\n",
						  packerTable.size(), UDPPeerTable.size(), nodeTable.size());
			}
		}
	}
	close(theefd);
	return 0;
}

void Ypoller::clientEventHandle(epoll_event *_epollevent) {
	auto _fd = _epollevent->data.fd;
	std::list<Ypack<0xFF0> *> packList;

	auto action = packerTable[_fd]->eventhandle(packList, _epollevent);
	alst_Type _al;

	packcounter += packList.size();

	if (portTable.count(_fd)) {
		for (auto &pack : packList) {
			action |= upPackHandle(_al, _fd, pack);
			//...
			delete pack;
		}
	} else {
		for (auto &pack : packList) {
			if (pack->did == did) {
				action |= upPackHandle(_al, _fd, pack);
				//...
			} else {
				action |= downPackHandle(_al, _fd, pack);
				//...
			}
			delete pack;
		}
	}

	actionHandle(_al);

	actionHandle(_fd, action);

}

int Ypoller::UDPHandler(void) {
	Ypack<0xFF0> pkg;
	sockaddr_in clientaddr;
	uint32_t clientlen = sizeof(clientaddr);

	while (true) {
		auto n = recvfrom(UDPsfd, &pkg, sizeof(Ypack<0xFF0>), 0, (struct sockaddr *) &clientaddr, &clientlen);
		if (n > 0) {
			PRINTLOGF(YLOG_DEBUG, "UDP pack received, data length=%d, data=\n", n);
			PRINTLOGB(YLOG_DEBUG, &pkg, n);
			auto key = addrToKey(clientaddr);
			if (UDPPeerTable.count(key) == 0) {
				UDPPeerTable[key] = new UDPPeer(CONNECTIONDIEAGE, CONNMAXEVENTRATE);
			}
			auto action = UDPPeerTable[key]->packHandle(&pkg, n);
			if (action == YPA_TERMINATE) {
				//return error
				rmconn(clientaddr);
				continue;
			}
			printf("header dec pass\n");
			packcounter++;
			if (pkg.did == this->did) {
				//return error
				rmconn(clientaddr);
				continue;
			}
			alst_Type _al;

			action = downPackHandle(_al, clientaddr, &pkg);
			if (action == YPA_TERMINATE) {
				//return error
				printf("pack handle error\n");
				rmconn(clientaddr);
				continue;
			}
			actionHandle(_al);

//			//udp pack handle
//			printf("data=%s\n", (char *) &pkg);
//			char straddr[INET_ADDRSTRLEN];
//			inet_ntop(AF_INET, &(clientaddr.sin_addr), straddr, INET_ADDRSTRLEN);
//			printf("address=%s:%d\n", straddr, clientaddr.sin_port);
		} else {
			if (errno == EAGAIN) {
				//read complete
				return YPA_NULL;
			} else {
				PRINTLOGF(YLOG_DEBUG, "error recvfrom() error=%s\n", strerror(errno));
				return YPA_TERMINATE;
			}
		}
	}
}

static uint32_t get_global_sessionID(void) {
	static uint32_t global_sessionID = 1;
	if(++global_sessionID == 0){
		global_sessionID = 1;
	}
	return global_sessionID;
}

Ypollact_Type Ypoller::upPackHandle(alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	Ypack<0xFF0> *packBack = nullptr;
	auto le = SecPackHandle(_fd, _pack, packBack);
	switch (le) {
		case (LNK_EVENT_NUN): {
			if (packBack) {
				return packerTable[_fd]->sendPack(packBack);
			} else {
				return YPA_NULL;
			}
		}
			break;
		case (LNK_EVENT_UP):
			packerTable[_fd]->setAgeTh(CONNECTIONDIEAGE, MAXSERVEREVENT);
					__attribute__ ((fallthrough));
		case (LNK_EVENT_SWSVROK):
		case (LNK_EVENT_SWSVRFAIL):
		case (LNK_EVENT_SETAESKOK):
		case (LNK_EVENT_SETAESKFAIL):
		case (LNK_EVENT_SETTCKRATEOK):
		case (LNK_EVENT_SETTCKRATEFAIL):
			return YPA_NULL;
		case (LNK_EVENT_APPDATAIN): {
			if (nodeTable.count(_pack->did)) {
				auto port = &portTable[_fd];
				port->sessionID_origin = _pack->sessionID;
				if(_pack->sessionID){
					port->sessionID = get_global_sessionID();
					_pack->sessionID = port->sessionID;
				} else {
					port->sessionID = 0;
				}
				std::list<Vbarray *> forwardPacks;
				std::list<Vbarray *> backPacks;
				nodeTable[_pack->did]->serverMSGProcess(_pack, forwardPacks, backPacks);
				for (auto &_dv : forwardPacks) {
					PRINTLOGF(YLOG_DEBUG, " super to device final data=\n");
					PRINTLOGB(YLOG_DEBUG, _dv->data(), _dv->size());
					send2dev(_al, _pack->did, _pack->cid, _dv->data(), _dv->size(), _pack->sessionID);
					delete _dv;
				}
				Ypollact_Type actions = YPA_NULL;
				for (auto &_dv : backPacks) {
					PRINTLOGF(YLOG_DEBUG, "back to super event data=\n");
					PRINTLOGB(YLOG_DEBUG, _dv->data(), _dv->size());
					actions |= sprMsgBack(_fd, _pack->did, CID_EVENT, _dv->data(), _dv->size(), _pack->sessionID);
					delete _dv;
				}
				return actions;
			} else if (_pack->did == this->did) {
				return superPackHandle(_al, _fd, _pack);
			} else {
				static const char out[] = "error 1:device is not online.";
				return sprMsgBack(_fd, _pack->did, CID_EVENT, (const uint8_t *) out, sizeof(out) - 1, _pack->sessionID);
			}
		}
			break;
		case (LNK_EVENT_ERROR): {
			return YPA_TERMINATE;
		}
			break;
		default: {
			return YPA_NULL;
		}
	}
}

Ypollact_Type Ypoller::downPackHandle(alst_Type &_al, const int _fd, Ypack<0xFF0> *_pack) {
	Dnode *np;
	if (nodeTable.count(_pack->did) == 0) {
		np = new Dnode(_pack->did, NODEECTIONDIEAGE, NODEMAXEVENTRATE);
		nodeTable[_pack->did] = np;
	} else {
		np = nodeTable[_pack->did];
	}

	Ypack<0xFF0> *packBack = nullptr;
	auto le = np->SecPackHandle(_fd, _pack, packBack);
	switch (le) {
		case (LNK_EVENT_NUN): {
			if (packBack) {
				return packerTable[_fd]->sendPack(packBack);
			} else {
				return YPA_NULL;
			}
		}
			break;
		case (LNK_EVENT_UP): {
			rdb.linestatlog(_pack->did, 10);
			rdb.setaddr(_pack->did, packerTable[_fd]->getIPaddress());
			PRINTLOGF(YLOG_DEBUG, "DOWN LNK_EVENT_UP, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event UP";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SWSVROK): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SWSVROK, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SWSVROK";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SWSVRFAIL): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SWSVRFAIL, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SWSVRFAIL";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SETAESKOK): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SETAESKOK, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SETAESKOK";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SETAESKFAIL): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SETAESKFAIL, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SETAESKFAIL";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SETTCKRATEOK): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SETTCKRATEOK, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SETTCKRATEOK";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SETTCKRATEFAIL): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SETTCKRATEFAIL, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SETTCKRATEFAIL";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_APPDATAIN): {
			std::list<Vbarray *> forwardpacks;
			std::list<Vbarray *> backpacks;
			np->deviceMSGProcess(_pack, forwardpacks, backpacks);

			auto action = YPA_NULL;
			for (auto &_dv : backpacks) {
				action |= devMsgBack(_fd, _pack->did, _pack->cid, _dv->data(), _dv->size(), _pack->sessionID);
				delete _dv;
			}

			for (auto &_dv : forwardpacks) {
				send2spr(_al, _pack->did, _pack->cid, _dv->data(), _dv->size(), _pack->sessionID);
				delete _dv;
			}
			return action;
		}
			break;
		case (LNK_EVENT_ERROR): {
			return YPA_TERMINATE;
		}
			break;
		default: {
			return YPA_NULL;
		}
	}
}

Ypollact_Type Ypoller::downPackHandle(alst_Type &_al, const sockaddr_in &addr, Ypack<0xFF0> *_pack) {
	Dnode *np;
	if (nodeTable.count(_pack->did) == 0) {
		np = new Dnode(_pack->did, NODEECTIONDIEAGE, NODEMAXEVENTRATE);
		nodeTable[_pack->did] = np;
	} else {
		np = nodeTable[_pack->did];
	}

	Ypack<0xFF0> *packBack = nullptr;
	auto le = np->SecPackHandle(addr, _pack, packBack);
	switch (le) {
		case (LNK_EVENT_NUN): {
			if (packBack) {
				return UDPPeerTable[addrToKey(addr)]->sendPack(packBack, addr);
			} else {
				return YPA_NULL;
			}
		}
			break;
		case (LNK_EVENT_UP): {
			rdb.linestatlog(_pack->did, 10);
			char straddr[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(addr.sin_addr), straddr, INET_ADDRSTRLEN);
			rdb.setaddr(_pack->did, straddr);
			PRINTLOGF(YLOG_DEBUG, "DOWN LNK_EVENT_UP, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event UP";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SWSVROK): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SWSVROK, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SWSVROK";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SWSVRFAIL): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SWSVRFAIL, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SWSVRFAIL";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SETAESKOK): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SETAESKOK, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SETAESKOK";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SETAESKFAIL): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SETAESKFAIL, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SETAESKFAIL";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SETTCKRATEOK): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SETTCKRATEOK, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SETTCKRATEOK";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_SETTCKRATEFAIL): {
			PRINTLOGF(YLOG_DEBUG, "LNK_EVENT_SETTCKRATEFAIL, did=0x%016lX\n", _pack->did);
			static const char outData[] = "event SETTCKRATEFAIL";    //static make it shared between all objects
			sendEVT2spr(_al, _pack->did, (const uint8_t *) outData, sizeof(outData) - 1, _pack->sessionID);
			return YPA_NULL;
		}
			break;
		case (LNK_EVENT_APPDATAIN): {
			std::list<Vbarray *> forwardpacks;
			std::list<Vbarray *> backpacks;
			np->deviceMSGProcess(_pack, forwardpacks, backpacks);

			auto action = YPA_NULL;
			for (auto &_dv : backpacks) {
				action |= devMsgBack(addr, _pack->did, _pack->cid, _dv->data(), _dv->size(), _pack->sessionID);
				delete _dv;
			}

			for (auto &_dv : forwardpacks) {
				send2spr(_al, _pack->did, _pack->cid, _dv->data(), _dv->size(), _pack->sessionID);
				delete _dv;
			}
			return action;
		}
			break;
		case (LNK_EVENT_ERROR): {
			return YPA_TERMINATE;
		}
			break;
		default: {
			return YPA_NULL;
		}
	}
}

int Ypoller::rmconn(const int _fd) {
	close(_fd);
	if (packerTable.count(_fd)) {
		if (this->portTable.count(_fd)) {
			this->rmport(_fd);
		} else {
			for (auto &i : packerTable[_fd]->getDidTable()) {
				if (rmnodeport(i, _fd) == 0) {
					//offline notice && log
					rdb.linestatlog(i, 11);
				}
			}
		}
		//delete pack every time disconnect
		delete packerTable[_fd];
		packerTable.erase(_fd);
		return 0;
	} else {
		return -1;
	}
}

int Ypoller::rmconn(const sockaddr_in &addr) {
	auto key = addrToKey(addr);
	if (UDPPeerTable.count(key)) {
		if (this->UDPportTable.count(key)) {
			this->rmport(addr);
		} else {
			for (auto &i : UDPPeerTable[key]->didTable) {
				if (rmnodeport(i, addr) == 0) {
					//offline notice && log
					rdb.linestatlog(i, 11);
				}
			}
		}
		delete UDPPeerTable[key];
		UDPPeerTable.erase(key);
		return 0;
	} else {
		return -1;
	}
}

int Ypoller::rmnodeport(const DID_Type &_did, const int _fd) {
	if (nodeTable.count(_did)) {
		if (nodeTable[_did]->rmport(_fd) == 0 and nodeTable[_did]->UDPportTable.empty()) {
			delete nodeTable[_did];
			nodeTable.erase(_did);
			return 0;
		} else {
			return 1;
		}
	} else {
		return -1;
	}
}

int Ypoller::rmnodeport(const DID_Type &_did, const sockaddr_in &addr) {
	if (nodeTable.count(_did)) {
		if (nodeTable[_did]->rmport(addr) == 0 and nodeTable[_did]->portTable.empty()) {
			delete nodeTable[_did];
			nodeTable.erase(_did);
			return 0;
		} else {
			return 1;
		}
	} else {
		return -1;
	}
}

void Ypoller::actionHandle(const alst_Type &_al) {
	for (auto &i : _al) {
		actionHandle(i.first, i.second);
	}
}

void Ypoller::actionHandle(const int _fd, Ypollact_Type _action) {
	if (_action & YPA_TERMINATE) {
		rmconn(_fd);
	} else if (_action & YPA_OUTSWON) {
		outevensw(_fd, true);
	} else if (_action & YPA_OUTSWOFF) {
		outevensw(_fd, false);
	}
}

int Ypoller::acceptAddEpoll(void) {
	while (true) {
		sockaddr addr;
		socklen_t in_len = sizeof(sockaddr);
		auto fd = accept4(thesfd, &addr, &in_len, SOCK_NONBLOCK);
		if (fd == -1) {
			if ((errno == EAGAIN) ||
				(errno == EWOULDBLOCK)) {
				/* We have processed all incoming
				   connections. */
			} else {
				PRINTLOGF(YLOG_ERR, "ERROR while accepting device connections ERROR=%s\n", strerror(errno));
			}
			break;
		} else {
			if (0 == add_epoll(fd)) {
				newconn(fd, addr);
			} else {
				close(fd);
			}
		}
	}
	return 0;
}

int Ypoller::newconn(const int _fd, const sockaddr &_addr) {
	if (packerTable.count(_fd)) {
		rmconn(_fd);
		PRINTLOGF(YLOG_ALERT, "epoll error! new connection already exist.\n");
		return -1;
	} else {
		packerTable[_fd] = new Dpacker(_addr, _fd, CONNECTIONDIEAGE, CONNMAXEVENTRATE);
		return 0;
	}
}

int Ypoller::timerhandle(void) {
	uint64_t exp;
	if (read(thetfd, &exp, sizeof(uint64_t)) != sizeof(uint64_t)) {
		PRINTLOGF(YLOG_CRIT, "read(thetfd) unknow problem\n");
		exit(EXIT_FAILURE);
	}
	(void) exp;
//	printf("sizeof Ypack<8>=%lu\n", sizeof(Ypack<8>));
	checker(PERIODCHECKINTERVAL);

	return 0;
}

int Ypoller::checker(uint32_t _period) {
	bool change = false;
	std::list<int> eraselater;
	for (auto &i : packerTable) {
		if (i.second->checker(_period)) {
			eraselater.push_front(i.first);
		}
	}
	for (auto &i : eraselater) {
		rmconn(i);
		change = true;
	}

	std::list<uint64_t> UDPeraselater;

	for (auto &i : UDPPeerTable) {
		if (i.second->checker(_period)) {
			UDPeraselater.push_front(i.first);
		}
	}

	for (auto &i : UDPeraselater) {
		rmconn(keyToAddr(i));
		change = true;
	}
	if (change) {
		PRINTLOGF(YLOG_DEBUG, "packerTable.size=%d, UDPPeerTable.size=%d, nodeTable.size=%d\n",
				  packerTable.size(), UDPPeerTable.size(), nodeTable.size());
	}

	msgload1s = packcounter / _period;
	packcounter = 0;

	if (msgloadenable) PRINTLOGF(YLOG_NOTICE, "msgload1s=%lu\n", msgload1s);

	maxEvent = 0;
	SecMaxEvent = maxEvent;
	for (auto &i : nodeTable) {
		i.second->checker(_period);
	}
	return 0;
}


int Ypoller::add_epoll(const int _fd) {
	epoll_event event;
	event.data.fd = _fd;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(theefd, EPOLL_CTL_ADD, _fd, &event) == -1) {
		PRINTLOGF(YLOG_ERR, "epoll_ctl add fail _fd=%d\nstrerro=%s\n", _fd, strerror(errno));
		return -1;
	}
	return 0;
}


int Ypoller::tcp_create_and_bind(const char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, serverFd;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
	hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
	hints.ai_flags = AI_PASSIVE;     /* All interfaces */
	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0) {
		PRINTLOGF(YLOG_ERR, "getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		serverFd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (serverFd == -1) continue;
		int optVal = 1;
		if (setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) == -1) {
			PRINTLOGF(YLOG_ERR, "Setsockopt fail\n");
			return -1;
		}
		s = bind(serverFd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			/* We managed to bind successfully! */
			break;
		}
		close(serverFd);
	}
	if (rp == nullptr) {
		PRINTLOGF(YLOG_ERR, "Could not bind. port=%s\n", port);
		return -1;
	}
	freeaddrinfo(result);
	return serverFd;
}


int Ypoller::udp_create_and_bind(const char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, serverFd;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
	hints.ai_socktype = SOCK_DGRAM; /* We want a UDP socket */
	hints.ai_flags = AI_PASSIVE;     /* All interfaces */
	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0) {
		PRINTLOGF(YLOG_ERR, "getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		serverFd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (serverFd == -1) continue;
		int optVal = 1;
		if (setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) == -1) {
			PRINTLOGF(YLOG_ERR, "Setsockopt fail\n");
			return -1;
		}
		s = bind(serverFd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			/* We managed to bind successfully! */
			break;
		}
		close(serverFd);
	}
	if (rp == nullptr) {
		PRINTLOGF(YLOG_ERR, "Could not bind. port=%s\n", port);
		return -1;
	}
	freeaddrinfo(result);
	return serverFd;
}


int Ypoller::create_server(const char *_port) {
	auto sfd = tcp_create_and_bind(_port);
	if (sfd == -1) {
		PRINTLOGF(YLOG_ERR, "tcp bind fail port=%s\n", _port);
		return -1;
	}
	if (make_socket_non_blocking(sfd) == -1) {
		PRINTLOGF(YLOG_ERR, "make_socket_non_blocking fail _port=%s\n", _port);
		return -1;
	}
	if (listen(sfd, SOMAXCONN) == -1) {
		PRINTLOGF(YLOG_ERR, "listen fail _port=%s\n", _port);
		return -1;
	}
	return sfd;
}

int Ypoller::createUDPServer(const char *_port) {
	auto sfd = udp_create_and_bind(_port);
	if (sfd == -1) {
		PRINTLOGF(YLOG_ERR, "UDP bind fail port=%s\n", _port);
		return -1;
	}
	if (make_socket_non_blocking(sfd) == -1) {
		PRINTLOGF(YLOG_ERR, "make_socket_non_blocking UDP fail _port=%s\n", _port);
		return -1;
	}
//	if (listen(sfd, SOMAXCONN) == -1) {
//		PRINTLOGF(YLOG_ERR, "listen fail _port=%s\n", _port);
//		return -1;
//	}
	return sfd;
}

int Ypoller::timerfd_create_and_arm(int _seconds) {
	int tfd;
	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (tfd == -1) {
		PRINTLOGF(YLOG_ERR, "timerfd_create\n");
		return -1;
	}

	if (make_socket_non_blocking(tfd) == -1) {
		PRINTLOGF(YLOG_ERR, "make_socket_non_blocking (tfd)\n");
		return -1;
	}

	struct itimerspec new_value;

	new_value.it_interval.tv_sec = _seconds;
	new_value.it_interval.tv_nsec = 0;
	new_value.it_value.tv_sec = _seconds;
	new_value.it_value.tv_nsec = 0;

	if (timerfd_settime(tfd, 0, &new_value, 0) == -1) {
		PRINTLOGF(YLOG_ERR, "timerfd_settime\n");
		return -1;
	}
	return tfd;
}


int Ypoller::outevensw(const int _fd, const bool _sw) {
	epoll_event event;
	event.data.fd = _fd;
	if (_sw) {
		event.events = EPOLLIN | EPOLLET | EPOLLOUT;
	} else {
		event.events = EPOLLIN | EPOLLET;
	}

	if (epoll_ctl(theefd, EPOLL_CTL_MOD, _fd, &event) == -1) {
		PRINTLOGF(YLOG_CRIT, "epoll_ctl (epollfd, EPOLL_CTL_MOD, fd=%d, &event)\n", _fd);
		//exit(EXIT_FAILURE);
	}
	return 0;
}

int
Ypoller::send2dev(alst_Type &_al, const DID_Type &_did, const CID_Type _cid, const uint8_t *data, const uint32_t _inlen,
				  uint32_t sessionID) {
	Ypack<0xFF0> opk;

	if (nodeTable.count(_did)) {
		auto node = nodeTable[_did];
		for (auto &port : node->portTable) {
			if (port.second.auth >= AUTH_OK) {
				opk.did = _did;
				opk.cid = _cid;
				if (port.second.Encrypt(data, _inlen, opk.data, opk.CBC_lowLen, sessionID) == 0) {
					auto action = packerTable[port.first]->sendPack(&opk);
					_al.push_front(std::pair(port.first, action));
				}
			}
		}
		return 0;
	} else {
		return -1;
	}
}

int
Ypoller::send2spr(alst_Type &_al, const DID_Type &_did, const CID_Type _cid, const uint8_t *data, const uint32_t _inlen,
				  uint32_t sessionID) {
	Ypack<0xFF0> opk;

	for (auto &port : portTable) {
		if ((sessionID != 0 and sessionID == port.second.sessionID) or
				(sessionID == 0 and port.second.auth == AUTH_EVTPORT) or
				(_cid == CID_EVENT and port.second.auth == AUTH_EVTPORT)) {
			opk.did = _did;
			opk.cid = _cid;
			if(sessionID != 0 and sessionID == port.second.sessionID){
				sessionID = port.second.sessionID_origin;
			}
			if (port.second.Encrypt(data, _inlen, opk.data, opk.CBC_lowLen, sessionID) == 0) {
				auto action = packerTable[port.first]->sendPack(&opk);
				_al.push_front(std::pair(port.first, action));
			}
		}
	}

	return 0;
}

int
Ypoller::sendEVT2spr(alst_Type &_al, const DID_Type &_did, const uint8_t *data, const uint32_t _inlen,
					 uint32_t sessionID) {
	return send2spr(_al, _did, CID_EVENT, data, _inlen, sessionID);
}

Ypollact_Type
Ypoller::devMsgBack(const int _fd, const DID_Type &_did, const CID_Type _cid, const uint8_t *data,
					const uint32_t _inlen,
					uint32_t sessionID) {
	Ypack<0xFF0> opk;
	opk.did = _did;
	opk.cid = _cid;
	if (nodeTable[_did]->dataEncrypt(_fd, data, _inlen, opk.data, opk.CBC_lowLen, sessionID) == 0) {
		return packerTable[_fd]->sendPack(&opk);
	}
	return YPA_NULL;
}

Ypollact_Type
Ypoller::devMsgBack(const sockaddr_in &addr, const DID_Type &_did, const CID_Type _cid, const uint8_t *data,
					const uint32_t _inlen,
					uint32_t sessionID) {
	Ypack<0xFF0> opk;
	opk.did = _did;
	opk.cid = _cid;
	if (nodeTable[_did]->dataEncrypt(addr, data, _inlen, opk.data, opk.CBC_lowLen, sessionID) == 0) {
		return UDPPeerTable[addrToKey(addr)]->sendPack(&opk, addr);
	}
	return YPA_NULL;
}

Ypollact_Type
Ypoller::sprMsgBack(const int _fd, const DID_Type &_did, const CID_Type _cid, const uint8_t *data,
					const uint32_t _inlen,
					uint32_t sessionID) {
	Ypack<0xFF0> opk;
	opk.did = _did;
	opk.cid = _cid;
	if (dataEncrypt(_fd, data, _inlen, opk.data, opk.CBC_lowLen, sessionID) == 0) {
		return packerTable[_fd]->sendPack(&opk);
	}
	return YPA_NULL;
}

size_t Ypoller::packerTableSize(void) {
	return packerTable.size();
}

size_t Ypoller::nodeTableSize(void) {
	return nodeTable.size();
}



