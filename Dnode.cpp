#include <cstdarg>
#include "Ylog.h"
#include "Dnode.h"
#include <dirent.h>
#include <dlfcn.h>
#include <cstring>

Dnode::Dnode(const uint64_t &_did, uint32_t _deathAge, uint32_t _eventsRateTh) :
		QsdmpSvr(_did),
		Yage(_deathAge, _eventsRateTh) {
	//PRINTLOGF(YLOG_DEBUG, "node construct did=0x%016lX\n", did);
}

Dnode::~Dnode() {
	//delete all devices in devices table
	for (auto &i : devices) {
		switch (i.first) {
			default: {
				delete i.second;
			}
		}
	}
	//PRINTLOGF(YLOG_DEBUG, "node disstruct did=0x%016lX\n", did);
}

int Dnode::deviceMSGProcess(Ypack<0xFF0> *pack, std::list<Vbarray *> &_fwdpcks,
							std::list<Vbarray *> &_backpacks) {
	refresh();

	if (devices.count(pack->cid) == 0) {
		if (this->devicecreate(pack->did, pack->cid) != 0) {
			PRINTLOGF(YLOG_ERR, "create device fail. did=0x%016lX, cid=0x%02X\n", pack->did, pack->cid);
			return -1;
		}
	}

//	PRINTLOGF(YLOG_DEBUG, "data from device:\nfd=%d, did=0x%016lX, cid=0x%02X data=%s\nbin data=\n", fd, pack->did,
//			  pack->cid, pack->data);
//	PRINTLOGB(YLOG_DEBUG, pack->data, pack->get_length());
	return devices[pack->cid]->deviceMSGProcess(pack->data, pack->get_length(), _fwdpcks, _backpacks);
}

int Dnode::serverMSGProcess(Ypack<0xFF0> *pack, std::list<Vbarray *> &_fwdpcks, std::list<Vbarray *> &_backpacks) {
	if (devices.count(pack->cid) == 0) {
		if (this->devicecreate(pack->did, pack->cid) != 0) {
			PRINTLOGF(YLOG_ERR, "create device fail. did=0x%016lX, cid=0x%02X\n", pack->did, pack->cid);
			return -1;
		}
	}
//	PRINTLOGF(YLOG_DEBUG, "super to device: did=0x%016lX, cid=0x%02X data=%s\n", pack->did, pack->cid, pack->data);
	return devices[pack->cid]->serverMSGProcess(pack->data, pack->get_length(), _fwdpcks, _backpacks);
}


int Dnode::devicecreate(DID_Type _did, CID_Type _cid) {
	if (makertable.count(_cid)) {
		devices[_cid] = makertable[_cid].maker(_did);
		PRINTLOGF(YLOG_DEBUG, "Dnode::devicecreate success\n");
		return 0;
	} else if (makertable.count(DEFAULTFLPU)) {
		devices[_cid] = makertable[DEFAULTFLPU].maker(_did);
		PRINTLOGF(YLOG_INFO, "Dnode::devicecreate success. default FLPU used as cid=0x%02X\n", _cid);
		return 0;
	} else {
		devices[_cid] = new FLPUdefault(_did);
		PRINTLOGF(YLOG_INFO, "Dnode::devicecreate fail! unknow cid=0x%02X, "
							 "DEFAULTFLPU not loaded. build in default FLPU loaded\n", _cid);
		return 0;
	}
}


std::unordered_map<CID_Type, ddllinfo_t>  Dnode::makertable;

void FLPU_logPrintf(yloglevel _loglevel, const char *_template, ...) {
	va_list args;
	va_start (args, _template);
	PRINTLOGVF(_loglevel, _template, args);
	va_end (args);
}

int Dnode::loadRoms(uint8_t cid){
	if(makertable.count(cid)){
		return makertable[cid].IAPROM_loader();
	} else{
		return -1;
	}
}

int Dnode::loadmakers(void) {
	DIR *d;
	struct dirent *dir;
	d = opendir("FLPU_plugins/");
	if (d) {
		while ((dir = readdir(d)) != nullptr) {
			if (dir->d_type == DT_REG) {
				PRINTLOGF(YLOG_INFO, "------------------------------%-15s-----------------------------------\n",
						  dir->d_name);
				char fullpath[300];
				sprintf(fullpath, "FLPU_plugins/%s", dir->d_name);
				auto handle1 = dlopen(fullpath, RTLD_LAZY);
				if (handle1 == nullptr) {
					PRINTLOGF(YLOG_NOTICE, "dl error! in dlopen() filename='%s' error=%s\n", fullpath, dlerror());
					continue;
				}

				auto FLPU_Init = (FLPU_Init_t) dlsym(handle1, "FLPU_Init");
				if (FLPU_Init == nullptr) {
					PRINTLOGF(YLOG_NOTICE, "dl error! in dlsym(handle1, 'FLPU_Init') filename='%s' error=%s\n",
							  fullpath,
							  dlerror());
					continue;
				}

				auto info = FLPU_Init(FLPU_logPrintf);
				if (info.sign != FLPUSOSIGN) {
					PRINTLOGF(YLOG_NOTICE, "dl error! sign dont match. FLPUSOSIGN=%d. filename=%s\n", info.sign,
							  fullpath);
					continue;
				}
				if (not IS_CID_VALID(info.cid)) {
					PRINTLOGF(YLOG_NOTICE, "dl error! cid invalid. cid=%d. filename=%s\n", info.cid, fullpath);
					continue;
				}

				if (makertable[info.cid].ver < info.ver) {
					makertable[info.cid] = info;
					PRINTLOGF(YLOG_INFO, "ddll load success! filename='%s' cid=0x%02X, version=%d\n", fullpath,
							  info.cid, info.ver);
				} else {
					PRINTLOGF(YLOG_INFO, "old version ddll not loaded! filename='%s' cid=0x%02X, version=%d\n",
							  fullpath, info.cid, info.ver);
				}
			}
		}

		closedir(d);

		if (makertable.empty()) {
			PRINTLOGF(YLOG_WARNING, "error! no valid device plugin found. build in FLPU used.\n");
		}

	} else {
		PRINTLOGF(YLOG_WARNING, "error! opendir 'FLPU_plugins' fail. error=%s\nbuild in FLPU used.", strerror(errno));
	}
	return 0;
}

