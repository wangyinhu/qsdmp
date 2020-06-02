#include "FLPUdefault.h"
#include <cstdio>
#include <cstring>

#define VERSION    5

logprintf_t logprintf = nullptr;


FLPUdefault::FLPUdefault(uint64_t _did) :
		Absflpu(_did) {
	//printf("FLPUdefault construct did=0x%016lX\n", did);
}

FLPUdefault::~FLPUdefault() {
	//printf("FLPUdefault disstruct did=0x%016lX\n", did);
}

int FLPUdefault::checker(int period) {
	return 0;
}

int FLPUdefault::deviceMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks,
								 std::list<Vbarray *> &_bckpcks) {
	auto vector1 = new Vbarray(_size);
	memcpy(vector1->data(), _MSGin, _size);
	_fwdpcks.push_front(vector1);
	logprintf(YLOG_ALERT, "FLPUdefault received device data=%s\n", (char*)_MSGin);
	return 0;
}

int FLPUdefault::serverMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks,
								 std::list<Vbarray *> &_bckpcks) {
	auto vector1 = new Vbarray(_size);
	memcpy(vector1->data(), _MSGin, _size);
	_fwdpcks.push_front(vector1);
	logprintf(YLOG_ALERT, "FLPUdefault received upper data=%s\n", (char*)_MSGin);
	return 0;
}

int FLPUdefault::version(void) {
	return VERSION;
}


extern "C" {
Absflpu *maker(uint64_t _did) {
	return new FLPUdefault(_did);
}

ddllinfo_t FLPU_Init(logprintf_t _logprintf) {
	logprintf = _logprintf;
	ddllinfo_t rtn;
	rtn.sign = FLPUSOSIGN;
	rtn.cid = DEFAULTFLPU;
	rtn.ver = VERSION;
	rtn.maker = maker;
	return rtn;
}
}
