//
// Created by yale on 7/27/18.
//

#include "FLPUcharger.h"
#include <cstdio>
#include <cstring>
#include "IAPserver.h"

#define VERSION    6

using CMD_TYPE = uint8_t;

#define CMD_IAP ((CMD_TYPE)0x08U)

Ylog yglog("FLPUcharger");


using IAPCMD_TYPE = uint8_t;

#define IAPCMD_START					((IAPCMD_TYPE)0x01U)
#define IAPCMD_CODE						((IAPCMD_TYPE)0x02U)
#define IAPCMD_START_CMD				((IAPCMD_TYPE)0x03U)

IAPserver IAPsvr;

FLPUcharger::FLPUcharger(uint64_t _did) :
		Absflpu(_did) {
	//printf("FLPUcharger construct did=0x%016lX\n", did);
}

FLPUcharger::~FLPUcharger() {
	//printf("FLPUcharger disstruct did=0x%016lX\n", did);
}

int FLPUcharger::checker(int period) {
	return 0;
}

int FLPUcharger::deviceMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks,
								  std::list<Vbarray *> &_bckpcks) {
	if (_size) {
		if (_MSGin[0] == CMD_IAP) {
			PRINTLOGF(YLOG_DEBUG, "CMD_IAP received device data=\n");
			PRINTLOGB(YLOG_DEBUG, _MSGin, _size);
			if (not IAPsvr.isLoaded()) {
				PRINTLOGF(YLOG_DEBUG, "IAP rom not loaded.\n");
				return 0;
			}
			switch (_MSGin[1]) {
				case IAPCMD_START: {
					if(_size < 1 + 1 + 4){
						PRINTLOGF(YLOG_DEBUG, "IAPCMD_START pack too small.size=%d\n", _size);
						return 0;
					}
					uint32_t baseAddress;
					uint8_t i = 2;
					memcpy(&baseAddress, _MSGin + i, sizeof(baseAddress));
					if (not IAPsvr.isBaseAddress(baseAddress)) {
						PRINTLOGF(YLOG_DEBUG, "not IAPsvr.isBaseAddress(baseAddress)\n");
						return 0;
					}
					uint16_t Ver = IAPsvr.getVersionNum();
					uint32_t codeLength = IAPsvr.getCodeLength(baseAddress);
					uint32_t checkSum = IAPsvr.getCheckSum(baseAddress);
					auto vector1 = new Vbarray(
							sizeof(CMD_IAP) +
							sizeof(IAPCMD_START) +
							sizeof(Ver) +
							sizeof(baseAddress) +
							sizeof(codeLength) +
							sizeof(checkSum));
					i = 0;
					vector1->data()[i++] = CMD_IAP;
					vector1->data()[i++] = IAPCMD_START;
					memcpy(vector1->data() + i, &Ver, sizeof(Ver));
					i += sizeof(Ver);
					memcpy(vector1->data() + i, &baseAddress, sizeof(baseAddress));
					i += sizeof(baseAddress);
					memcpy(vector1->data() + i, &codeLength, sizeof(codeLength));
					i += sizeof(codeLength);
					memcpy(vector1->data() + i, &checkSum, sizeof(checkSum));
					i += sizeof(checkSum);
					_bckpcks.push_front(vector1);
					//notice upper server
					auto vector2 = new Vbarray(*vector1);
					vector2->data()[1] = IAPCMD_START_CMD;
					_fwdpcks.push_front(vector2);
					return 0;
				}
					break;
				case IAPCMD_CODE: {
					if(_size < 1 + 1 + 2 + 4 + 2){
						PRINTLOGF(YLOG_DEBUG, "IAPCMD_CODE pack too small.size=%d\n", _size);
						return 0;
					}
					uint16_t Ver;
					uint32_t programAddress;
					uint16_t length;
					uint8_t i = 2;    //CMD + SUB_CMD
					memcpy(&Ver, _MSGin + i, sizeof(Ver));
					i += sizeof(Ver);
					memcpy(&programAddress, _MSGin + i, sizeof(programAddress));
					i += sizeof(programAddress);
					memcpy(&length, _MSGin + i, sizeof(length));
					i += sizeof(length);
					auto vector1 = new Vbarray(i + length);
					i = 0;
					vector1->data()[i++] = CMD_IAP;
					vector1->data()[i++] = IAPCMD_CODE;
					memcpy(vector1->data() + i, &Ver, sizeof(Ver));
					i += sizeof(Ver);
					memcpy(vector1->data() + i, &programAddress, sizeof(programAddress));
					i += sizeof(programAddress);
					auto lengthIndex = i;
					uint16_t outCodeLength;
					i += sizeof(outCodeLength);
					IAPsvr.getCode(programAddress, length, vector1->data() + i, outCodeLength);
					memcpy(vector1->data() + lengthIndex, &outCodeLength, sizeof(outCodeLength));
					vector1->resize(i + outCodeLength);
					_bckpcks.push_front(vector1);
					return 0;
				}
					break;
				default:
					break;
			}
		}
	}
	auto vector1 = new Vbarray(_size);
	memcpy(vector1->data(), _MSGin, _size);
	_fwdpcks.push_front(vector1);
	PRINTLOGF(YLOG_DEBUG, "FLPUcharger received device data=\n%s\n", (char *) _MSGin);
	PRINTLOGB(YLOG_DEBUG, _MSGin, _size);
	return 0;
}

int FLPUcharger::serverMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks,
								  std::list<Vbarray *> &_bckpcks) {
	if (_size) {
		if (_MSGin[0] == CMD_IAP and _MSGin[1] == IAPCMD_START_CMD) {
			PRINTLOGF(YLOG_DEBUG, "CMD_IAP received server data=\n");
			PRINTLOGB(YLOG_DEBUG, _MSGin, _size);
			if (not IAPsvr.isLoaded()) {
				PRINTLOGF(YLOG_DEBUG, "IAP rom not loaded.\n");
				auto vector2 = new Vbarray(_size);
				memcpy(vector2->data(), _MSGin, _size);
				vector2->data()[1] |= 0x80u;
				_bckpcks.push_front(vector2);
				return 0;
			}
		}
	}

	auto vector1 = new Vbarray(_size);
	memcpy(vector1->data(), _MSGin, _size);
	_fwdpcks.push_front(vector1);
	PRINTLOGF(YLOG_DEBUG, "FLPUcharger received upper data=\n%s\n", (char *) _MSGin);
	PRINTLOGB(YLOG_DEBUG, _MSGin, _size);
	return 0;
}

int FLPUcharger::version(void) {
	return VERSION;
}


extern "C" {
	Absflpu *maker(uint64_t _did) {
		return new FLPUcharger(_did);
	}

	int IAPServer_load(void) {
		return IAPsvr.loadROM(CHARGERFLPU);
	}

	ddllinfo_t FLPU_Init(logprintf_t _logprintf) {
		ddllinfo_t rtn;
		rtn.sign = FLPUSOSIGN;
		rtn.cid = CHARGERFLPU;
		rtn.ver = VERSION;
		rtn.maker = maker;
		rtn.IAPROM_loader = IAPServer_load;
		return rtn;
	}
}


