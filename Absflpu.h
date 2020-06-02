#ifndef XDEVICE_H
#define XDEVICE_H

#include <cstdint>
#include <list>
#include <vector>
#include "Ylog.h"


#define DEFAULTFLPU        0
#define CHARGERFLPU        0x21U
#define FLPUSOSIGN        12345

using Vbarray = std::vector<unsigned char>;


class Absflpu {
public:
	explicit Absflpu(uint64_t _did);

	virtual ~Absflpu();

	uint64_t did;

public:
	virtual int checker(int period) = 0;

	virtual int version(void) = 0;

	virtual int deviceMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks,
								 std::list<Vbarray *> &_bckpcks) = 0;

	virtual int serverMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks,
								 std::list<Vbarray *> &_bckpcks) = 0;
};


typedef Absflpu *(*maker_t)(uint64_t _did);
typedef int (*IAPROM_loader_t)(void);

struct ddllinfo_t {
	uint32_t sign = 0;
	uint16_t cid = 0;
	uint16_t ver = 0;
	maker_t maker = nullptr;
	IAPROM_loader_t IAPROM_loader = nullptr;
};

typedef void (*logprintf_t)(yloglevel _loglevel, const char *_template, ...);
typedef ddllinfo_t (*FLPU_Init_t)(logprintf_t _logprintf);


#endif // XDEVICE_H

