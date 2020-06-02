#ifndef TEST_H
#define TEST_H

#include "Absflpu.h"


class FLPUdefault : public Absflpu {
public:
	explicit FLPUdefault(uint64_t _did);

	~FLPUdefault() final;

	int version(void) final;

	int checker(int period) final;

	int
	deviceMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks, std::list<Vbarray *> &_bckpcks) final;

	int
	serverMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks, std::list<Vbarray *> &_bckpcks) final;
};

#endif // TEST_H
