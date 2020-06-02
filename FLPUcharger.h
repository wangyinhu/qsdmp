//
// Created by yale on 7/27/18.
//

#ifndef QSDMP_CHARGERFLPU_H
#define QSDMP_CHARGERFLPU_H

#include "Absflpu.h"


class FLPUcharger : public Absflpu {
public:
	explicit FLPUcharger(uint64_t _did);

	~FLPUcharger() final;

	int version(void) final;

	int checker(int period) final;

	int
	deviceMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks, std::list<Vbarray *> &_bckpcks) final;

	int
	serverMSGProcess(uint8_t *_MSGin, uint32_t _size, std::list<Vbarray *> &_fwdpcks, std::list<Vbarray *> &_bckpcks) final;
};


#endif //QSDMP_CHARGERFLPU_H
