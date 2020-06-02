//
// Created by yale on 7/22/18.
//

#ifndef QSDMP_ENCRYPTION_H
#define QSDMP_ENCRYPTION_H

#include "cstdint"
#include <openssl/aes.h>
#include <cstdio>
#include "Ypacker.h"

/**
 * Sync flow:
 * client:	authReq		send pack: block16byte(token + rand1) + block16byte(zero)
 * server:	authReqAsr	check(token == TOKEN)		send pack: block16byte(rand1 + rand2) + block16byte(time1 + time2)
 * client:	authAsrAck	check(rand1, time1 == time2)		send pack: block16byte(rand2 + initial pack INC OUT and IN)
 * server:	authAck 	check(rand2), setup(inPackINC, outPackINC)
 * PASS
 */


union syncBlock {
	uint8_t bytes[16];
	struct {
		long long unsigned int rand0;
		union {
			long long unsigned int rand1;
			struct {
				uint32_t inPackINC;
				uint32_t outPackINC;
			};
		};
	};
};

union authBlock {
	uint8_t bytes[16];
	struct {
		int64_t packTime;
		uint32_t sessionID;
		uint32_t packINC;
	};
};

union timeBlock {
	uint8_t bytes[16];
	struct {
		uint64_t time1;
		uint64_t time2;
	};
};

enum AUTHSTAT_T {
	AUTH_NA = 0,        //step 1 and 2
	AUTH_OK,        //step 3 and 4
	AUTH_EVTPORT,    //
	AUTH_TOP,
};


class encryption {
public:
	void authReq(uint8_t *_data);

	int authAsrAck(uint8_t *_data);

	int authReqAsr(uint8_t *_data);

	int authAck(uint8_t *_data);

	int Decrypt(uint8_t *_data, uint16_t CBC, uint32_t &sessionID);

	int Encrypt(const uint8_t *plainData, uint32_t dataSize, uint8_t *chpherdata, uint16_t &outCBC, uint32_t sessionID);

	int packDecrypt(Ypack<0xFF0> *pack);

	AUTHSTAT_T auth = AUTH_NA;
	uint32_t sessionID = 0;
	uint32_t sessionID_origin = 0;

	void loadKey(AES_KEY *ek_p, AES_KEY *dk_p);

private:
	union {
		struct {
			uint32_t inPackINC;
			uint32_t outPackINC;
		};
		long long unsigned int randnum;
	};

	AES_KEY *ek_p;
	AES_KEY *dk_p;

	static constexpr uint64_t AUTH_TOC = 1235;
};


#endif //QSDMP_ENCRYPTION_H
