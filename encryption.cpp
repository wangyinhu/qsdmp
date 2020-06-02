//
// Created by yale on 7/22/18.
//

#include "encryption.h"
#include "Ylog.h"
#include <immintrin.h>


void encryption::authReq(uint8_t *_data) {
	auth = AUTH_NA;
	syncBlock authblock;

	authblock.rand0 = AUTH_TOC;
	_rdrand64_step(&randnum);
	authblock.rand1 = randnum;
	AES_encrypt(authblock.bytes, _data, ek_p);
	AES_encrypt(_data, _data + 16, ek_p);
}


/**
 *
 * @param _data 32 byte = 2 * 16 byte cipher blocks
 * @return
 */
int encryption::authReqAsr(uint8_t *_data) {
	auth = AUTH_NA;
	syncBlock authblock;

	AES_decrypt(_data, authblock.bytes, dk_p);
	if (AUTH_TOC == authblock.rand0) {
		authblock.rand0 = authblock.rand1;
		_rdrand64_step(&randnum);
		authblock.rand1 = randnum;
		AES_encrypt(authblock.bytes, _data, ek_p);
		timeBlock timeblock;
		timeblock.time1 = time(nullptr);
		timeblock.time2 = timeblock.time1;
		for (int i = 0; i < 16; i++) {
			timeblock.bytes[i] xor_eq _data[i];
		}
		AES_encrypt(timeblock.bytes, _data + 16, ek_p);

		return 0;
	} else {
		return -1;
	}

}

int encryption::authAsrAck(uint8_t *_data) {
	syncBlock authblock;
	AES_decrypt(_data, authblock.bytes, dk_p);
	if (randnum == authblock.rand0) {
		authblock.rand0 = authblock.rand1;
		timeBlock timeblock;
		AES_decrypt(_data + 16, timeblock.bytes, dk_p);
		for (int i = 0; i < 16; i++) {
			timeblock.bytes[i] xor_eq _data[i];
		}
		if (timeblock.time1 != timeblock.time2) {
			printf("authAsrAck: incoming timestamp not equal!!\n");
			return -1;
		}
		auth = AUTH_OK;
		_rdrand64_step(&randnum);        //init pack INC in and out
		authblock.rand1 = randnum;        //send back to server
		AES_encrypt(authblock.bytes, _data, ek_p);
		return 0;
	} else {
		return -1;
	}
}


int encryption::authAck(uint8_t *_data) {
	syncBlock authblock;
	AES_decrypt(_data, authblock.bytes, dk_p);
	if (randnum == authblock.rand0) {
		auth = AUTH_OK;
		outPackINC = authblock.inPackINC;
		inPackINC = authblock.outPackINC;
		return 0;
	} else {
		return -1;
	}

}

/**
 *
 * @param _data	(in / out)
 * @param CBC (in) Cipher Block Count
 * @param sessionID (out) session ID
 * @return	on success :decrypted data length, on fail return -1.
 */
int encryption::Decrypt(uint8_t *_data, uint16_t CBC, uint32_t &sessionID) {
	if (CBC >= 2) {
		authBlock auth_block;
		AES_decrypt(_data, auth_block.bytes, dk_p);
		auto timeError = auth_block.packTime - time(nullptr);

		if ((auth_block.packINC >= this->inPackINC) && (20 > timeError) && (-20 < timeError)) {
			this->inPackINC = auth_block.packINC;
			sessionID = auth_block.sessionID;
			for (uint16_t i = 1u; i < CBC; i++) {
				AES_decrypt(_data + i * 16, auth_block.bytes, dk_p);
				for (uint8_t j = 0u; j < 16; j++) {
					_data[(i - 1) * 16 + j] xor_eq auth_block.bytes[j];
				}
			}
			auto inOutLength = CBC * 16u;
			for (inOutLength -= 16 + 1; inOutLength > 0; inOutLength--) {        //16: 1 block; 1: size to index
				if (_data[inOutLength] == 0) {
					break;
				} else if (_data[inOutLength] != 0xff) {
					PRINTLOGF(YLOG_ALERT,
							  "\x1b[36;1mdataDecrypt: DATA TAIL FORMAT NOT CORRECT!!!, MUST BEING ATTACKED!!!!!!!!!!!\x1b[0m");
					return -1;
				}
			}
			return inOutLength;
		} else {
			PRINTLOGF(YLOG_WARNING, "Decrypt: time or INC varify fail! "
						   "inPackINC=%d, packINC=%d, timeError=%ld\n", this->inPackINC, auth_block.packINC, timeError);
			return -1;
		}
	} else {
		return -1;
	}
}

/**
 *
 * @param plainData
 * @param dataSize
 * @param chpherdata
 * @param outCBC
 * @param sessionID
 * @return
 */
int encryption::Encrypt(const uint8_t *plainData, const uint32_t dataSize, uint8_t *chpherdata, uint16_t &outCBC,
						uint32_t sessionID) {
	if (auth >= AUTH_OK) {
		uint16_t div = (uint16_t)1u + (uint16_t)(dataSize / 16u);    //data blocks
		outCBC = div + (uint16_t)1u;                        //data blocks + 1 session block
		authBlock auth_block;
		auth_block.packTime = (uint32_t) time(nullptr);
		auth_block.packINC = outPackINC++;
		auth_block.sessionID = sessionID;
		AES_encrypt(auth_block.bytes, chpherdata, ek_p);

		uint8_t aessum[16];

		for (uint16_t j = 0u; j < div; j++) {
			for (uint8_t k = 0u; k < 16; k++) {
				uint32_t index = j * 16u + k;
				if (index < dataSize) {
					aessum[k] = plainData[index] xor chpherdata[index];
				} else if (index == dataSize) {
					aessum[k] = chpherdata[index];        // xor 0
				} else {
					aessum[k] = chpherdata[index] xor (uint8_t) 0xff;
				}
			}
			AES_encrypt(aessum, chpherdata + (j + 1) * 16, ek_p);
		}
		return 0;
	} else {
		return -1;
	}
}

int encryption::packDecrypt(Ypack<0xFF0> *pack) {
	auto len = Decrypt(pack->data, pack->CBC_lowLen, pack->sessionID);
	if(len >= 0){
		pack->set_length((uint32_t)len);
	}
	return len;
}


void encryption::loadKey(AES_KEY *_ek_p, AES_KEY *_dk_p) {
	this->ek_p = _ek_p;
	this->dk_p = _dk_p;
}




