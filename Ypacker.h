#ifndef YPACKER_H
#define YPACKER_H

#include <cstdint>
#include <vector>
#include <list>
#include <unordered_set>
#include <openssl/aes.h>
#include "Ylog.h"
#include "sbvector.h"


using DID_Type = uint64_t;
using CID_Type = uint8_t;
using Ypollact_Type = uint32_t;

#define    YPA_NULL                ((Ypollact_Type)0x00U)
#define    YPA_OUTSWON             ((Ypollact_Type)0x01U)
#define    YPA_OUTSWOFF            ((Ypollact_Type)0x02U)
#define    YPA_TERMINATE           ((Ypollact_Type)0x04U)
#define    YPA_MYPACKGOT           ((Ypollact_Type)0x08U)
#define    YPA_NMPACKGOT           ((Ypollact_Type)0x10U)
#define    YPA_SENDFAIL            ((Ypollact_Type)0x20U)
#define    YPA_TOP                 ((Ypollact_Type)0x40U)


enum YpVer_Type : uint8_t {
	YPVER_TINY = 0,        //for pack length less than 0xF0 bytes
	YPVER_BASIC,        //for pack length less than 0xFF0 bytes
	YPVER_EXT,            //for pack length less than 0xFFFF0 bytes
	YPVER_TOP,
};


#define CID_AUTH_REQ            ((CID_Type)0x01U)         //auth request
#define CID_AUTH_ASR            ((CID_Type)0x02U)         //auth answer
#define CID_AUTH_ACK            ((CID_Type)0x03U)         //answer acknowledgment
#define CID_AUTH_TCK            ((CID_Type)0x04U)         //tick
#define CID_AUTH_UDK            ((CID_Type)0x05U)         //update aesk
#define CID_AUTH_SSW            ((CID_Type)0x06U)         //switch server
#define CID_AUTH_STR            ((CID_Type)0x07U)         //set tick rate

#define CID_EVENT               ((CID_Type)0x1EU)         //
#define CID_AUTH_END            ((CID_Type)0x1FU)         //

#define CID_APPS_SPR            ((CID_Type)0x20U)         //
#define CID_APPS_START          ((CID_Type)0x21U)         //
#define CID_APPS_CHG            ((CID_Type)0x21U)         //
#define CID_APPS_END            ((CID_Type)0x7FU)         //
#define CID_VAL_MASK            ((CID_Type)0x7FU)         //
#define CID_ERR_MASK            ((CID_Type)0x80U)         //

#define IS_CID_VALID(cid) ((CID_APPS_START <= (cid) and (cid) <= CID_APPS_END) or (cid) == 0)

union Yphead {
	uint8_t bytes[16];
	struct {
		DID_Type did;
		uint16_t ZERO;        //const 0
		uint16_t VAR;        //variable
		uint16_t bnc;
		YpVer_Type ver;
		CID_Type cid;
	} __attribute__((packed));

	void print(yloglevel level) {
		PRINTLOGF(level, "headmem=");
		PRINTLOGB(level, bytes, 16);
		PRINTLOGF(level, "did=");
		PRINTLOGB(level, &did, 8);
		PRINTLOGF(level, "ZERO=");
		PRINTLOGB(level, &ZERO, 2);
		PRINTLOGF(level, "VAR=");
		PRINTLOGB(level, &VAR, 2);
		PRINTLOGF(level, "bnc=");
		PRINTLOGB(level, &bnc, 2);
		PRINTLOGF(level, "ver=");
		PRINTLOGB(level, &ver, 1);
		PRINTLOGF(level, "cid=");
		PRINTLOGB(level, &cid, 1);
	}
} __attribute__((packed));


//#define YPACKMEMORYLEAKDEBUG			//for pack buffer
//#define YPACKERMEMORYLEAKDEBUG		//for packer worker

#ifdef YPACKMEMORYLEAKDEBUG
extern uint64_t packmemcount;
#endif //YPACKMEMORYLEAKDEBUG


template<int DATASIZE>
struct Ypack {

#ifdef YPACKMEMORYLEAKDEBUG
	Ypack(){printf("Ypack construst, packmemcount=%lu\n", ++packmemcount);}
	~Ypack(){printf("Ypack distrust, packmemcount=%lu\n", --packmemcount);}
#endif //YPACKMEMORYLEAKDEBUG

	union {
		uint8_t head_bytes[16];
		struct {
			DID_Type did;            //64 bit
			uint32_t sessionID;        //32 bit
			uint16_t CBC_lowLen;    //16 bit block number count
			uint8_t highLen;        //8  bit
			CID_Type cid;            //8  bit
		};
	};
	uint8_t data[DATASIZE];

	void set_length(uint32_t len) {
		CBC_lowLen = (uint16_t) (len & 0x0000ffffu);
		highLen = (uint8_t) ((len & 0x00ff0000u) >> 16u);
	}

	uint32_t get_length(void) {
		return CBC_lowLen + highLen * 0x10000u;
	}

	void print(yloglevel level) {
		PRINTLOGF(level, "head_bytes=");
		PRINTLOGB(level, head_bytes, 16);
		PRINTLOGF(level, "did=");
		PRINTLOGB(level, &did, 8);
		PRINTLOGF(level, "sessionID=");
		PRINTLOGB(level, &sessionID, 4);
		PRINTLOGF(level, "CBC_lowLen=");
		PRINTLOGB(level, &CBC_lowLen, 2);
		PRINTLOGF(level, "highLen=");
		PRINTLOGB(level, &highLen, 1);
		PRINTLOGF(level, "cid=");
		PRINTLOGB(level, &cid, 1);
	}
};


class Ypacker {
public:
	explicit Ypacker(int _fd);

	virtual ~Ypacker();

	Ypollact_Type sendPack(Ypack<0xFF0> *_pack);

	Ypollact_Type readyWrite(void);

	Ypollact_Type getSecPacks(std::list<Ypack<0xFF0> *> &packlist);

protected:
	int fd;
private:
	sbvector inbuff;
	sbvector outbuff;

	int getPacksFromData(std::list<Ypack<0xFF0> *> &packlist, Ypack<0xFF0> *_data, uint32_t len);

	int getPacksFromBuffer(std::list<Ypack<0xFF0> *> &packlist, Ypack<0xFF0> * buf);

public:
	static AES_KEY ek;
	static AES_KEY dk;
	static void loadHeaderKey(const uint8_t *aesk);
};

uint32_t packup(Ypack<0xFF0> *_pack);

int headDecrypt(uint8_t* _data);

bool isHeadValid(const Yphead &headmem);

#endif // YPACKER_H
