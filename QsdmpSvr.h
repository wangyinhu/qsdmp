#ifndef UNODE_H
#define UNODE_H


#include <openssl/aes.h>
#include <unordered_map>
#include "Dpacker.h"
#include "encryption.h"

#define DEFAULTAESKDID        0x0000000000000001
#define HEADERKEYDID        0x0000000000000002


class QsdmpSvr {
public:
	explicit QsdmpSvr(const uint64_t &_did);

	virtual ~QsdmpSvr();

	size_t rmport(int _fd);

	size_t rmport(const sockaddr_in &addr);

	enum lnk_event : int {
		LNK_EVENT_NUN = 0,
		LNK_EVENT_UP,
		LNK_EVENT_SWSVROK,
		LNK_EVENT_SWSVRFAIL,
		LNK_EVENT_SETAESKOK,
		LNK_EVENT_SETAESKFAIL,
		LNK_EVENT_SETTCKRATEOK,
		LNK_EVENT_SETTCKRATEFAIL,
		LNK_EVENT_APPDATAIN,
		LNK_EVENT_ERROR,
		LNK_EVENT_TOP,
	};

	lnk_event SecPackHandle(const int &fd, Ypack<0xFF0> *packin, Ypack<0xFF0> *&packBack);

	lnk_event SecPackHandle(const sockaddr_in &addr, Ypack<0xFF0> *packin, Ypack<0xFF0> *&packBack);

	std::unordered_map<int, encryption> portTable;

	std::unordered_map<uint64_t , encryption> UDPportTable;

	int dataEncrypt(int _fd, const uint8_t *textdata, const uint32_t &textsize, uint8_t *chpherdata,
					uint16_t &outCBC, uint32_t sessionID);

	int dataEncrypt(const sockaddr_in &addr, const uint8_t *textdata, const uint32_t &textsize, uint8_t *chpherdata,
					uint16_t &outCBC, uint32_t sessionID);

	int loadk(void);

	bool isdefaultk(void) const;

	int setEvtPort(int _fd);
protected:
	AES_KEY ek;
	AES_KEY dk;
	DID_Type did;


private:
	bool defaultK;

	lnk_event SecPackHandle(encryption &port, Ypack<0xFF0> *packin, Ypack<0xFF0> *&packBack);
};

uint64_t addrToKey(const sockaddr_in &addr);

sockaddr_in keyToAddr(const uint64_t &key);



#endif // UNODE_H


