#ifndef DEVPORT_H
#define DEVPORT_H

#include "Ypacker.h"
#include "encryption.h"

#define DEFAULTAESKDID        ((DID_Type)1)
#define HEADERKEYDID        ((DID_Type)2)
#define SUPERYDID            ((DID_Type)3)


class QsdmpCli : public Ypacker, public encryption {
public:
	QsdmpCli(int _fd, const DID_Type &_did, const CID_Type &_cid, const uint8_t *devk, const uint8_t *headerk);

	~QsdmpCli() override;

	Ypollact_Type packHandle(Ypack<0xFF0> *pack);

	Ypollact_Type sendReq(void);

	Ypollact_Type sendTck(void);

	Ypollact_Type send(const uint8_t *data, uint32_t len, uint32_t sessionID);

	Ypollact_Type
	sendto(const DID_Type &_did, const CID_Type &_cid, const uint8_t *data, uint32_t len, uint32_t sessionID);

	virtual void upevent_cb(void);

	virtual Ypollact_Type notmypack(Ypack<0xFF0> *pack);

	virtual Ypollact_Type mypackdata(Ypack<0xFF0> *pack);

	virtual void authTck_cb(time_t &svrtime);

	virtual int authUDK(uint8_t *_data) = 0;

	virtual int authSSW(uint8_t *_data, uint32_t len) = 0;

	DID_Type did;
	CID_Type cid;

	void loadDevk(const uint8_t *aesk);

protected:
	time_t lastactive;
private:
	AES_KEY ek;
	AES_KEY dk;
};

#endif // DEVPORT_H
