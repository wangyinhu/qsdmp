#ifndef FCGICLI_H
#define FCGICLI_H

#include "QsdmpCli.h"

#define DEVAESKSIZE                        16
using SUPERCMD_TYPE = uint16_t;


class qezcli : public QsdmpCli {
public:
	qezcli(const char *_host, int _port, const DID_Type &_did, const CID_Type &_cid, const uint8_t *devk,
		   const uint8_t *headerk, int timeout);

	virtual ~qezcli();

	virtual int authSSW(uint8_t *_data, uint32_t len) override;

	virtual int authUDK(uint8_t *_data) override;

	virtual Ypollact_Type notmypack(Ypack<0xFF0> *pack);

	virtual Ypollact_Type mypackdata(Ypack<0xFF0> *pack);

	Ypollact_Type getpacks(std::list<Ypack<0xFF0> *> &packlist, uint64_t _flags);

	Ypollact_Type sendto(const DID_Type &_did, const CID_Type &_cid, const uint8_t *data, uint32_t len, uint32_t sessionID);

	int evtReg(void);

	int msgloadlogenable(void);

	int msgloadlogdisable(void);

	int setLogLevel(yloglevel _level);

	int loadcidroms(uint8_t cid);

	int loadcidmakers(void);

	int queryIP(uint64_t * dids, char IPaddresses[][16], int length, uint32_t sessionID);

	int queryStatus(uint64_t * dids, uint8_t *statusArray, int length, uint32_t sessionID);

	ssize_t getnodecount(void);

	ssize_t getpackercount(void);

	ssize_t getaomsgload1s(void);

	int updatedevK(const DID_Type &_did, const uint8_t *data);

	int switchdevsvr(const DID_Type &_did, const char *data);

	int Auth(const char * _TYPE);

private:
	int connecttoserver(const char * _TYPE);

	char *serverhost = 0;
	int serverport;
	int timeout;
};

#endif // FCGICLI_H
