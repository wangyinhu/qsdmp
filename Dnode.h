#ifndef DNODE_H
#define DNODE_H

#include "Yage.h"
#include "QsdmpSvr.h"
#include <unordered_map>
#include "FLPUdefault.h"


class Dnode : public QsdmpSvr, public Yage {
public:
	Dnode(const uint64_t &_did, uint32_t _deathAge, uint32_t _eventsRateTh);

	virtual ~Dnode();

	int
	deviceMSGProcess(Ypack<0xFF0> *pack, std::list<Vbarray *> &_fwdpcks, std::list<Vbarray *> &_bckpcks);

	int serverMSGProcess(Ypack<0xFF0> *pack, std::list<Vbarray *> &_fwdpcks, std::list<Vbarray *> &_bckpcks);

	static int loadmakers(void);
	static int loadRoms(uint8_t cid);
private:
	std::unordered_map<CID_Type, Absflpu *> devices;

	int devicecreate(DID_Type _did, CID_Type _cid);

	static std::unordered_map<CID_Type, ddllinfo_t> makertable;
};

#endif // DNODE_H
