//
// Created by yale on 8/13/18.
//

#ifndef QSDMP_UDPPEER_H
#define QSDMP_UDPPEER_H


#include <netinet/in.h>
#include "Yage.h"
#include "Ypacker.h"

class UDPPeer : public Yage {
public:
	UDPPeer(uint32_t _deathAge, uint32_t _eventsRateTh);
	virtual ~UDPPeer();
	std::unordered_set<DID_Type> didTable;
	Ypollact_Type packHandle(Ypack<0xFF0> * _pack, ssize_t len);
	Ypollact_Type sendPack(Ypack<0xFF0> *_pack, const sockaddr_in &addr);
	static int fd;
};


#endif //QSDMP_UDPPEER_H
