#include <sys/socket.h>
#include "UDPPeer.h"

UDPPeer::UDPPeer(uint32_t _deathAge, uint32_t _eventsRateTh) : Yage(_deathAge, _eventsRateTh) {

}

UDPPeer::~UDPPeer() {

}

Ypollact_Type UDPPeer::packHandle(Ypack<0xFF0> * _pack, ssize_t len){
	auto packLength = headDecrypt((uint8_t *) _pack);
	if(packLength == len){
		didTable.insert(_pack->did);
		return YPA_NULL;
	} else {
		return YPA_TERMINATE;
	}
}

Ypollact_Type UDPPeer::sendPack(Ypack<0xFF0> *_pack, const sockaddr_in &addr){
	refresh();
	auto sizep = packup(_pack);
	PRINTLOGF(YLOG_DEBUG, "Ypacker sendPack fd=%d, data length=%d, data=\n", fd, sizep);
	PRINTLOGB(YLOG_DEBUG, _pack, sizep);
	sendto(fd, _pack, sizep, 0, (struct sockaddr *) &addr, sizeof(addr));
	return YPA_NULL;
}

int UDPPeer::fd;