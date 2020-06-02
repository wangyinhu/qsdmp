#ifndef DPACKER_H
#define DPACKER_H

#include "Ypacker.h"
#include <sys/epoll.h>
#include "Yage.h"
#include "Ylib.h"


class Dpacker : public Ypacker, public Yage {
public:
	Dpacker(const sockaddr &_addr, int _fd, uint32_t _deathAge, uint32_t _eventsRateTh);

	virtual ~Dpacker();

	Ypollact_Type eventhandle(std::list<Ypack<0xFF0> *> &packlist, const epoll_event *epollevent);

	const char *getIPaddress(void) const;

	const std::unordered_set<DID_Type> &getDidTable(void);

	int removedid(const DID_Type &uid);

	Ypollact_Type sendPack(Ypack<0xFF0> *_pack);

private:
	char *charIPaddress;
	std::unordered_set<DID_Type> didTable;

};

#endif // DPACKER_H
