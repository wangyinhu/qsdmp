#include "Dpacker.h"
#include "Ylog.h"


Dpacker::Dpacker(const sockaddr &_addr, const int _fd, uint32_t _deathAge, uint32_t _eventsRateTh) :
		Ypacker(_fd),
		Yage(_deathAge, _eventsRateTh) {
	charIPaddress = addrtostr(_addr);
	PRINTLOGF(YLOG_DEBUG, "Dpacker construct addr=%s\n", charIPaddress);
}

Dpacker::~Dpacker() {
	PRINTLOGF(YLOG_DEBUG, "Dpacker distruct addr=%s\n", charIPaddress);
	free(charIPaddress);
}

Ypollact_Type Dpacker::sendPack(Ypack<0xFF0> *_pack) {
	refresh();
	return Ypacker::sendPack(_pack);
}

Ypollact_Type Dpacker::eventhandle(std::list<Ypack<0xFF0> *> &packlist, const epoll_event *epollevent) {
	if (fd == epollevent->data.fd) {
		refresh();
		if (epollevent->events & EPOLLHUP) {    //never happens!!!!!!!!!!!!
			return YPA_TERMINATE;
		} else {
			auto rtn = YPA_NULL;
			if (epollevent->events & EPOLLIN) {
				rtn |= getSecPacks(packlist);
				for (auto &i : packlist) {
					didTable.insert(i->did);
				}
			}
			if (epollevent->events & EPOLLOUT) {
				rtn |= readyWrite();
			}
			return rtn;
		}
	} else {
		PRINTLOGF(YLOG_ERR, "Dpacker eventhandle wrong event fd");
		return YPA_NULL;
	}
}

const char *Dpacker::getIPaddress(void) const {
	return charIPaddress;
}

const std::unordered_set<DID_Type> &Dpacker::getDidTable(void) {
	return didTable;
}

int Dpacker::removedid(const DID_Type &uid) {
	didTable.erase(uid);
	return 0;
}
