#include "Yage.h"


Yage::Yage(uint32_t _deathAge, uint32_t _eventsRateTh) :
		dead(false),
		myage(0),
		deathAge(_deathAge),
		events(0),
		eventsRateTh(_eventsRateTh) {

}

Yage::~Yage() {
}

void Yage::setAgeTh(uint32_t _deathAge, uint32_t _eventsRateTh) {
	myage = 0;
	deathAge = _deathAge;
	events = 0;
	eventsRateTh = _eventsRateTh;

}

void Yage::refresh(void) {
	myage = 0;
	events++;
}

bool Yage::isOnline(void) const {
	return !dead;
}

int Yage::checker(const uint32_t _elapsed) {
	int rtn;
	myage += _elapsed;
	if (myage >= deathAge) {
		myage = deathAge;
		if (!dead) {
			rtn = OFFLINEEVENT;      //emit offline message
			dead = true;
		} else {
			rtn = OFFLINESTATUS;      // message
		}
	} else {
		if (events > (eventsRateTh * _elapsed)) {
			rtn = DEVICEEVENTFAULT;      //device fault: request too offten
		} else {
			rtn = DEVICEOK;
		}
		events = 0;
	}
	return rtn;
}
