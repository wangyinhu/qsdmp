#ifndef YAGE_H
#define YAGE_H

#include <cstdint>

enum : uint32_t {
	DEVICEOK = 0,
	OFFLINESTATUS,
	DEVICEEVENTFAULT,
	OFFLINEEVENT,
};


class Yage {
public:
	Yage(uint32_t _deathAge, uint32_t _eventsRateTh);

	virtual ~Yage();

	void refresh(void);         //received a heartbeat pack,can emit online event

	bool isOnline(void) const;

	int checker(uint32_t _elapsed);     //periodly Check offline status,can emit offline event

	void setAgeTh(uint32_t _deathAge, uint32_t _eventsRateTh);

private:

	bool dead;

	uint32_t myage;         //increase 1 in checker,clear in refresh. judged in periodcheck ,see if beyond dathage.

	uint32_t deathAge;           //max age before dead

	uint32_t events;             //clear in periodcheck, increase 1 in refresh. judged in periodcheck ,see if beyond error threshold.

	uint32_t eventsRateTh;      //error threshold.

};


#endif // YAGE_H
