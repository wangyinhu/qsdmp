#ifndef XDB_H
#define XDB_H

#include <hiredis/hiredis.h>
#include "Ypacker.h"

class rediscli {
public:
	rediscli();

	virtual ~rediscli();

	void setredispw(const int _port, const char *hexpw);

	int getdevice(char *data, int &datalen, const DID_Type &did);

	int getcompanys(char *data, int &datalen, const char *company);

	int linestatlog(const DID_Type &did, const int &stat);

	bool Kexist(const DID_Type &uid);

	int getaesk(uint8_t *aesk, const DID_Type &did);

	int getstat(uint8_t *_stat, const DID_Type &did);

	int getipv4(uint8_t *_ipv4, const DID_Type &did);

	void setaddr(const DID_Type &did, const char *addr);

	void clearStat(void);

	void clearIpv4(void);

private:
	const timeval timeout = {0, 500000};
	redisContext *conn;

	void redisauth(void);

	int connectdb(void);

	int closedb(void);

	std::vector<char> key;
	int port = 0;
};

extern rediscli rdb;


#endif // XDB_H
