#include "Ylib.h"
#include "Ylog.h"
#include "rediscli.h"
#include <cstdlib>
#include <cstring>


rediscli::rediscli() {
}

rediscli::~rediscli() {
	if (port) {
		clearIpv4();
		clearStat();
	}
}

void rediscli::clearStat(void) {
	connectdb();
	redisauth();
	auto reply = (redisReply *) redisCommand(conn, "DEL stat");
	freeReplyObject(reply);
	closedb();
}

void rediscli::clearIpv4(void) {
	connectdb();
	redisauth();
	auto reply = (redisReply *) redisCommand(conn, "DEL ipv4");
	freeReplyObject(reply);
	closedb();
}


int rediscli::linestatlog(const DID_Type &did, const int &stat) {
	const char *statstr;
	if (stat == 10) {
		statstr = "UP";
	} else if (stat == 11) {
		statstr = "DOWN";
	} else if (stat == 12) {
		statstr = "TIMEOUT";
	} else {
		statstr = "UNKNOW";
	}

	connectdb();

	redisauth();
	auto reply = (redisReply *) redisCommand(conn, "HSET stat %b %s", &did, sizeof(DID_Type), statstr);
	freeReplyObject(reply);

	closedb();
	return 0;
}

bool rediscli::Kexist(const DID_Type &did) {
	int rtn;
	connectdb();

	redisauth();

	auto reply = (redisReply *) redisCommand(conn, "HEXISTS aesk %b", &did, sizeof(DID_Type));

	if (reply->type == REDIS_REPLY_INTEGER && reply->integer == 1) {
		rtn = true;
	} else {
		rtn = false;
	}
	freeReplyObject(reply);
	closedb();
	return rtn;
}

int rediscli::closedb(void) {
	redisFree(conn);
	return 0;
}

int rediscli::connectdb(void) {
	conn = redisConnectWithTimeout("localhost", port, timeout);
	if (conn == NULL || conn->err) {
		if (conn) {
			redisFree(conn);
		} else {
		}
		PRINTLOGF(YLOG_ERR, "error! redis connect fail. localhost, port=%d\n", port);
		exit(1);
	}
	return 0;
}


int rediscli::getaesk(uint8_t *aesk, const DID_Type &did) {
	int rtn;
	connectdb();

	redisauth();

	auto reply = (redisReply *) redisCommand(conn, "HGET aesk %b", &did, sizeof(DID_Type));

	if (reply->type == REDIS_REPLY_STRING && reply->len == 16) {
		memcpy(aesk, reply->str, 16);
		rtn = 0;
	} else {
		rtn = -1;
	}

	freeReplyObject(reply);

	closedb();
	return rtn;
}

void rediscli::setredispw(const int _port, const char *hexpw) {
	port = _port;
	auto hexlen = strlen(hexpw);
	uint8_t data[hexlen / 2 + 1];

	auto datalen = hex2raw(data, hexpw, INT64_MAX);
	key.resize(datalen);
	memcpy(key.data(), data, datalen);

	connectdb();
	redisauth();
	closedb();
}

void rediscli::redisauth(void) {
	auto reply = (redisReply *) redisCommand(conn, "AUTH %b", key.data(), key.size());
	if (reply->type == REDIS_REPLY_STATUS && reply->len == 2) {
		if (memcmp(reply->str, "OK", 2) != 0) {
			PRINTLOGF(YLOG_ERR, "error! redis AUTH fail. \n");
			exit(-1);
		}
	} else {
		PRINTLOGF(YLOG_ERR, "error! redis AUTH fail. \n");
		exit(-1);
	}
	freeReplyObject(reply);
}

void rediscli::setaddr(const DID_Type &did, const char *addr) {
	connectdb();

	redisauth();
	auto reply = (redisReply *) redisCommand(conn, "HSET ipv4 %b %s", &did, sizeof(DID_Type), addr);

	freeReplyObject(reply);

	closedb();
	return;
}


int rediscli::getdevice(char *data, int &datalen, const DID_Type &did) {
	int rtn;
	connectdb();

	redisauth();
	char hexdid[20];
	raw2hex(hexdid, (uint8_t *) &did, sizeof(DID_Type));
	auto reply = (redisReply *) redisCommand(conn, "HGET devices %s", hexdid);

	if (reply->type == REDIS_REPLY_STRING && reply->len < datalen) {
		memcpy(data, reply->str, reply->len);
		data[reply->len] = 0;
		datalen = reply->len;
		rtn = 0;
	} else {
		rtn = -1;
	}

	freeReplyObject(reply);

	closedb();
	return rtn;
}


int rediscli::getcompanys(char *data, int &datalen, const char *company) {
	int rtn;
	connectdb();

	redisauth();
	auto reply = (redisReply *) redisCommand(conn, "HGET companys %s", company);

	if (reply->type == REDIS_REPLY_STRING && reply->len <= datalen) {
		memcpy(data, reply->str, reply->len);
		data[reply->len] = 0;
		datalen = reply->len;
		rtn = 0;
	} else {
		rtn = -1;
	}

	freeReplyObject(reply);

	closedb();
	return rtn;
}

int rediscli::getstat(uint8_t *_stat, const DID_Type &did) {
	int rtn;
	connectdb();

	redisauth();

	auto reply = (redisReply *) redisCommand(conn, "HGET stat %b", &did, sizeof(DID_Type));

	if (reply->type == REDIS_REPLY_STRING && reply->len < 10) {
		memcpy(_stat, reply->str, reply->len);
		_stat[reply->len] = 0;
		rtn = 0;
	} else {
		rtn = -1;
	}

	freeReplyObject(reply);

	closedb();
	return rtn;
}


int rediscli::getipv4(uint8_t *_ipv4, const DID_Type &did) {
	int rtn;
	connectdb();

	redisauth();

	auto reply = (redisReply *) redisCommand(conn, "HGET ipv4 %b", &did, sizeof(DID_Type));

	if (reply->type == REDIS_REPLY_STRING && reply->len < 20) {
		memcpy(_ipv4, reply->str, reply->len);
		_ipv4[reply->len] = 0;
		rtn = 0;
	} else {
		rtn = -1;
	}

	freeReplyObject(reply);

	closedb();
	return rtn;
}

