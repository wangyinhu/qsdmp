#ifndef YPOLLER_H
#define YPOLLER_H

#include "Dpacker.h"
#include "Dnode.h"
#include "UDPPeer.h"
#include <unordered_map>
#include <unordered_set>
#include <sys/epoll.h>
#include <list>
#include <utility>


using alst_Type = std::list<std::pair<int, Ypollact_Type>>;

class Ypoller : public QsdmpSvr {
public:
	explicit Ypoller(const DID_Type &_did);

	virtual ~Ypoller();

	int start(const char *_port);

	void stop(int);

	int send2dev(alst_Type &_al, const DID_Type &_did, CID_Type _cid, const uint8_t *data, uint32_t _inlen, uint32_t sessionID);

	int send2spr(alst_Type &_al, const DID_Type &_did, CID_Type _cid, const uint8_t *data, uint32_t _inlen, uint32_t sessionID);

	int sendEVT2spr(alst_Type &_al, const DID_Type &_did, const uint8_t *data, uint32_t _inlen, uint32_t sessionID);

	Ypollact_Type
	devMsgBack(int _fd, const DID_Type &_did, CID_Type _cid, const uint8_t *data, uint32_t _inlen, uint32_t sessionID);

	Ypollact_Type
	devMsgBack(const sockaddr_in &addr, const DID_Type &_did, CID_Type _cid, const uint8_t *data, uint32_t _inlen, uint32_t sessionID);

	Ypollact_Type
	sprMsgBack(int _fd, const DID_Type &_did, CID_Type _cid, const uint8_t *data, uint32_t _inlen, uint32_t sessionID);

	size_t packerTableSize(void);

	size_t nodeTableSize(void);

	int outevensw(const int _fd, const bool _sw);

	int rmconn(const int _fd);

	int rmconn(const sockaddr_in &addr);

	int rmnodeport(const DID_Type &_did, const int _fd);

	int rmnodeport(const DID_Type &_did, const sockaddr_in &addr);

	int thesfd;
	int UDPsfd;
	int theefd;
	int thetfd;
	bool keepRunning = true;
	int maxEvent;
	int SecMaxEvent;
	std::unordered_map<int, Dpacker *> packerTable;
	std::unordered_map<uint64_t, UDPPeer *> UDPPeerTable;
	std::unordered_map<DID_Type, Dnode *> nodeTable;

	int add_epoll(int _fd);

	int timerhandle(void);

	int acceptAddEpoll(void);

	int UDPHandler(void);

	void clientEventHandle(epoll_event *_epollevent);

	static int create_server(const char *_port);

	static int createUDPServer(const char *_port);

	static int tcp_create_and_bind(const char *_port);

	static int udp_create_and_bind(const char *_port);

	int newconn(int _fd, const sockaddr &_addr);

	int checker(uint32_t _period);

	int timerfd_create_and_arm(int _seconds);

	void actionHandle(int _fd, Ypollact_Type _action);

	void actionHandle(const alst_Type &_al);

	Ypollact_Type upPackHandle(alst_Type &_al, int _fd, Ypack<0xFF0> *_pack);

	Ypollact_Type downPackHandle(alst_Type &_al, int _fd, Ypack<0xFF0> *_pack);

	Ypollact_Type downPackHandle(alst_Type &_al, const sockaddr_in &addr, Ypack<0xFF0> *_pack);

	Ypollact_Type superPackHandle(alst_Type &_al, int _fd, Ypack<0xFF0> *_pack);

	uint64_t packcounter = 0;
	uint64_t msgload1s = 0;
	bool msgloadenable = false;
};

#endif // YPOLLER_H
