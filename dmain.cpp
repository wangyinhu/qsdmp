#include <csignal>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include "Ypoller.h"
#include "Ylib.h"
#include "Ylog.h"
#include "rediscli.h"


//#define USE_RAPIDJSON

#ifdef USE_RAPIDJSON
#include "rapidjson/include/rapidjson/document.h"

#else

#define CONFIGURU_IMPLEMENTATION 1
#include "configuru.hpp"

#endif


int qsdmpdPort = 0;
uint64_t SuperDID;
Ypoller *thePoll = nullptr;


#ifdef USE_RAPIDJSON

#define MAXJSONCONFIGFILELENGTH		10000

static int getJsonConfig(char *filename) {
	char buf[MAXJSONCONFIGFILELENGTH];
	int fd = open(filename, O_RDONLY);

	if (fd > 0) {
		ssize_t length = read(fd, buf, MAXJSONCONFIGFILELENGTH);
		if (length > 0 && length < MAXJSONCONFIGFILELENGTH) {
			buf[length] = 0;
			rapidjson::Document document;
			document.Parse(buf);
			if (!document.IsObject()) {
				PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m syntax error.\n");
				return -1;
			} else {
				int RedisPort;
				auto itr = document.FindMember("RedisPort");
				if ((itr != document.MemberEnd()) && (itr->value.IsInt())) {
					RedisPort = itr->value.GetInt();
					if (RedisPort < 20 or RedisPort > 65535) {
						PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter RedisPort out of range (20 ~ 65535)\n");
						return -1;
					}
				} else {
					PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter RedisPort not found from config file.\n");
					return -1;
				}

				itr = document.FindMember("RedisAuthK");
				if ((itr != document.MemberEnd()) && (itr->value.IsString())) {
					rdb.setredispw(RedisPort, itr->value.GetString());
				} else {
					PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter RedisAuthK not found from config file.\n");
					return -1;
				}

				itr = document.FindMember("SuperDID");
				if ((itr != document.MemberEnd()) && (itr->value.IsString())) {
					hex2raw((uint8_t *) &SuperDID, itr->value.GetString());
				} else {
					PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter SuperDID not found from config file.\n");
					return -1;
				}

				itr = document.FindMember("qsdmpdPort");
				if ((itr != document.MemberEnd()) && (itr->value.IsInt())) {
					qsdmpdPort = itr->value.GetInt();
					if (RedisPort < 20 or RedisPort > 65535) {
						PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter RedisPort out of range (20 ~ 65535)\n");
						return -1;
					}
				} else {
					PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter qsdmpdPort not found from config file.\n");
					return -1;
				}

				itr = document.FindMember("logLevel");
				if ((itr != document.MemberEnd()) && (itr->value.IsInt())) {
					auto logLevel = itr->value.GetInt();
					if (logLevel < 1 or logLevel > 7) {
						PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter logLevel out of range [1 ~ 7]\n");
						return -1;
					}
					LOGLVLSET(logLevel);
				} else {
					PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter logLevel not found from config file.\n");
					return -1;
				}
			}
		} else {
			PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m read config file fail error=%s\n", strerror(errno));
			return -1;
		}
		close(fd);

	} else {
		PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m open config file fail. file name=%s, error=%s\n", filename,
				  strerror(errno));
		return -1;
	}
	return 0;
}

#else

static int getJsonConfig(char *filename) {
	int RedisPort;
	configuru::Config cfg = configuru::parse_file(filename, configuru::JSON);
	if (cfg.has_key("SuperDID")) {
		auto SuperDIDc = (std::string)cfg["SuperDID"];
		hex2raw((uint8_t *) &SuperDID, SuperDIDc.c_str());
	} else{
		PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter SuperDID not found from config file.\n");
		return -1;
	}
	if (cfg.has_key("RedisPort")) {
		RedisPort = (int)cfg["RedisPort"];
		if (RedisPort < 20 or RedisPort > 65535) {
			PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter RedisPort out of range (20 ~ 65535)\n");
			return -1;
		}
	} else{
		PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter RedisPort not found from config file.\n");
		return -1;
	}
	if (cfg.has_key("logLevel")) {
		auto logLevel = (int)cfg["logLevel"];
		if (logLevel < 1 or logLevel > 7) {
			PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter logLevel out of range [1 ~ 7]\n");
			return -1;
		}
		LOGLVLSET(logLevel);
	} else{
		PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter logLevel not found from config file.\n");
		return -1;
	}
	if (cfg.has_key("RedisAuthK")) {
		auto RedisAuthK = (std::string)cfg["RedisAuthK"];
		rdb.setredispw(RedisPort, RedisAuthK.c_str());
	} else{
		PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter RedisAuthK not found from config file.\n");
		return -1;
	}
	if (cfg.has_key("qsdmpdPort")) {
		qsdmpdPort = (int)cfg["qsdmpdPort"];
		if (qsdmpdPort < 20 or qsdmpdPort > 65535) {
			PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter qsdmpdPort out of range (20 ~ 65535)\n");
			return -1;
		}
	} else{
		PRINTLOGF(YLOG_ERR, "\x1b[31;1m error!\x1b[0m parameter qsdmpdPort not found from config file.\n");
		return -1;
	}
	return 0;
}

#endif


/**
 * @brief system signal handler
 * @param arg
 */
static void SIGINT_Handler(int arg) {
	PRINTLOGF(YLOG_ALERT, "SIGINT received, process quit in 5 seconds.\n");
	if (thePoll) {
		thePoll->stop(arg);
	}
}


/**
 * @brief system signal handler
 * @param arg
 */
static void SIGQUIT_Handler(int arg) {
	PRINTLOGF(YLOG_ALERT, "SIGQUIT received, process quit in 5 seconds.\n");
	if (thePoll) {
		thePoll->stop(arg);
	}
}


/**
 * @brief system signal handler
 * @param arg
 */
static void SIGPIPE_Handler(int arg) {
	PRINTLOGF(YLOG_ALERT, "SIGPIPE received.\n");
}


/**
 * @brief catch system signal
 */
static void sysSignalCatch(void) {
	struct sigaction act;
	act.sa_handler = SIGINT_Handler;
	sigaction(SIGINT, &act, nullptr);
	act.sa_handler = SIGQUIT_Handler;
	sigaction(SIGQUIT, &act, nullptr);
	act.sa_handler = SIGPIPE_Handler;
	sigaction(SIGPIPE, &act, nullptr);
}

/**
 * @brief change open file number limit to hardware limit
 * @return return 0 on success
 */
static int setNofile(void) {
	rlimit limit;
	getrlimit(RLIMIT_NOFILE, &limit);
	limit.rlim_cur = limit.rlim_max;
	setrlimit(RLIMIT_NOFILE, &limit);
	getrlimit(RLIMIT_NOFILE, &limit);
	PRINTLOGF(YLOG_ALERT, "RLIMIT_NOFILE set to %ld\n", limit.rlim_cur);
	return 0;
}

int argsHandle(bool &dm, char *&cfgFileName, int argc, char **argv) {
	const char *help = "Usage: \x1b[36;1m qsdmpd /path/to/Config_file [OPTION]\x1b[0m\n"
					   "\n"
					   "Options:\n"
					   "    -d\tdaemon mode\n"
					   "Config_file:\n"
					   "    config file is a json text file. must have following keys:\n"
					   "        \x1b[36;1m RedisPort\x1b[0m(number): port number of the redis server connecting to.\n"
					   "        \x1b[36;1m RedisAuthK\x1b[0m(hex string): hex of Auth key of the redis server.\n"
					   "        \x1b[36;1m qsdmpdPort\x1b[0m(number): qsdmpd port that is going to listen.\n"
					   "        \x1b[36;1m logLevel\x1b[0m(number): qsdmpd log level range in [1,7].\n";
	const char *errStr = "parameter error! type \n"
						 "Try '\x1b[36;1m qsdmpd --help\x1b[0m' for more information.\n";
	dm = false;
	if (argc == 1) {
		printf("Try '\x1b[36;1m qsdmpd --help\x1b[0m' for more information.\n");
		return -1;
	} else if (argc == 2 || argc == 3) {
		if (strcmp("--help", argv[1]) == 0 || strcmp("-h", argv[1]) == 0) {
			printf("%s", help);
			return -1;
		} else if (argv[1][0] != '-') {
			cfgFileName = argv[1];
			if (argc == 3 && strcmp(argv[2], "-d") == 0) {
				dm = true;
			}
			return 0;
		} else {
			printf("%s", errStr);
			return -1;
		}
	} else {
		printf("%s", errStr);
		return -1;
	}
}


/**
 * @brief main
 * @param argc
 * @param argv
 * @return 
 */
int main(int argc, char **argv) {
	char *cfgFileName;
	bool dm;

	if (argsHandle(dm, cfgFileName, argc, argv) != 0) {
		return -1;
	}

	if (0 == getJsonConfig(cfgFileName)) {
		setNofile();
		char strPort[10];
		sprintf(strPort, "%d", qsdmpdPort);
		Ypoller poll(SuperDID);
		thePoll = &poll;
		sysSignalCatch();
		if (dm) {
			if (-1 == daemon(1, 0)) {
				PRINTLOGF(YLOG_ALERT, "daemon(1,0) fail!\n");
				exit(EXIT_FAILURE);
			}
		}
		return poll.start(strPort);
	} else {
		PRINTLOGF(YLOG_ALERT, "\x1b[36;1m getJsonConfig fail.\x1b[0m\n");
		return -1;
	}
}


