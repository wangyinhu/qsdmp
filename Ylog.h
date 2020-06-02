#ifndef YLOG_H
#define YLOG_H

#include <cstdio>
#include <cstdint>
#include <sys/timerfd.h>
#include <cstdarg>

using yloglevel = uint8_t;

enum : yloglevel {
	YLOG_EMERG = 0,        //•system is unusable Level 0
	YLOG_ALERT,        //•Alert Messages, Severity Level 1
	YLOG_CRIT,        //•Critical Messages, Severity Level 2
	YLOG_ERR,        //•Error Messages, Severity Level 3
	YLOG_WARNING,        //•Warning Messages, Severity Level 4
	YLOG_NOTICE,        //•Notification Messages, Severity Level 5
	YLOG_INFO,        //•Informational Messages, Severity Level 6
	YLOG_DEBUG,        //•Debugging Messages, Severity Level 7
	YLOG_TOP
};


class Ylog {
public:
	explicit Ylog(const char *_name);

	virtual ~Ylog();

	int setLogLevel(yloglevel _loglevel);

	int logf(yloglevel _loglevel, const char *_template, ...);

	int logf(yloglevel _loglevel, const char *_template, va_list args);

	int logb(yloglevel _loglevel, const void *data, uint32_t len);

	yloglevel getLoglevel() const;

private:
	char *name;
	char *fullname;
	yloglevel loglevel = YLOG_INFO;
private:

	void newfilename(void);

	time_t logfiletime;

	int printlinestart(yloglevel _loglevel, const time_t &_time, FILE *_pFile);
};

extern Ylog yglog;

#define PRINTLOGVF(_loglevel, _template, args)    	if((_loglevel) <= yglog.getLoglevel()) yglog.logf(_loglevel, _template, args)
#define PRINTLOGF(_loglevel, args...)    	if(_loglevel <= yglog.getLoglevel()) yglog.logf(_loglevel, args)
#define PRINTLOGB(_loglevel, args...)    	if(_loglevel <= yglog.getLoglevel()) yglog.logb(_loglevel, args)
#define LOGLVLSET(_loglevel)    			yglog.setLogLevel(_loglevel)
#define LOGLVLGET(_loglevel)    			yglog.getLoglevel()


#endif // YLOG_H


