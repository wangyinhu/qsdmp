#include "Ylog.h"
#include "Ylib.h"
#include <cstring>
#include <sys/timerfd.h>
#include <cstdint>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#define    LOGFILESPLITTIME            (24*60*60)
#define    TIMESTRINGROOMINBYTES        (26 + 5 + 20)
#define    QDSLOGDIR                    "/var/log/Qsdmpd"
#define    LINESPLIT                    " >>  "


const char *LOGLVLSTR[] = {
		"unusable: ",
		"•Alert: ",
		"•Critical: ",
		"•Error: ",
		"•Warning: ",
		"•Notification: ",
		"•Informational: ",
		"•Debugging: ",
};

const char *LOGLVLDETAILSTR[] = {
		"•system is unusable Level 0",
		"•Alert Messages, Severity Level 1",
		"•Critical Messages, Severity Level 2",
		"•Error Messages, Severity Level 3",
		"•Warning Messages, Severity Level 4",
		"•Notification Messages, Severity Level 5",
		"•Informational Messages, Severity Level 6",
		"•Debugging Messages, Severity Level 7",
};


Ylog::Ylog(const char *_name) {
	name = (char *) malloc(strlen(_name) + 20);
	fullname = (char *) malloc(strlen(_name) + 40);
	sprintf(name, "%s-%06d", _name, getpid());

	newfilename();
	if (-1 == mkdir(QDSLOGDIR, 0777)) {
		if (errno == EACCES) {
			printf("\x1b[31;1merror\x1b[0m occur when making log dir=%s, error=%s\n", QDSLOGDIR, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}


Ylog::~Ylog() {
	free(name);
	free(fullname);
}

int Ylog::setLogLevel(const yloglevel _loglevel) {
	if (_loglevel < YLOG_TOP) {
		loglevel = _loglevel;
		this->logf(YLOG_ALERT, "log level set to %s\n", LOGLVLDETAILSTR[_loglevel]);
		return 0;
	} else {
		return -1;
	}
}


int Ylog::logf(yloglevel _loglevel, const char *_template, ...) {
	//================see if new log file is needed=============
	time_t _time;
	time(&_time);
	if (_time - logfiletime >= LOGFILESPLITTIME) {
		newfilename();
	}
	//==================log=====================
	FILE *pFile = fopen(fullname, "a");
	if (pFile == nullptr) {
		perror("open or create log file fail.\n");
		exit(EXIT_FAILURE);
	}
	//----------------print line start----------
	printlinestart(_loglevel, _time, pFile);

	//---to log file---
	va_list args;
	va_start (args, _template);
	vfprintf(pFile, _template, args);
	va_end (args);

	//---to terminal---
	va_start (args, _template);
	vprintf(_template, args);
	va_end (args);

	auto len = strlen(_template);
	if (len > 0) {
		if (_template[len - 1] != '\n') {
			fputc('\n', pFile);
			putchar('\n');
		}
	} else {
		fputc('\n', pFile);
		putchar('\n');
	}

	fclose(pFile);
	return 0;
}

int Ylog::logf(yloglevel _loglevel, const char *_template, va_list args) {
	//================see if new log file is needed=============
	time_t _time;
	time(&_time);
	if (_time - logfiletime >= LOGFILESPLITTIME) {
		newfilename();
	}
	//==================log=====================
	FILE *pFile = fopen(fullname, "a");
	if (pFile == nullptr) {
		perror("open or create log file fail.\n");
		exit(EXIT_FAILURE);
	}
	//----------------print line start----------
	printlinestart(_loglevel, _time, pFile);

	va_list args_bkp;
	__va_copy(args_bkp, args);
	//---to log file---
	vfprintf(pFile, _template, args);

	//---to terminal---
	vprintf(_template, args_bkp);

	auto len = strlen(_template);
	if (len > 0) {
		if (_template[len - 1] != '\n') {
			fputc('\n', pFile);
			putchar('\n');
		}
	} else {
		fputc('\n', pFile);
		putchar('\n');
	}

	fclose(pFile);
	return 0;
}

int Ylog::printlinestart(yloglevel _loglevel, const time_t &_time, FILE *_pFile) {
	char a[TIMESTRINGROOMINBYTES];
	ctime_r(&_time, a);
	strcpy(a + 24, LINESPLIT);
	constexpr auto splitlen = strlen(LINESPLIT);
	strcpy(a + 24 + splitlen, LOGLVLSTR[_loglevel]);
	fputs(a, _pFile);
	return 0;
}

int Ylog::logb(yloglevel _loglevel, const void *_data, uint32_t len) {
	auto data = (uint8_t *) _data;

	FILE *pFile = fopen(fullname, "a");

	//----------------print line start----------
	time_t _time;
	time(&_time);
	printlinestart(_loglevel, _time, pFile);

	char temp[len * 2 + 1];
	raw2hex(temp, data, len);


	//---to log file---
	fprintf(pFile, "%s\n", temp);

	//---to terminal---
	printf("%s\n", temp);

	fclose(pFile);
	return 0;
}

void Ylog::newfilename(void) {

	time(&logfiletime);    //refresh file time
	struct tm result;
	localtime_r(&logfiletime, &result);

	sprintf(fullname, "%s/%s-%04d%02d%02d_%02d%02d%02d.log", QDSLOGDIR, name,
			result.tm_year + 1900,
			result.tm_mon + 1,
			result.tm_mday,
			result.tm_hour,
			result.tm_min,
			result.tm_sec);
}

yloglevel Ylog::getLoglevel() const {
	return loglevel;
}

