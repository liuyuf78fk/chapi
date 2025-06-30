// chapi-log.h

#ifndef CHAPI_LOG_H
#define CHAPI_LOG_H

#include <syslog.h>
#include <stdarg.h>
#include "common.h"

extern int g_log_level;


#define LOG_ERR_MSG(fmt, ...)  do { if (g_log_level >= 1) syslog(LOG_ERR, fmt, ##__VA_ARGS__); } while (0)
#define LOG_INFO_MSG(fmt, ...) do { if (g_log_level >= 2) syslog(LOG_INFO, fmt, ##__VA_ARGS__); } while (0)

#endif
