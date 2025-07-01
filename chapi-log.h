/*
 * CHAPI - ChaCha20-based Host Address Protocol over UDP
 * 
 * Copyright (C) 2025 Liu Yu <f78fk@live.com>
 * 
 * This file is part of CHAPI.
 * 
 * CHAPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * CHAPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with CHAPI.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef CHAPI_LOG_H
#define CHAPI_LOG_H

#include <syslog.h>
#include <stdarg.h>
#include "common.h"

extern int g_log_level;


#define LOG_ERR_MSG(fmt, ...)  do { if (g_log_level >= 1) syslog(LOG_ERR, fmt, ##__VA_ARGS__); } while (0)
#define LOG_INFO_MSG(fmt, ...) do { if (g_log_level >= 2) syslog(LOG_INFO, fmt, ##__VA_ARGS__); } while (0)

#endif
