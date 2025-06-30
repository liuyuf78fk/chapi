#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "ini.h"
#include "config.h"
#include "common.h"
#include "chapi-log.h"
#include <unistd.h>

#define MAX_PORT 65535
#define MIN_PORT 1

#ifndef DEFAULT_LOG_LEVEL
#define DEFAULT_LOG_LEVEL 2
#endif

static char *get_config_path(void)
{
	return CONF_FILE_PATH;
}

static int handler(void *user, const char *section, const char *name,
		   const char *value)
{
	struct chapi_config *cfg = (struct chapi_config *)user;

	if (!value || strlen(value) == 0) {
		LOG_ERR_MSG("Empty value for config key: [%s] %s", section,
			    name);
		return 0;
	}

	if (strcmp(name, "bind_address") == 0) {
		if (!is_valid_ipv4(value)) {
			LOG_ERR_MSG("Invalid bind_address: %s", value);
			return 0;
		}
		strncpy(cfg->bind_address, value,
			sizeof(cfg->bind_address) - 1);
		cfg->bind_address[sizeof(cfg->bind_address) - 1] = '\0';
	} else if (strcmp(name, "port") == 0) {
		char *endptr = NULL;
		long port = strtol(value, &endptr, 10);
		if (errno != 0 || *endptr != '\0' || port < MIN_PORT
		    || port > MAX_PORT) {
			LOG_ERR_MSG("Invalid port number: %s", value);
			return 0;
		}
		cfg->port = (int)port;
	} else if (strcmp(name, "rate_limit_window") == 0) {
		long val = strtol(value, NULL, 10);
		if (val <= 0 || val > 3600) {
			LOG_ERR_MSG("Invalid rate_limit_window: %s", value);
			return 0;
		}
		cfg->rate_limit_window = (int)val;
	} else if (strcmp(name, "rate_limit_count") == 0) {
		long val = strtol(value, NULL, 10);
		if (val <= 0 || val > 1000) {
			LOG_ERR_MSG("Invalid rate_limit_count: %s", value);
			return 0;
		}
		cfg->rate_limit_count = (int)val;
	} else if (strcmp(name, "max_clients") == 0) {
		long val = strtol(value, NULL, 10);
		if (val < 1 || val > 100000) {
			LOG_ERR_MSG("Invalid max_clients: %s", value);
			return 0;
		}
		cfg->max_clients = (int)val;
	} else if (strcmp(name, "log_level") == 0) {
		long val = strtol(value, NULL, 10);
		if (val < 0 || val > 2) {
			LOG_ERR_MSG("Invalid log_level: %s", value);
			return 0;
		}
		cfg->log_level = (int)val;
	} else if (strcmp(name, "enable_rate_limit") == 0) {
		char *endptr;
		long val = strtol(value, &endptr, 10);
		if (endptr == value || *endptr != '\0'
		    || (val != 0 && val != 1)) {
			LOG_ERR_MSG("Invalid value for enable_rate_limit: %s",
				    value);
			return 0;
		}
		cfg->enable_rate_limit = (int)val;
	}

	else {
		LOG_INFO_MSG("Unknown config key: [%s] %s (ignored)", section,
			     name);
	}

	return 1;
}

int load_config(struct chapi_config *cfg)
{

	strncpy(cfg->bind_address, DEFAULT_BIND_ADDR,
		sizeof(cfg->bind_address));
	cfg->port = DEFAULT_PORT;
	cfg->rate_limit_window = RATE_LIMIT_WINDOW;
	cfg->rate_limit_count = RATE_LIMIT_COUNT;
	cfg->max_clients = MAX_CLIENTS;
	cfg->log_level = DEFAULT_LOG_LEVEL;
#ifdef ENABLE_RATE_LIMIT
	cfg->enable_rate_limit = 1;
#else
	cfg->enable_rate_limit = 0;
#endif
	char *path = get_config_path();
	if (!path)
		return -1;

	if (ini_parse(path, handler, cfg) < 0) {
		return -1;
	}

	return 0;
}
