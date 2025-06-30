#ifndef CONFIG_H
#define CONFIG_H

struct chapi_config {
	char bind_address[64];
	int port;
	int rate_limit_window;
	int rate_limit_count;
	int max_clients;
	int log_level;
	int enable_rate_limit;
};

int load_config(struct chapi_config *cfg);

#endif				// CONFIG_H
