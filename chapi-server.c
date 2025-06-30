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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include "common.h"
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include "config.h"
#include "chapi-log.h"

#define LOG_CLIENT_REQUEST(ip) \
    do { \
        static time_t last_log = 0; \
        static int req_count = 0; \
        req_count++; \
        if (time(NULL) - last_log > 5 || req_count % 100 == 0) { \
            LOG_INFO_MSG("Processed %d requests. Last IP: %s", req_count, ip); \
            last_log = time(NULL); \
        } \
    } while(0)

static time_t get_monotonic_time()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

typedef struct {
	char ip[INET_ADDRSTRLEN];
	time_t *timestamps;
	int index;
} client_entry;

int init_rate_limit(int max_clients);
void free_rate_limit(void);

volatile sig_atomic_t shutdown_requested = 0;
static unsigned char key[KEY_LEN];
static client_entry *clients = NULL;
static int client_count = 0;
static int sockfd = 0;
static struct chapi_config config;

int init_rate_limit(int max_clients)
{
	if (max_clients < 1) {
		return -1;
	}
	if (clients != NULL) {
		free_rate_limit();
	}

	clients = (client_entry *) calloc(max_clients, sizeof(client_entry));
	if (!clients) {
		LOG_ERR_MSG("Failed to allocate memory for clients");
		return -1;
	}

	for (int i = 0; i < max_clients; ++i) {
		clients[i].timestamps =
		    (time_t *) calloc(config.rate_limit_count, sizeof(time_t));
		if (!clients[i].timestamps) {
			LOG_ERR_MSG
			    ("Failed to allocate timestamps for client %d", i);
			for (int j = 0; j < i; ++j) {
				free(clients[j].timestamps);
			}
			free(clients);
			clients = NULL;
			return -1;
		}
	}

	client_count = 0;
	return 0;
}

void free_rate_limit()
{
	if (clients) {
		for (int i = 0; i < config.max_clients; ++i) {
			free(clients[i].timestamps);
		}
		free(clients);
		clients = NULL;
	}
	client_count = 0;
}

void secure_erase(void *ptr, size_t len)
{
	sodium_memzero(ptr, len);
}

void cleanup()
{
	if (sockfd >= 0) {
		LOG_INFO_MSG("Server shutting down gracefully...");
		close(sockfd);
		sockfd = -1;
	}
	free_rate_limit();
	LOG_INFO_MSG("Cleaned up rate limit resources");
	secure_erase(key, KEY_LEN);
	closelog();
}

void handle_signal(int sig)
{

	const char *sig_name = "";
	switch (sig) {
	case SIGTERM:
		sig_name = "SIGTERM";
		break;
	case SIGINT:
		sig_name = "SIGINT";
		break;
	case SIGQUIT:
		sig_name = "SIGQUIT";
		break;
	default:
		sig_name = "UNKNOWN";
	}
	syslog(LOG_INFO, "Received %s, shutting down...", sig_name);
	shutdown_requested = 1;

	if (sockfd >= 0) {
		shutdown(sockfd, SHUT_RDWR);
		close(sockfd);
		sockfd = -1;
	}
}

void setup_signal_handlers(void)
{
	struct sigaction sa;
	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
}

void get_client_ip(char *ipbuf, size_t buflen,
		   const struct sockaddr_in *cliaddr)
{
	if (!inet_ntop(AF_INET, &(cliaddr->sin_addr), ipbuf, buflen)) {
		strncpy(ipbuf, "0.0.0.0", buflen);
		ipbuf[buflen - 1] = '\0';
	}
}

int is_rate_limited(const char *ip)
{
	time_t now;
	int i, j;

	if (!clients || !ip)
		return 0;

	now = get_monotonic_time();

	for (i = 0; i < client_count; i++) {
		if (strcmp(clients[i].ip, ip) == 0) {
			int count = 0;

			for (j = 0; j < config.rate_limit_count; j++) {
				if (now - clients[i].timestamps[j] <
				    config.rate_limit_window)
					count++;
			}

			if (count >= config.rate_limit_count)
				return 1;

			if (clients[i].index >= config.rate_limit_count)
				clients[i].index = 0;
			clients[i].timestamps[clients[i].index] = now;
			clients[i].index++;
			return 0;
		}
	}

	if (client_count < config.max_clients) {
		strncpy(clients[client_count].ip, ip, INET_ADDRSTRLEN - 1);
		clients[client_count].ip[INET_ADDRSTRLEN - 1] = '\0';

		memset(clients[client_count].timestamps, 0,
		       sizeof(time_t) * config.rate_limit_count);

		clients[client_count].timestamps[0] = now;
		clients[client_count].index = 1;
		client_count++;
	}

	return 0;
}

int main(void)
{

	atexit(cleanup);

	openlog("chapi-server", LOG_PID, LOG_DAEMON);
	LOG_INFO_MSG("Starting chapi-server %s (Build: %s %s)", VERSION,
		     __DATE__, __TIME__);

	if (load_config(&config) == 0) {
		g_log_level = config.log_level;
	} else {
		LOG_ERR_MSG
		    ("Failed to load configuration file, using default configuration.");
	}

	setup_signal_handlers();

	if (config.enable_rate_limit) {
		if (init_rate_limit(config.max_clients) != 0) {
			LOG_ERR_MSG("Failed to initialize rate limiting");
			return -1;
		}
	}

	if (sodium_init() < 0) {
		LOG_ERR_MSG("libsodium init failed");
		return -1;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		LOG_ERR_MSG("socket creation failed");
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(config.bind_address);
	servaddr.sin_port = htons(config.port);

	int opt = SOCKET_REUSEADDR_ON;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		LOG_ERR_MSG("setsockopt failed: %s", strerror(errno));
		return -1;
	}

	if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) <
	    0) {
		LOG_ERR_MSG("bind failed,port %d", config.port);
		close(sockfd);
		return -1;
	}

	LOG_INFO_MSG("Server started on %s:%d\n", config.bind_address,
		     config.port);

	int key_source = 0;
	if (load_key(key, &key_source) != 0) {
		LOG_ERR_MSG
		    ("Fatal: failed to load valid key from file or macro.");
	} else {
		if (key_source == KEY_SOURCE_FILE) {
			LOG_INFO_MSG("Key loaded from file successfully.");
		} else if (key_source == KEY_SOURCE_MACRO) {
			LOG_INFO_MSG("Key loaded from macro definition.");
		}
	}

	unsigned char buffer[MAX_MSG_LEN] __attribute__((aligned(64)));
	unsigned char nonce[NONCE_LEN];
	unsigned char decrypted[MAX_MSG_LEN];
	unsigned char ciphertext[MAX_MSG_LEN];
	unsigned char send_nonce[NONCE_LEN];
	unsigned char sendbuf[NONCE_LEN + MAX_MSG_LEN];

	ssize_t bytes_received = -1;

	while (!shutdown_requested) {
		struct sockaddr_in cliaddr;
		socklen_t len = sizeof(cliaddr);
		char ip[INET_ADDRSTRLEN];

		bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
					  (struct sockaddr *)&cliaddr, &len);

		if (bytes_received < 0) {
			if (shutdown_requested && errno == EBADF) {
				break;
			}

			LOG_ERR_MSG("recvfrom error: %s", strerror(errno));
			continue;
		}

		if (bytes_received < (ssize_t) NONCE_LEN) {

			continue;
		}

		memcpy(nonce, buffer, NONCE_LEN);

		static unsigned char last_nonce[NONCE_LEN];
		if (memcmp(nonce, last_nonce, NONCE_LEN) == 0) {
			LOG_ERR_MSG("Duplicate nonce detected");
			continue;
		}
		memcpy(last_nonce, nonce, NONCE_LEN);

		unsigned long long decrypted_len = 0;
		if (crypto_aead_chacha20poly1305_ietf_decrypt
		    (decrypted, &decrypted_len, NULL, buffer + NONCE_LEN,
		     bytes_received - NONCE_LEN, NULL, 0, nonce, key) != 0) {
			LOG_ERR_MSG
			    ("Decryption failed (Possible invalid key/nonce)");
			continue;
		}

		if (decrypted_len < CMD_GETIP_LEN
		    || memcmp(decrypted, CMD_GETIP, CMD_GETIP_LEN) != 0) {
			get_client_ip(ip, sizeof(ip), &cliaddr);

			char cmd_preview[11] = { 0 };
			size_t preview_len =
			    decrypted_len < 10 ? decrypted_len : 10;
			memcpy(cmd_preview, decrypted, preview_len);
			cmd_preview[preview_len] = '\0';

			LOG_ERR_MSG("Invalid command from IP %s (len=%llu): %s",
				    ip, decrypted_len, cmd_preview);

			continue;
		}

		get_client_ip(ip, sizeof(ip), &cliaddr);

		if (config.enable_rate_limit == 1) {
			if (is_rate_limited(ip)) {

				LOG_INFO_MSG("Rate limit exceeded for IP: %s",
					     ip);
				continue;
			}
		}

		LOG_CLIENT_REQUEST(ip);

		size_t ip_len = strlen(ip);
		if (ip_len > INET_ADDRSTRLEN - 1) {
			LOG_ERR_MSG("Invalid IP length: %zu", ip_len);
			continue;
		}

		secure_erase(ciphertext, sizeof(ciphertext));
		secure_erase(send_nonce, sizeof(send_nonce));
		secure_erase(sendbuf, sizeof(sendbuf));

		randombytes_buf(send_nonce, NONCE_LEN);

		unsigned long long ciphertext_len = 0;
		if (crypto_aead_chacha20poly1305_ietf_encrypt
		    (ciphertext, &ciphertext_len, (const unsigned char *)ip,
		     ip_len, NULL, 0, NULL, send_nonce, key) != 0) {

			continue;
		}

		if (ciphertext_len > MAX_MSG_LEN) {
			LOG_ERR_MSG("Ciphertext too long: %llu",
				    ciphertext_len);
			continue;
		}

		if (NONCE_LEN + ciphertext_len > sizeof(sendbuf)) {
			LOG_ERR_MSG("Output buffer overflow risk: total %llu",
				    NONCE_LEN + ciphertext_len);
			continue;
		}

		memcpy(sendbuf, send_nonce, NONCE_LEN);
		memcpy(sendbuf + NONCE_LEN, ciphertext, ciphertext_len);

		ssize_t sent_len =
		    send_with_retry(sockfd, sendbuf, NONCE_LEN + ciphertext_len,
				    0,
				    (struct sockaddr *)&cliaddr, len,
				    SEND_RETRY_LIMIT);

		if (sent_len < 0) {
			LOG_ERR_MSG("send_with_retry failed: %s",
				    strerror(errno));
		}

	}
	return 0;
}
