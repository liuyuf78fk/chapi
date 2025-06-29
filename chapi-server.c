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
	time_t timestamps[RATE_LIMIT_COUNT];
	int index;
} client_entry;

volatile sig_atomic_t shutdown_requested = 0;
static unsigned char key[KEY_LEN];
static client_entry clients[MAX_CLIENTS];
static int client_count = 0;
static int sockfd = 0;

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
	closelog();
	secure_erase(key, KEY_LEN);
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
	time_t now = get_monotonic_time();
	int i, j;
	for (i = 0; i < client_count; i++) {
		if (strcmp(clients[i].ip, ip) == 0) {
			int count = 0;
			for (j = 0; j < RATE_LIMIT_COUNT; j++) {
				if (now - clients[i].timestamps[j] <
				    RATE_LIMIT_WINDOW) {
					count++;
				}
			}
			if (count >= RATE_LIMIT_COUNT) {
				return 1;
			}
			clients[i].timestamps[clients[i].index] = now;
			clients[i].index++;
			if (clients[i].index >= RATE_LIMIT_COUNT) {
				clients[i].index = 0;
			}
			return 0;
		}
	}

	if (client_count < MAX_CLIENTS) {
		strncpy(clients[client_count].ip, ip, INET_ADDRSTRLEN);
		memset(clients[client_count].timestamps, 0,
		       sizeof(clients[client_count].timestamps));
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
	LOG_INFO_MSG("Starting chapi-server v1.0 (Build: %s %s)", __DATE__,
		     __TIME__);
	setup_signal_handlers();
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
	servaddr.sin_addr.s_addr = inet_addr(SERVER_BIND_ADDR);
	servaddr.sin_port = htons(SERVER_PORT);

	int opt = SOCKET_REUSEADDR_ON;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		LOG_ERR_MSG("setsockopt failed: %s", strerror(errno));
		return -1;
	}

	if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) <
	    0) {
		LOG_ERR_MSG("bind failed,port %d", SERVER_PORT);
		close(sockfd);
		return -1;
	}

	LOG_INFO_MSG("Server started on %s:%d\n", SERVER_BIND_ADDR,
		     SERVER_PORT);

	hex_to_bin(KEY_HEX, key, KEY_LEN);

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

#ifdef ENABLE_RATE_LIMIT
		if (is_rate_limited(ip)) {

			LOG_INFO_MSG("Rate limit exceeded for IP: %s", ip);
			continue;
		}
#endif

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
