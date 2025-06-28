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

typedef struct {
	char ip[INET_ADDRSTRLEN];
	time_t timestamps[RATE_LIMIT_COUNT];
	int index;
} client_entry;

static client_entry clients[MAX_CLIENTS];
static int client_count = 0;
static int sockfd = 0;

void cleanup()
{
	LOG_INFO_MSG("Server shutting down gracefully...");
	close(sockfd);
	closelog();
}

void handle_signal(int sig)
{
	exit(EXIT_SUCCESS);
}

void hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len)
{
	for (size_t i = 0; i < bin_len; i++) {
		sscanf(hex + 2 * i, "%2hhx", &bin[i]);
	}
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
	time_t now = time(NULL);

	for (int i = 0; i < client_count; i++) {
		if (strcmp(clients[i].ip, ip) == 0) {
			int count = 0;
			for (int j = 0; j < RATE_LIMIT_COUNT; j++) {
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

int main()
{
	atexit(cleanup);
	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);
	signal(SIGQUIT, handle_signal);
	openlog("chapi-server", LOG_PID, LOG_DAEMON);
	if (sodium_init() < 0) {
		LOG_ERR_MSG("libsodium init failed");
		return EXIT_FAILURE;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		LOG_ERR_MSG("socket creation failed");
		return EXIT_FAILURE;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(SERVER_BIND_ADDR);
	servaddr.sin_port = htons(SERVER_PORT);

	if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) <
	    0) {
		LOG_ERR_MSG("bind failed,port %d", SERVER_PORT);
		close(sockfd);
		return EXIT_FAILURE;
	}

	LOG_INFO_MSG("Server started on %s:%d\n", SERVER_BIND_ADDR,
		     SERVER_PORT);
	unsigned char key[KEY_LEN];
	hex_to_bin(KEY_HEX, key, KEY_LEN);

	unsigned char buffer[MAX_MSG_LEN];
	unsigned char nonce[NONCE_LEN];
	unsigned char decrypted[MAX_MSG_LEN];
	unsigned char ciphertext[MAX_MSG_LEN];
	unsigned char send_nonce[NONCE_LEN];
	unsigned char sendbuf[NONCE_LEN + MAX_MSG_LEN];

	while (1) {
		struct sockaddr_in cliaddr;
		socklen_t len = sizeof(cliaddr);

		ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
				     (struct sockaddr *)&cliaddr, &len);
		if (n < (ssize_t) NONCE_LEN) {

			continue;
		}

		memcpy(nonce, buffer, NONCE_LEN);

		unsigned long long decrypted_len = 0;
		if (crypto_aead_chacha20poly1305_ietf_decrypt
		    (decrypted, &decrypted_len, NULL, buffer + NONCE_LEN,
		     n - NONCE_LEN, NULL, 0, nonce, key) != 0) {
			continue;
		}

		if (decrypted_len < 5 || memcmp(decrypted, "GETIP", 5) != 0) {
			continue;
		}

		char ip[INET_ADDRSTRLEN];
		get_client_ip(ip, sizeof(ip), &cliaddr);

#ifdef ENABLE_RATE_LIMIT
		if (is_rate_limited(ip)) {

			LOG_INFO_MSG("Rate limit exceeded for IP: %s", ip);
			continue;
		}
#endif

		LOG_INFO_MSG("Client requested IP, returning: %s\n", ip);

		size_t ip_len = strlen(ip);
		if (ip_len > INET_ADDRSTRLEN - 1) {
			LOG_ERR_MSG("Invalid IP length: %zu", ip_len);
			continue;
		}

		memset(ciphertext, 0, sizeof(ciphertext));
		memset(send_nonce, 0, sizeof(send_nonce));
		memset(sendbuf, 0, sizeof(sendbuf));

		randombytes_buf(send_nonce, NONCE_LEN);

		unsigned long long ciphertext_len = 0;
		if (crypto_aead_chacha20poly1305_ietf_encrypt
		    (ciphertext, &ciphertext_len, (const unsigned char *)ip,
		     ip_len, NULL, 0, NULL, send_nonce, key) != 0) {

			continue;
		}

		memcpy(sendbuf, send_nonce, NONCE_LEN);
		if (NONCE_LEN + ciphertext_len > sizeof(sendbuf)) {

			continue;
		}
		memcpy(sendbuf + NONCE_LEN, ciphertext, ciphertext_len);

		ssize_t sent_len =
		    sendto(sockfd, sendbuf, NONCE_LEN + ciphertext_len, 0,
			   (struct sockaddr *)&cliaddr, len);
		if (sent_len < 0) {

			LOG_ERR_MSG("sendto failed");
		}
	}

}
