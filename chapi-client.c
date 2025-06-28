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
#include <ctype.h>
#include <errno.h>

#include "common.h"

void hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len)
{
	size_t i;
	unsigned int byte;
	for (i = 0; i < bin_len; i++) {
		sscanf(hex + 2 * i, "%2x", &byte);
		bin[i] = (unsigned char)byte;
	}
}

int is_valid_ipv4(const char *ip)
{
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
	return result == 1 ? 1 : 0;
}

int main(void)
{
	int sockfd = -1;
	unsigned char *sendbuf = NULL;
	int ret = -1;
	ssize_t sent = -1;
	ssize_t bytes_received = -1;

	if (sodium_init() < 0) {
		fprintf(stderr, "libsodium init failed\n");
		goto err;
	}

	if (strlen(KEY_HEX) != KEY_LEN * 2) {
		fprintf(stderr,
			"KEY_HEX length is invalid, expected %d hex digits.\n",
			KEY_LEN * 2);
		goto err;
	}

	unsigned char key[KEY_LEN];
	hex_to_bin(KEY_HEX, key, KEY_LEN);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		goto err;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(SERVER_PORT);
	if (inet_pton(AF_INET, SERVER_PUBLIC_ADDR, &servaddr.sin_addr) <= 0) {
		perror("inet_pton failed");
		goto err;
	}

	unsigned char nonce[NONCE_LEN];
	randombytes_buf(nonce, NONCE_LEN);

	const char *msg = "GETIP";
	unsigned char ciphertext[MAX_MSG_LEN];
	unsigned long long clen;

	if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &clen,
						      (const unsigned char *)
						      msg, strlen(msg), NULL, 0,
						      NULL, nonce, key) != 0) {
		fprintf(stderr, "Encryption failed\n");
		goto err;
	}

	sendbuf = malloc(NONCE_LEN + clen);

	if (sendbuf == NULL) {
		perror("malloc failed");
		goto err;
	}

	memcpy(sendbuf, nonce, NONCE_LEN);
	memcpy(sendbuf + NONCE_LEN, ciphertext, clen);

	sent = sendto(sockfd, sendbuf, NONCE_LEN + clen, 0,
		      (const struct sockaddr *)&servaddr, sizeof(servaddr));

	if (sent < 0) {
		perror("sendto failed");
		goto err;
	}

	free(sendbuf);
	sendbuf = NULL;

	struct timeval timeout = { 2, 0 };
	if (setsockopt
	    (sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		perror("setsockopt failed");
		goto err;
	}

	unsigned char recvbuf[MAX_MSG_LEN];

	bytes_received =
	    recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, NULL, NULL);

	if (bytes_received < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			fprintf(stderr, "The server is unresponsive\n");
		} else {
			perror("recvfrom error");
		}
		goto err;
	}

	if (bytes_received < NONCE_LEN) {
		fprintf(stderr,
			"Received packet is too short, invalid format.\n");
		goto err;
	}

	memcpy(nonce, recvbuf, NONCE_LEN);
	unsigned char decrypted[MAX_MSG_LEN];
	unsigned long long mlen;

	if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &mlen, NULL,
						      recvbuf + NONCE_LEN,
						      bytes_received -
						      NONCE_LEN, NULL, 0, nonce,
						      key) != 0) {
		fprintf(stderr, "Decryption failed\n");
		goto err;
	}

	decrypted[mlen] = '\0';	// safe: mlen always < MAX_MSG_LEN due to AEAD max length
	if (!is_valid_ipv4((char *)decrypted)) {
		fprintf(stderr, "Invalid IP: %s\n", decrypted);
		goto err;
	}

	if (strcmp((char *)decrypted, "0.0.0.0") == 0) {
		fprintf(stderr,
			"Server returned 0.0.0.0 - failed to determine client IP address.\n");
		goto err;
	}

	printf("%s\n", decrypted);
	ret = 0;

 err:
	if (sendbuf)
		free(sendbuf);
	if (sockfd >= 0)
		close(sockfd);
	return ret;
}
