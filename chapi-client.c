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
	for (size_t i = 0; i < bin_len; i++) {
		sscanf(hex + 2 * i, "%2hhx", &bin[i]);
	}
}

int is_valid_ipv4(const char *ip)
{
	struct sockaddr_in sa;
	return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

int main()
{
	if (sodium_init() < 0) {
		fprintf(stderr, "libsodium init failed\n");
		return 1;
	}

	int sockfd;
	struct sockaddr_in servaddr;

	unsigned char key[KEY_LEN];
	hex_to_bin(KEY_HEX, key, KEY_LEN);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(SERVER_PORT);
	inet_pton(AF_INET, SERVER_PUBLIC_ADDR, &servaddr.sin_addr);

	unsigned char nonce[NONCE_LEN];
	randombytes_buf(nonce, NONCE_LEN);

	const char *msg = "GETIP";
	unsigned char ciphertext[MAX_MSG_LEN];
	unsigned long long clen;

	crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &clen,
						  (const unsigned char *)msg,
						  strlen(msg), NULL, 0, NULL,
						  nonce, key);

	unsigned char sendbuf[NONCE_LEN + clen];
	memcpy(sendbuf, nonce, NONCE_LEN);
	memcpy(sendbuf + NONCE_LEN, ciphertext, clen);

	sendto(sockfd, sendbuf, sizeof(sendbuf), 0,
	       (const struct sockaddr *)&servaddr, sizeof(servaddr));

	struct timeval timeout = { 2, 0 };
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	unsigned char recvbuf[MAX_MSG_LEN];
	ssize_t n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, NULL, NULL);

	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			fprintf(stderr, "The server is unresponsive\n");
		} else {
			perror("recvfrom error\n");
		}
		return 1;
	}

	if (n < NONCE_LEN) {
		fprintf(stderr,
			"Received packet is too short, invalid format.\n");
		return 1;
	}

	memcpy(nonce, recvbuf, NONCE_LEN);
	unsigned char decrypted[MAX_MSG_LEN];
	unsigned long long mlen;

	if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &mlen, NULL,
						      recvbuf + NONCE_LEN,
						      n - NONCE_LEN, NULL, 0,
						      nonce, key) != 0) {
		fprintf(stderr, "Decryption failed\n");
		return 1;
	}

	decrypted[mlen] = '\0';
	if (is_valid_ipv4((char *)decrypted)) {
		printf("%s\n", decrypted);
	} else {
		fprintf(stderr, "Invalid IP: %s\n", decrypted);
		return 1;
	}

	return 0;
}
