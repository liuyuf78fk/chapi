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
#include <netdb.h>
#include <getopt.h>

#include "common.h"

int resolve_server_address(const char *host, int port,
			   struct sockaddr_in *out_addr)
{
	if (!host || !out_addr) {
		fprintf(stderr, "resolve_server_address: invalid argument\n");
		return -1;
	}

	struct addrinfo hints;
	struct addrinfo *result = NULL;
	char port_str[6];

	snprintf(port_str, sizeof(port_str), "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;

	int ret = getaddrinfo(host, port_str, &hints, &result);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo failed for host '%s': %s\n", host,
			gai_strerror(ret));
		return -2;
	}

	if (result->ai_addrlen != sizeof(struct sockaddr_in)) {
		fprintf(stderr, "Unexpected sockaddr size\n");
		freeaddrinfo(result);
		return -3;
	}

	memcpy(out_addr, result->ai_addr, sizeof(struct sockaddr_in));

	freeaddrinfo(result);
	return 0;
}

void print_usage(const char *progname)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] [server_address]\n"
		"Options:\n"
		"  -v, --version          Show version and exit\n"
		"  -p, --port PORT        Specify server port (1-65535)\n"
		"  -6, --ipv6             Use IPv6 (currently unsupported)\n"
		"  -h, --help             Show this help message\n", progname);
}

int is_number(const char *s)
{
	if (!s || !*s)
		return 0;
	while (*s) {
		if (!isdigit((unsigned char)*s))
			return 0;
		s++;
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int sockfd = -1;
	unsigned char *sendbuf = NULL;
	int exit_code = -1;
	ssize_t sent = -1;
	ssize_t bytes_received = -1;

	char server_addr_str[256] = DEFAULT_SERVER_ADDR;

	int server_port = DEFAULT_PORT;
	int ipv6_flag = 0;

	static struct option long_options[] = {
		{"version", no_argument, 0, 'v'},
		{"port", required_argument, 0, 'p'},
		{"ipv6", no_argument, 0, '6'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	int opt, option_index = 0;
	while ((opt =
		getopt_long(argc, argv, "vp:6h", long_options,
			    &option_index)) != -1) {
		switch (opt) {
		case 'v':
			fprintf(stdout, "chapi-client %s\n", VERSION);
			fprintf(stdout, "Build: %s %s\n", __DATE__, __TIME__);
			return 0;
		case 'p':
			if (!is_number(optarg)) {
				fprintf(stderr, "invalid port number '%s'\n",
					optarg);
				goto err;
			}
			server_port = atoi(optarg);
			if (server_port < 1 || server_port > 65535) {
				fprintf(stderr,
					"port must be between 1 and 65535\n");
				goto err;
			}
			break;
		case '6':
			ipv6_flag = 1;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		case '?':
		default:
			print_usage(argv[0]);
			goto err;
		}
	}

	if (optind < argc) {
		strncpy(server_addr_str, argv[optind],
			sizeof(server_addr_str) - 1);
		server_addr_str[sizeof(server_addr_str) - 1] = '\0';
	}

	if (ipv6_flag) {
		fprintf(stderr, "IPv6 is not supported yet.\n");
		goto err;
	}

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
	if (load_key(key) != 0) {
		fprintf(stderr,
			"Fatal: failed to load valid key from file or macro.\n");
		goto err;
	}

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		goto err;
	}

	struct sockaddr_in server_sockaddr;
	int status = resolve_server_address(server_addr_str, server_port,
					    &server_sockaddr);
	if (status != 0) {
		fprintf(stderr, "Failed to resolve server address\n");
		goto err;
	}

	unsigned char nonce[NONCE_LEN];
	randombytes_buf(nonce, NONCE_LEN);

	const char *msg = CMD_GETIP;
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
		      (const struct sockaddr *)&server_sockaddr,
		      sizeof(server_sockaddr));

	if (sent < 0) {
		perror("sendto failed");
		goto err;
	}

	free(sendbuf);
	sendbuf = NULL;

	struct timeval timeout = { SOCKET_TIMEOUT_SEC, SOCKET_TIMEOUT_USEC };
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
	exit_code = 0;

 err:
	if (sendbuf)
		free(sendbuf);
	if (sockfd >= 0)
		close(sockfd);
	return exit_code;
}
