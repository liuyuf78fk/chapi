#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <ctype.h>
#include <getopt.h>
#include "common.h"

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_MAX_RETRIES 2

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
		fprintf(stderr, "getaddrinfo failed for host '%s': %d\n", host,
			ret);
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
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
		return -1;
	}

	SOCKET sockfd = INVALID_SOCKET;
	unsigned char *sendbuf = NULL;
	int exit_code = -1;
	int sent = -1;
	int bytes_received = -1;

	char server_addr_str[256] = DEFAULT_SERVER_ADDR;

	int server_port = DEFAULT_PORT;
	int ipv6_flag = 0;
	int retry_count = 0;
	const int max_retries = DEFAULT_MAX_RETRIES;

	static struct option long_options[] = {
		{"version", no_argument, 0, 'v'},
		{"port", required_argument, 0, 'p'},
		{"ipv6", no_argument, 0, '6'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	int opt, option_index = 0;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
			case 'v':
				fprintf(stdout, "chapi-client %s\n", VERSION);
				fprintf(stdout, "Build: %s %s\n", __DATE__,
					__TIME__);
				WSACleanup();
				return 0;
			case 'p':
				if (i + 1 >= argc) {
					fprintf(stderr,
						"Option -p requires an argument\n");
					goto err;
				}
				if (!is_number(argv[i + 1])) {
					fprintf(stderr,
						"invalid port number '%s'\n",
						argv[i + 1]);
					goto err;
				}
				server_port = atoi(argv[i + 1]);
				i++;
				break;
			case '6':
				ipv6_flag = 1;
				break;
			case 'h':
				print_usage(argv[0]);
				WSACleanup();
				return 0;
			default:
				fprintf(stderr, "Unknown option: %s\n",
					argv[i]);
				print_usage(argv[0]);
				goto err;
			}
		} else {

			strncpy(server_addr_str, argv[i],
				sizeof(server_addr_str) - 1);
			server_addr_str[sizeof(server_addr_str) - 1] = '\0';
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
	if (load_key(key, NULL) != 0) {
		fprintf(stderr,
			"Fatal: failed to load valid key from file or macro.\n");
		goto err;
	}

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
		fprintf(stderr, "socket creation failed: %d\n",
			WSAGetLastError());
		goto err;
	}

	struct sockaddr_in server_sockaddr;
	int status = resolve_server_address(server_addr_str, server_port,
					    &server_sockaddr);
	if (status != 0) {
		fprintf(stderr, "Failed to resolve server address\n");
		goto err;
	}

send_again:

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
		fprintf(stderr, "malloc failed\n");
		goto err;
	}

	memcpy(sendbuf, nonce, NONCE_LEN);
	memcpy(sendbuf + NONCE_LEN, ciphertext, clen);

	sent = sendto(sockfd, (const char *)sendbuf, (int)(NONCE_LEN + clen), 0,
		      (const struct sockaddr *)&server_sockaddr,
		      sizeof(server_sockaddr));

	if (sent < 0) {
		fprintf(stderr, "sendto failed: %d\n", WSAGetLastError());
		goto err;
	}

	free(sendbuf);
	sendbuf = NULL;

	DWORD timeout = SOCKET_TIMEOUT_SEC * 1000 + SOCKET_TIMEOUT_USEC / 1000;
	if (setsockopt
	    (sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
	     sizeof(timeout)) == SOCKET_ERROR) {
		fprintf(stderr, "setsockopt failed: %d\n", WSAGetLastError());
		goto err;
	}

	unsigned char recvbuf[MAX_MSG_LEN];

	bytes_received =
	    recvfrom(sockfd, (char *)recvbuf, sizeof(recvbuf), 0, NULL, NULL);

	if (bytes_received < 0) {
		int err = WSAGetLastError();
		if (err == WSAETIMEDOUT) {
			fprintf(stderr, "The server is unresponsive\n");
			if (retry_count < max_retries) {
				fprintf(stderr, "retrying %d/%d ...\n",
					retry_count + 1, max_retries);
				retry_count++;
				if (sendbuf) free(sendbuf);
				goto send_again;
			}
		} else {
			fprintf(stderr, "recvfrom error: %d\n", err);
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
	if (sockfd != INVALID_SOCKET)
		closesocket(sockfd);
	WSACleanup();
	return exit_code;
}
