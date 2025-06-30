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

#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pwd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <sodium.h>

#define VERSION "v1.0.1"

#define KEY_FILE_PATH "/etc/chapi/chapi.key"
#define CONF_FILE_PATH "/etc/chapi/chapi.conf"

#define DEFAULT_PORT 10000

#define DEFAULT_BIND_ADDR   "0.0.0.0"
#define DEFAULT_SERVER_ADDR "127.0.0.1"

//#define ENABLE_RATE_LIMIT
#define RATE_LIMIT_WINDOW 1
#define RATE_LIMIT_COUNT 1
#define MAX_CLIENTS 1024

#define LOG_LEVEL_DEFAULT 2	// 0=off, 1=errors only, 2=verbose

#define KEY_HEX "a01af296150f544a0bb1033731ca243d03628e20bb8ce89a14631b14c6a3551a"

#define NONCE_LEN crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define KEY_LEN crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define MAC_LEN crypto_aead_chacha20poly1305_IETF_ABYTES
#define MAX_MSG_LEN 256

#define SEND_RETRY_LIMIT 3
#define CMD_GETIP       "GETIP"
#define CMD_GETIP_LEN   5

#define SOCKET_REUSEADDR_ON  1
#define SOCKET_REUSEADDR_OFF 0

#define SOCKET_TIMEOUT_SEC 1
#define SOCKET_TIMEOUT_USEC 0

#define KEY_SOURCE_FILE 1
#define KEY_SOURCE_MACRO 2


int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len);
int is_valid_ipv4(const char *ip);
int send_with_retry(int sock, const void *buf, size_t len, int flags,
		    const struct sockaddr *dest_addr, socklen_t addrlen,
		    int max_retries);
int load_key(unsigned char *key_out, int *source);

#endif
