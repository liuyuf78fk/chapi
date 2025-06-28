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

#define SERVER_PORT 10000
#define KEY_HEX "a01af296150f544a0bb1033731ca243d03628e20bb8ce89a14631b14c6a3551a"
#define NONCE_LEN crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define KEY_LEN crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define MAC_LEN crypto_aead_chacha20poly1305_IETF_ABYTES
#define MAX_MSG_LEN 256

#define SERVER_BIND_ADDR   "0.0.0.0"
#define SERVER_PUBLIC_ADDR "127.0.0.1"

//#define ENABLE_RATE_LIMIT
#define RATE_LIMIT_WINDOW 6
#define RATE_LIMIT_COUNT 1
#define MAX_CLIENTS 1024

#define LOG_LEVEL 1		// 0=off, 1=errors only, 2=verbose
#define LOG_ERR_MSG(fmt, ...)  do { if (LOG_LEVEL >= 1) syslog(LOG_ERR, fmt, ##__VA_ARGS__); } while (0)
#define LOG_INFO_MSG(fmt, ...)   do { if (LOG_LEVEL >= 2) syslog(LOG_INFO, fmt, ##__VA_ARGS__); } while (0)

void hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len);
int is_valid_ipv4(const char *ip);

#endif
