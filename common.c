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
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <unistd.h>
#include <syslog.h>

#include "common.h"

int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len)
{
	size_t i;
	unsigned int byte;
	for (i = 0; i < bin_len; i++) {
		sscanf(hex + 2 * i, "%2x", &byte);
		bin[i] = (unsigned char)byte;
	}
	return 0;
}

int is_valid_ipv4(const char *ip)
{
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
	return result == 1 ? 1 : 0;
}

int send_with_retry(int sock, const void *buf, size_t len, int flags,
		    const struct sockaddr *dest_addr, socklen_t addrlen,
		    int max_retries)
{
	if (sock < 0 || !buf || len == 0 || !dest_addr || max_retries <= 0) {
		errno = EINVAL;
		return -1;
	}

	int attempt = 0;
	ssize_t sent_len = 0;

	while (attempt < max_retries) {
		sent_len = sendto(sock, buf, len, flags, dest_addr, addrlen);

		if (sent_len >= 0) {
			return sent_len;
		}

		switch (errno) {
#if EAGAIN == EWOULDBLOCK
		case EAGAIN:
#else
		case EAGAIN:
		case EWOULDBLOCK:
#endif
		case EINTR:
			usleep(1000 * (1 << attempt));
			LOG_ERR_MSG("sendto retryable error (attempt %d): %s",
				    attempt + 1, strerror(errno));
			break;
		default:
			LOG_ERR_MSG("sendto fatal error: %s", strerror(errno));
			return -1;
		}
		attempt++;
	}
	LOG_ERR_MSG("sendto failed after %d attempts", max_retries);
	return -1;
}

int load_key(unsigned char *key_out)
{
    char path[512];
    const char *home = getenv("HOME");
    FILE *fp = NULL;
    char hex[KEY_LEN * 2 + 2] = { 0 };

    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw)
            home = pw->pw_dir;
    }

    if (!home)
        goto fail;

    snprintf(path, sizeof(path), "%s/%s", home, KEY_FILE_PATH);

    fp = fopen(path, "r");
    if (!fp)
        goto fail;

    if (!fgets(hex, sizeof(hex), fp))
        goto fail;

    size_t len = strlen(hex);
    while (len > 0 && (hex[len - 1] == '\n' || hex[len - 1] == '\r'))
        hex[--len] = '\0';

    if (len != KEY_LEN * 2)
        goto fail;

    for (size_t i = 0; i < len; ++i) {
        if (!isxdigit((unsigned char)hex[i]))
            goto fail;
    }

    if (hex_to_bin(hex, key_out, KEY_LEN) != 0)
        goto fail;

    fclose(fp);
    return 0;

fail:
    if (fp)
        fclose(fp);
    return hex_to_bin(KEY_HEX, key_out, KEY_LEN);
}
