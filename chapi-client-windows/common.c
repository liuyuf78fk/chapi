#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

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

int send_with_retry(SOCKET sock, const void *buf, size_t len, int flags,
            const struct sockaddr *dest_addr, socklen_t addrlen,
            int max_retries)
{
    if (sock == INVALID_SOCKET || !buf || len == 0 || !dest_addr || max_retries <= 0) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }

    int attempt = 0;
    int sent_len = 0;

    while (attempt < max_retries) {
        sent_len = sendto(sock, (const char*)buf, (int)len, flags, dest_addr, addrlen);

        if (sent_len >= 0) {
            return sent_len;
        }

        int err = WSAGetLastError();
        switch (err) {
        case WSAEWOULDBLOCK:
        case WSAEINTR:
            Sleep(1000 * (1 << attempt));
            fprintf(stderr, "sendto retryable error (attempt %d): %d\n",
                    attempt + 1, err);
            break;
        default:
            fprintf(stderr, "sendto fatal error: %d\n", err);
            return -1;
        }
        attempt++;
    }
    fprintf(stderr, "sendto failed after %d attempts\n", max_retries);
    return -1;
}

int load_key(unsigned char *key_out, int *source)
{
    const char *path = KEY_FILE_PATH;
    FILE *fp = NULL;
    char hex[KEY_LEN * 2 + 2] = { 0 };
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
    if (source)
        *source = KEY_SOURCE_FILE;
    return 0;

fail:
    if (fp)
        fclose(fp);
    int ret = hex_to_bin(KEY_HEX, key_out, KEY_LEN);
    if (source)
        *source = KEY_SOURCE_MACRO;
    return ret;
}