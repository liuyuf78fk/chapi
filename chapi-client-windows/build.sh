#!/bin/sh

gcc -o chapi-client.exe chapi-client.c common.c -static -lsodium -lws2_32