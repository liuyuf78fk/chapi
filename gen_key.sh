#!/bin/bash

echo "Generating ChaCha20-Poly1305 shared key (256-bit)..."
key=$(openssl rand -hex 32)

echo ""
echo "Please copy the following content into the KEY_HEX macro definition in common.h:"
echo ""
echo "#define KEY_HEX \"$key\""
echo ""

