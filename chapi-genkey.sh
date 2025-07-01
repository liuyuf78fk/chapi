#!/usr/bin/env bash
#
# CHAPI - ChaCha20-based Host Address Protocol over UDP
#
# Description:
#   Generates a secure ChaCha20-Poly1305 key (256-bit) for CHAPI encryption.
#   The key is saved to /etc/chapi/chapi.key with restricted permissions.
#   If the keyfile exists, prompts for overwrite confirmation.
#
# Usage:
#   ./chapi-genkey.sh
#
# Dependencies:
#   - openssl (for cryptographically secure key generation)
#
# Copyright (C) 2025 Liu Yu <f78fk@live.com>
#
# This file is part of CHAPI.
#
# CHAPI is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# CHAPI is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with CHAPI. If not, see <https://www.gnu.org/licenses/>.

set -euo pipefail

PROG_NAME=$(basename "$0")

err() {
  # usage: err <exit_code> <message>
  local exit_code=$1; shift
  printf "%s: error: %s\n" "$PROG_NAME" "$*" >&2
  exit "$exit_code"
}

# Check for openssl
if ! command -v openssl >/dev/null 2>&1; then
  err 1 "openssl is not installed.
Hint: install it with
  sudo apt-get install openssl    # Debian/Ubuntu
  sudo yum install openssl        # CentOS/RHEL
  brew install openssl            # macOS"
fi

# Generate key
printf "Generating ChaCha20-Poly1305 key (256 bits)...\n\n"
key=$(openssl rand -hex 32) || err 2 "failed to generate random key"

# Prepare directory and save key
chapi_dir="/etc/chapi"
chapi_keyfile="$chapi_dir/chapi.key"

mkdir -p "$chapi_dir"                     || err 3 "cannot create directory $chapi_dir"

# If keyfile exists, prompt for overwrite
if [[ -e "$chapi_keyfile" ]]; then
  printf "Warning: %s already exists.\n" "$chapi_keyfile"
  read -r -p "Overwrite it? [y/N] " answer
  case "$answer" in
    [Yy]|[Yy][Ee][Ss])
      : # proceed to overwrite
      ;;
    *)
      # user chose not to overwrite: just display the key and exit
      printf "\nYour new key is:\n\n  %s\n\n" "$key"
      exit 0
      ;;
  esac
fi

printf "%s" "$key" > "$chapi_keyfile"      || err 4 "cannot write key to $chapi_keyfile"

if id -u chapi >/dev/null 2>&1; then
    chown root:chapi "$chapi_keyfile" || err 5 "cannot set ownership to root:chapi on $chapi_keyfile"
    chmod 640 "$chapi_keyfile" || err 6 "cannot set permissions (640) on $chapi_keyfile"
else
    echo "Warning: chapi user not found, setting fallback permissions."
    chmod 755 /etc/chapi || err 5 "cannot set permissions on /etc/chapi"
    chmod 644 "$chapi_keyfile" || err 6 "cannot set permissions (644) on $chapi_keyfile"
fi

# Output results
printf "Success! Your new key is:\n\n  %s\n\n" "$key"

printf "Key has been saved to %s\n\n" "$chapi_keyfile"

printf "You have two ways to use it:\n\n"

printf "  1. Hardcode in source (static)\n"
printf "     Add to common.h:\n\n"
printf "       #define KEY_HEX \"%s\"\n\n" "$key"

printf "  2. Load from file (dynamic)\n"
printf "     chapi will automatically read the key from %s at startup.\n\n" "$chapi_keyfile"

printf "To deploy the same key to another machine, run:\n\n"
printf "  mkdir -p /etc/chapi && printf '%s' > /etc/chapi/chapi.key && chmod 755 /etc/chapi && chmod 644 /etc/chapi/chapi.key\n\n" "$key"
exit 0

