#!/usr/bin/env bash
#
# chapi-genkey — generate a ChaCha20-Poly1305 256-bit shared key

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
chapi_dir="$HOME/.chapi"
chapi_keyfile="$chapi_dir/.chapi.key"

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
chmod 600 "$chapi_keyfile"                || err 5 "cannot set permissions on $chapi_keyfile"

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
printf "  mkdir -p ~/.chapi && printf '%s' > ~/.chapi/.chapi.key && chmod 600 ~/.chapi/.chapi.key\n\n" "$key"
exit 0

