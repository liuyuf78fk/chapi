# CHAPI

**CHAPI** (ChaCha20-based Host Address Protocol over UDP) is a minimalist, secure, and efficient protocol to query your public IP address over encrypted UDP using ChaCha20-Poly1305

## Why CHAPI?

Many applications and systems need to know their public IP address — yet most solutions rely on full HTTPS stacks (such as nginx combined with curl), requiring heavy TLS handshakes and HTTP headers just to return a tiny string like 1.2.3.4. (Frustrated by this unnecessary overhead, I developed CHAPI.)

**CHAPI** is a lightweight alternative designed for self-hosters, embedded devices, and low-overhead environments. It lets trusted clients query the server over encrypted UDP, returning only what’s needed — your IP

---

## 🚀 Features & Performance

- **ChaCha20-Poly1305 encryption** — secure by default, without OpenSSL or TLS bloat  
- **High-performance UDP server** — extremely lightweight and fast  
- **Single-threaded design** — suitable for embedded or minimal Linux environments  
- **Minimal overhead** — no TLS handshakes, no HTTP headers, just encrypted IP delivery
- **One-RTT response** — client gets encrypted IP reply in a single round-trip
- **Rate limiting support** — prevent abuse with per-IP throttling (optional via macro)  
- **Resilient to attacks** — encrypted communication, strict format validation  
- **Low memory usage** — chapi-server uses ~1.2 MB RAM on Linux (RSS)
- **Proven fast in benchmarks** — with 50 concurrent clients, a total of 1000 encrypted requests took approximately 1.5 seconds

### ⚙️ Benchmark Example

```
Total requests: 1000
Concurrency: 50 clients
Successes: 1000
Failures: 0
Total time: 1.5 seconds
Average time per request: 0.0015 seconds (1.5 ms)
```
This demonstrates that even with a single-threaded design on a single-core VPS, CHAPI can achieve this level of performance
This makes it more efficient than HTTP+TLS solutions, especially in bandwidth-sensitive or embedded environments


---

## Requirements

- GCC compiler (tested with gcc 13.3.0)
- libsodium library installed (for ChaCha20-Poly1305 encryption)

---

## Installation

### 1. Install dependencies (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y build-essential libsodium-dev
```

### 2. Clone the repository and enter directory

```bash
git clone https://github.com/liuyuf78fk/chapi.git
cd chapi
```

### 3. Generate a shared ChaCha20-Poly1305 key

```
./gen_key.sh
```

You will see output like:

```
Generating ChaCha20-Poly1305 shared key (256-bit)...

Please copy the following content into the KEY_HEX macro definition in common.h:

#define KEY_HEX "5b766b1ea5e65ca55d33feac34c5f35da501b019ff85e0ab1be558c11a8e75d3"
```

Open `common.h` and replace the `KEY_HEX` macro with the generated value

### 4. Configure settings in `common.h`

```c
#define SERVER_PORT 10000
#define KEY_HEX "5b766b1ea5e65ca55d33feac34c5f35da501b019ff85e0ab1be558c11a8e75d3"
#define NONCE_LEN crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define KEY_LEN crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define MAC_LEN crypto_aead_chacha20poly1305_IETF_ABYTES
#define MAX_MSG_LEN 256

#define SERVER_BIND_ADDR   "0.0.0.0"
#define SERVER_PUBLIC_ADDR "127.0.0.1"

//#define ENABLE_RATE_LIMIT
#define RATE_LIMIT_WINDOW 6    // in seconds
#define RATE_LIMIT_COUNT 1
#define MAX_CLIENTS 1024

#define LOG_LEVEL 1            // 0=off, 1=errors only, 2=verbose
```

---

## Build

```bash
make
```

---

## Installation

### For the server:

```bash
sudo make install
```

This will:

- Create a dedicated system user `chapi` if it does not exist
- Install binaries to `/usr/local/bin/`
- Install and enable the systemd service `chapi-server.service`
- Start the service immediately

### For the client only:

```bash
sudo make install-client
```

This installs only the client binary

---

## Running and Logs

The server runs as a systemd service named `chapi-server.service`

Check server logs with:

```bash
sudo journalctl -u chapi-server.service -f
```

---

## Usage

Run the client (example):

```bash
chapi-client
```

It will query the server and print your public IP or an error

---

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See the LICENSE file for details

---

