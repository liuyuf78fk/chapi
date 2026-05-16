# CHAPI

**CHAPI** is a lightweight encrypted UDP-based protocol for querying your public IP address using ChaCha20-Poly1305 authenticated encryption via libsodium.

## Why CHAPI?

Many applications and systems need to know their public IP address — yet most existing solutions rely on full HTTP/TLS stacks, often requiring TLS handshakes and HTTP headers just to return a small response such as `1.2.3.4`.

**CHAPI** started as a small experiment to see how lightweight a public IP query protocol could be without relying on HTTP or TLS.

It allows trusted clients sharing a pre-distributed key to query a server over encrypted UDP and receive a minimal encrypted response containing the detected public IP address.

---

## Features & Performance

- **ChaCha20-Poly1305 authenticated encryption** using libsodium  
- **Lightweight UDP server implementation** with minimal protocol overhead 
- **Single-threaded design** — suitable for embedded or minimal Linux environments  
- **Minimal packet overhead** — no HTTP headers or TLS negotiation
- **One-RTT response** — client gets encrypted IP reply in a single round-trip
- **Rate limiting support** — prevent abuse with per-IP throttling (optional via macro)  
- **Basic validation and malformed packet handling**  
- **Low memory usage** — chapi-server uses ~1.2 MB RAM on Linux (RSS)
- **Small codebase** intended for learning, experimentation, and lightweight deployments

### Benchmark Example

```
Total requests: 1000
Concurrency: 50 clients
Successes: 1000
Failures: 0
Total time: 1.5 seconds
Average time per request: 0.0015 seconds (1.5 ms)
```
Example benchmark results obtained on a low-end VPS under light test conditions.

Actual performance depends on:
- CPU architecture
- system tuning
- network conditions
- packet size
- concurrent traffic load


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

```bash
./chapi-genkey.sh
```

Output example:

```
Generating ChaCha20-Poly1305 key (256 bits)...
Key has been saved to /etc/chapi/chapi.key
```

> If you prefer static embedding, copy the printed key into the `KEY_HEX` macro in `common.h`.

---

### 4. Configuration Methods

Since **June 30, 2025**, the server supports configuration via external files.

By default, `make install` will create and install the following:

- `/etc/chapi/chapi.conf` — main INI configuration file
- `/etc/chapi/chapi.key` — encryption key used at runtime

---

#### Option 1: File-based Configuration (Recommended)

Example `/etc/chapi/chapi.conf`:

```ini
# ============================
# Network Settings
# ============================
bind_address = 0.0.0.0
port = 10000

# ============================
# Rate Limiting Settings
# ============================
enable_rate_limit = 0
rate_limit_window = 1
rate_limit_count = 1
max_clients = 1024

# ============================
# Logging Settings
# ============================
log_level = 2
```

If `/etc/chapi/chapi.key` exists, it will be used as the shared key.

---

#### Option 2: Static Macro Configuration (Legacy Compatible)

If you want to avoid external files and embed configuration directly, you can still modify `common.h` manually:

```c
#define DEFAULT_PORT 10000
#define KEY_HEX "your_generated_key_here"
#define DEFAULT_BIND_ADDR   "0.0.0.0"
#define DEFAULT_SERVER_ADDR "127.0.0.1"
#define ENABLE_RATE_LIMIT
#define RATE_LIMIT_WINDOW 1
#define RATE_LIMIT_COUNT 1
#define MAX_CLIENTS 1024
#define LOG_LEVEL_DEFAULT 2
```

To enforce macro-only behavior, delete the config and key files:

```bash
sudo rm /etc/chapi/chapi.conf
sudo rm /etc/chapi/chapi.key
```

> If config or key file exists, they override the macros.

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
- Install default configuration to `/etc/chapi/`
- Enable and start the `chapi-server.service`
- Set proper permissions on config and key

### For the client only:

```bash
sudo make install-client
```

This installs only the client binary

---

## Client Usage

```bash
chapi-client <server-address> [-p <port>]
```

- `<server-address>` can be an IP address or domain name
- `-p <port>` specifies a custom port

Example:

```bash
chapi-client example.com -p 60000
```

> If the client is run without any arguments, it uses the `DEFAULT_SERVER_ADDR` and `DEFAULT_PORT` values defined in `common.h`.

---

## Client Configuration

The client supports two modes of key handling:

---

### Option 1: File-based Key Loading (Default)

By default, the client will load the ChaCha20-Poly1305 key from:

```
/etc/chapi/chapi.key
```

This allows secure key distribution without recompilation.

---

### Option 2: Static Macro Key (Embedded in Source)

If you prefer to embed the key statically in the source code:

1. Open `common.h`  
2. Set the `KEY_HEX` macro manually with your key string：

```c
#define KEY_HEX "your_generated_key_here"
```

Then, delete the key file to enforce macro mode:

```bash
sudo rm /etc/chapi/chapi.key
```

> If the key file exists, the client will **always** load from the file first

---

## Summary: Configuration and Key Priority

| Component | File                             | Description                          | Priority |
|-----------|----------------------------------|--------------------------------------|----------|
| Server    | `/etc/chapi/chapi.conf`          | Server INI config file               | High     |
| Server    | `/etc/chapi/chapi.key`           | Key file for encryption              | High     |
| Client    | `/etc/chapi/chapi.key`           | Key file for encryption              | High     |
| All       | Macros in `common.h`             | Fallback if above files are missing  | Fallback |

---

## Known Limitations

**Disclaimer: Scope & Deployment**  
CHAPI is designed as a minimalist tool for personal use, homelabs, and trusted low-overhead environments. It is **NOT** currently hardened against sophisticated UDP adversarial attacks (e.g., distributed UDP floods or replay attacks) on the open internet.

If you are deploying this on a public-facing server, please be aware of the following known architectural limitations:

- **Fixed-Size Rate Limiter Table:** The current rate-limiting implementation uses a fixed-size array (`MAX_CLIENTS`). Once the table is full, new IP addresses are no longer tracked by the limiter.
- **Linear Search Overhead:** The rate limiter checks incoming IPs using an `O(N)` linear search. In the event of a severe UDP flood using randomized spoofed source IPs, this may cause high CPU utilization on a single thread.
- **Basic Anti-Replay:** The server currently only caches the *most recent* Nonce to prevent immediate consecutive replays. It does not employ a sliding window or payload timestamps, meaning it could theoretically be bypassed by alternating replayed packets.
- **Shared Key Architecture (PSK):** All clients and the server share the same symmetric key. If one client node is compromised, the attacker can spoof requests or decrypt captured traffic within that specific deployment.

**Mitigation Recommendations:**
If you must expose CHAPI to the public internet, it is recommended to use iptables or nftables to restrict which hosts can access the service.

- Ensure your key file always has strict permissions:

```bash
sudo chmod 600 /etc/chapi/chapi.key
```

---

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).  
See the [LICENSE](LICENSE) file for full details.

### Third-party components

This project includes the [inih](https://github.com/benhoyt/inih) library by Ben Hoyt,  
which is licensed under the New BSD License. See [inih-LICENSE.txt](./inih-LICENSE.txt) for details.

This project also links to the [libsodium](https://github.com/jedisct1/libsodium) cryptographic library,
which is licensed under the [ISC License](https://github.com/jedisct1/libsodium/blob/master/LICENSE).

---
