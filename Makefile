CC = gcc
CFLAGS = -O2 -s -Wall
LDFLAGS = -lsodium

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

SERVER_SRC = chapi-server.c
CLIENT_SRC = chapi-client.c

SERVER_BIN = chapi-server
CLIENT_BIN = chapi-client

SERVICE_FILE = systemd/chapi-server.service
SERVICE_INSTALL_PATH = /etc/systemd/system/chapi-server.service

.PHONY: all clean install install-binaries install-service enable-service

all: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_SRC) common.h
	$(CC) $(CFLAGS) -o $@ $(SERVER_SRC) $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_SRC) common.h
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SRC) $(LDFLAGS)

install: all create-user install-binaries install-service enable-service

install-client: 
	install -m 755 $(CLIENT_BIN) $(BINDIR)/

create-user:
	@if ! id -u chapi >/dev/null 2>&1; then \
		echo "Creating dedicated user chapi..."; \
		useradd --system --no-create-home --shell /usr/sbin/nologin chapi; \
	else \
		echo "User chapi already exists, skipping creation."; \
	fi
install-binaries:
	install -d $(BINDIR)
	install -m 755 $(SERVER_BIN) $(BINDIR)/

install-service:
	install -d /etc/systemd/system
	install -m 644 $(SERVICE_FILE) $(SERVICE_INSTALL_PATH)

enable-service:
	systemctl daemon-reload
	systemctl enable chapi-server.service
	systemctl restart chapi-server.service

clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN)

