CC = gcc
CFLAGS  = -I../../include -g -Wall
LDFLAGS = -L../..
LDLIBS  = -lcrypto

# Preprocessor flags for client and server builds:
CLIENT_FLAGS = -DCLIENT_BUILD
SERVER_FLAGS = -DSERVER_BUILD

# Dependency groups to restrict headers for each module.
COMMON_DEPS      = rsa_common.h net_utils.h utils_common.h
CLIENT_MAIN_DEPS = rsa_common.h net_utils.h utils_common.h
SERVER_MAIN_DEPS = rsa_common.h net_utils.h utils_common.h

# Object files for each target.
CLIENT_OBJS = client_main.o rsa_common_client.o net_utils.o utils_common.o
SERVER_OBJS = server_main.o rsa_common_server.o net_utils.o utils_common.o

all: client server

client: $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $(CLIENT_FLAGS) -o $@ $(CLIENT_OBJS) $(LDFLAGS) $(LDLIBS)

server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(SERVER_FLAGS) -o $@ $(SERVER_OBJS) $(LDFLAGS) $(LDLIBS)

# Main application files for client and server.
client_main.o: client_main.c $(CLIENT_MAIN_DEPS)
	$(CC) $(CFLAGS) $(CLIENT_FLAGS) -c client_main.c -o $@
server_main.o: server_main.c $(SERVER_MAIN_DEPS)
	$(CC) $(CFLAGS) $(SERVER_FLAGS) -c server_main.c -o $@

# Build rsa_common.c separately for client and server.
rsa_common_client.o: rsa_common.c rsa_common.h
	$(CC) $(CFLAGS) $(CLIENT_FLAGS) -c rsa_common.c -o $@
rsa_common_server.o: rsa_common.c rsa_common.h
	$(CC) $(CFLAGS) $(SERVER_FLAGS) -c rsa_common.c -o $@

# net_utils is common and does not need a build flag.
net_utils.o: net_utils.c net_utils.h
	$(CC) $(CFLAGS) -c net_utils.c -o $@

# utils_common is common and does not need a build flag.
utils_common.o: utils_common.c utils_common.h
	$(CC) $(CFLAGS) -c utils_common.c -o $@

clean:
	$(RM) *.o *.pem *.der client server

.PHONY: test
test: all
	@echo "Starting server in background..."
	@./server &
	@sleep 2
	@echo "Running client..."
	@./client
	@sleep 2
	@pkill server
