#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <sys/types.h>
#include <stddef.h>

// Create a server socket that listens on the given port.
int create_server_socket(int port);

// Accept a client connection on the server socket.
int accept_client(int server_socket);

// Connect to a server given hostname and port.
int connect_to_server(const char *hostname, int port);

// Send all bytes in buf over the socket.
ssize_t send_all(int sockfd, const void *buf, size_t len);

// Receive exactly len bytes from the socket.
ssize_t recv_all(int sockfd, void *buf, size_t len);

#endif // NET_UTILS_H
