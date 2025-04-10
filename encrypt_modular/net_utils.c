#include "net_utils.h"
#include <sys/types.h>  // for size_t & ssize_t
#include <sys/socket.h>  // for socket APIs
/*
    https://pubs.opengroup.org/onlinepubs/009695099/basedefs/sys/socket.h.html
    The sockaddr structure is used to define a socket address which is used in the bind(),
    connect(), getpeername(), getsockname(), recvfrom(), and sendto() functions.

    struct sockaddr {
        sa_family_t  sa_family  Address family. 
        char         sa_data[]  Socket address (variable-length data). 
    }
*/
#include <netinet/in.h>  // for struct sockaddr_in
/*
    https://pubs.opengroup.org/onlinepubs/009695399/basedefs/netinet/in.h.html
    The sockaddr_in structure is used to store addresses for the Internet address family.
    Values of this type shall be cast by applications to struct sockaddr for use with socket functions.
    The sockaddr_in structure is used to store addresses for the Internet address family. Values of this type 
        shall be cast by applications to struct sockaddr for use with socket functions.

    struct sockaddr_in {
        sa_family_t     sin_family   AF_INET. 
        in_port_t       sin_port     Port number. 
        struct in_addr  sin_addr     IP address. 
        unsigned char   sin_zero[8]  Not used.
    }
    struct in_addr {
        in_addr_t  s_addr  IP address. 
    }
*/
#include <netdb.h>  // for gethostbyname()
/*
    https://pubs.opengroup.org/onlinepubs/009695199/basedefs/netdb.h.html
    
    struct hostent {
        char   *h_name       Official name of the host.
        char  **h_aliases    A pointer to an array of pointers to 
                                alternative host names, terminated by a 
                                null pointer. 
        int     h_addrtype   Address type. 
        int     h_length     The length, in bytes, of the address. 
        char  **h_addr_list  A pointer to an array of pointers to network 
                                addresses (in network byte order) for the host, 
                                terminated by a null pointer.
    }
*/
#include <arpa/inet.h>  // for htons()
/*
    https://pubs.opengroup.org/onlinepubs/009695399/functions/htons.html
    uint16_t htons(uint16_t hostshort);
    Return the argument value converted from host to network byte order.
*/
#include <unistd.h>  // for close()
#include <string.h>  // for memset()
#include <stdio.h>  // for perror()
#include <errno.h>  // used by perror() to print error messages
#include <stdlib.h>  // for exit()

int create_server_socket(int port)
{
    // file descriptor of the server socket
    int sockfd;
    // server address
    struct sockaddr_in addr;
    // option for setsockopt
    int opt = 1;

    /*
        https://pubs.opengroup.org/onlinepubs/009695399/functions/socket.html
        int socket(int domain, int type, int protocol);
        Create an unbound socket in a communications domain, and return a file descriptor
            that can be used in later function calls that operate on sockets.
        domain (AF_INET)
            Internet domain sockets for use with IPv4 addresses.
        type (SOCK_STREAM)
            Byte-stream socket (TCP).
        protocol (0)
            Specifying a protocol of 0 causes socket() to use an unspecified default
                protocol appropriate for the requested socket type.
    */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    /*
        https://pubs.opengroup.org/onlinepubs/009695099/functions/setsockopt.html
        int setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_length);
        socket (sockfd)
            Specifies the file descriptor of the socket to be set.
        level (SOL_SOCKET)
            Options to be accessed at socket level, not protocol level.
        option_name (SO_REUSEADDR)
            Specifies that the rules used in validating addresses supplied to bind()
                should allow reuse of local addresses, if this is supported by the protocol.
                This option takes an int value. This is a Boolean option.
        opt = 1 enables the reuse of local addresses.
    */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return -1;
    }

    /*
        Set every bytes within the server address to 0, especially sin_zero
        struct sockaddr_in {
            sa_family_t     sin_family   AF_INET. 
            in_port_t       sin_port     Port number. 
            struct in_addr  sin_addr     IP address. 
            unsigned char   sin_zero[8]  Not used.
        }
        struct in_addr {
            in_addr_t s_addr;  // IPv4 address
        }
    */
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);  // convert port to network byte order, explained above
    /*
        INADDR_ANY
            IPv4 local host address.
        INADDR_BROADCAST
            IPv4 broadcast address. 
    */
    addr.sin_addr.s_addr = INADDR_ANY;
    

    /*
        https://pubs.opengroup.org/onlinepubs/009695399/functions/bind.html
        int bind(int socket, const struct sockaddr *address, socklen_t address_len);
        Assign a local socket address address to a socket identified by descriptor socket
            that has no local socket address assigned. Sockets created with the socket() 
            function are initially unnamed; they are identified only by their address family.
        socket (sockfd)
            Specifies the file descriptor of the socket to be bound.
        address ((struct sockaddr *)&addr) NOTE: struct sockaddr_in is typecasted to struct sockaddr
            Points to a sockaddr structure containing the address to be bound to the socket.
                The length and format of the address depend on the address family of the socket.
        address_len (sizeof(addr))
    */
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    /*
        https://pubs.opengroup.org/onlinepubs/009695099/functions/listen.html
        int listen(int socket, int backlog);
        Mark a connection-mode socket, specified by the socket argument, as accepting connections.
        socket (sockfd)
            Specifies the file descriptor of the socket to be marked as accepting connections.
        backlog (5)
            Specifies the maximum length to which the listen queue of pending connections for the socket may grow.

    */
    if (listen(sockfd, 5) < 0) {
        perror("listen");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

int accept_client(int server_socket)
{
    // file descriptor of the client socket
    int client_socket;
    // client address
    struct sockaddr_in client_addr;
    // length of the client address
    socklen_t addr_len = sizeof(client_addr);

    /*
        https://pubs.opengroup.org/onlinepubs/009695099/functions/accept.html
        int accept(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
        Extract the first connection on the queue of pending connections, create a new socket with the same
            socket type protocol and address family as the specified socket, and allocate a new file descriptor for that socket.
        socket (server_socket)
            Specifies the file descriptor of the socket for which the connection is to be accepted.
        address ((struct sockaddr *)&client_addr)
            Either a null pointer, or a pointer to a sockaddr structure where the address of the connecting socket shall be returned.
        address_len (&addr_len)
            Points to a socklen_t structure which on input specifies the length of the supplied
                sockaddr structure, and on output specifies the length of the stored address.
    */
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
    if (client_socket < 0) {
        perror("accept");
        return -1;
    }
    return client_socket;
}

int connect_to_server(const char *hostname, int port)
{
    // file descriptor of the client socket
    int sockfd;
    // server address
    struct sockaddr_in server_addr;
    /*
        Host information
        struct hostent {
            char   *h_name       Official name of the host.
            char  **h_aliases    A pointer to an array of pointers to 
                                    alternative host names, terminated by a 
                                    null pointer. 
            int     h_addrtype   Address type. 
            int     h_length     The length, in bytes, of the address. 
            char  **h_addr_list  A pointer to an array of pointers to network 
                                    addresses (in network byte order) for the host, 
                                    terminated by a null pointer.
        }
    */
    struct hostent *server;

    /*
        https://pubs.opengroup.org/onlinepubs/009695199/functions/gethostbyname.html
        struct hostent *gethostbyname(const char *name);
        Return an entry containing addresses of address family AF_INET for the host with name name.
        name (hostname)
            Specifies the name of the host to be looked up.
    */
    if ((server = gethostbyname(hostname)) == NULL) {  // replace with getaddrinfo
        fprintf(stderr, "Error: no such host %s\n", hostname);
        return -1;
    }

    /*
        https://pubs.opengroup.org/onlinepubs/009695399/functions/socket.html
        int socket(int domain, int type, int protocol);
        Create an unbound socket in a communications domain, and return a file descriptor
            that can be used in later function calls that operate on sockets.
        domain (AF_INET)
            Internet domain sockets for use with IPv4 addresses.
        type (SOCK_STREAM)
            Byte-stream socket (TCP).
        protocol (0)
            Specifying a protocol of 0 causes socket() to use an unspecified default
                protocol appropriate for the requested socket type.  
    */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    /*
        Set every bytes within the server address to 0, especially sin_zero
        struct sockaddr_in {
            sa_family_t     sin_family   AF_INET. 
            in_port_t       sin_port     Port number. 
            struct in_addr  sin_addr     IP address. 
            unsigned char   sin_zero[8]  Not used.
        }
        struct in_addr {
            in_addr_t s_addr;  // IPv4 address
        }
    */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    /*
        Copy the server address to the server_addr.sin_addr.s_addr
        struct in_addr {
            in_addr_t s_addr;  // IPv4 address
        }
    */
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    server_addr.sin_port = htons(port);  // convert port to network byte order

    /*
        https://pubs.opengroup.org/onlinepubs/009695099/functions/connect.html
        int connect(int socket, const struct sockaddr *address, socklen_t address_len);
        Attempt to make a connection on a socket.
        socket (sockfd)
            Specifies the file descriptor of the socket to be connected.
        address ((struct sockaddr *)&server_addr)
            Points to a sockaddr structure containing the peer address. 
                The length and format of the address depend on the address family of the socket.
        address_len (sizeof(server_addr))
            Specifies the length of the sockaddr structure pointed to by the address argument.
    */
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

ssize_t send_all(int sockfd, const void *buf, size_t len)
{
    size_t total = 0;
    const char *p = buf;
    while (total < len) {
        /*
            https://pubs.opengroup.org/onlinepubs/009695399/functions/send.html
            Initiate transmission of a message from the specified socket to its peer.
                The send() functionshall send a message only when the socket is connected
                (including when the peer of a connectionless socket has been set via connect()).
            socket (sockfd)
                Specifies the file descriptor of the socket to be used for transmission.
            buf (p + total)
                Points to the buffer containing the message to send.
            len (len - total)
                Specifies the length of the message in bytes.
            flags (0)
                Specifies the type of message transmission. Values of this argument are
                    formed by logically OR'ing zero or more of the following flags:
                MSG_EOR
                    Terminates a record (if supported by the protocol).
                MSG_OOB
                    Sends out-of-band data on sockets that support out-of-band communications.
                        The significance and semantics of out-of-band data are protocol-specific.
        */
        ssize_t sent = send(sockfd, p + total, len - total, 0);
        if (sent <= 0) {
            perror("send");
            return -1;
        }
        total += sent;
    }
    return total;
}

ssize_t recv_all(int sockfd, void *buf, size_t len)
{
    size_t total = 0;
    char *p = buf;
    while (total < len) {
        /*
            https://pubs.opengroup.org/onlinepubs/009695099/functions/recv.html
            Receive a message from a connection-mode or connectionless-mode socket.
                It is normally used with connected sockets because it does not permit
                the application to retrieve the source address of received data.
            socket (sockfd)
                Specifies the file descriptor of the socket from which the message is to be received.
            buf (p + total)
                Points to the buffer where the message should be stored.
            len (len - total)
                Specifies the length in bytes of the buffer pointed to by the buffer argument.
            flags (0)
                Specifies the type of message reception. Values of this argument are
                    formed by logically OR'ing zero or more of the following values:
                MSG_PEEK
                    Peeks at an incoming message. The data is treated as unread and the
                        next recv() or similar function shall still return this data.
                MSG_OOB
                    Requests out-of-band data. The significance and semantics
                        of out-of-band data are protocol-specific.
                MSG_WAITALL
                    On SOCK_STREAM sockets this requests that the function block until the
                        full amount of data can be returned. The function may return the smaller
                        amount of data if the socket is a message-based socket, if a signal is
                        caught,if the connection is terminated, if MSG_PEEK was specified, or if
                        an error is pending for the socket. 
        */
        ssize_t received = recv(sockfd, p + total, len - total, 0);
        if (received <= 0) {
            if (received < 0)
                perror("recv");
            return -1;
        }
        total += received;
    }
    return total;
}
