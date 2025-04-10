#include "utils_common.h"

/*
* Parameters:
*   sockfd: The socket file descriptor to send the message to.
*   msg: Pointer to the message buffer to send.
*   msg_len: Length of the message to send.
*
* Returns:
*   0 on success, -1 on failure.
*/
int send_message(int sockfd, const unsigned char *msg, size_t msg_len)
{
    uint32_t net_len = htonl((uint32_t)msg_len);  // convert to network byte order

    if (send_all(sockfd, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        fprintf(stderr, "Client: Failed to send message length.\n");
        return -1;
    }
    printf("Client: Sent encrypted message length to server.\n");

    if (send_all(sockfd, msg, msg_len) != (ssize_t)msg_len) {
        fprintf(stderr, "Client: Failed to send encrypted data.\n");
        return -1;
    }
    printf("Client: Sent encrypted message to server.\n");

    return 0;
}

/*
* Parameters:
*   sockfd: The socket file descriptor to receive the message from.
*   msg: Pointer to an unsigned char pointer, where the message buffer will be stored.
*   msg_len  - Pointer to a variable that will hold the message length.
*   auto_alloc - When nonzero, the function receives the length and allocates the buffer.
*
* Returns:
*   0 on success, -1 on failure.
*/
int recv_message(int sockfd, unsigned char **msg, size_t *msg_len, int auto_alloc)
{
    if (auto_alloc) {
        uint32_t net_len = 0;
        // RECEIVE THE 32-BIT LENGTH of the encrypted message
        if (recv_all(sockfd, &net_len, sizeof(net_len)) != sizeof(net_len)) {
            fprintf(stderr, "Server: Failed to receive message length.\n");
            return -1;
        }
        printf("Server: Received encrypted message length from client.\n");

        // CONVERT LENGTH from network to host byte order and set msg_len
        *msg_len = ntohl(net_len);

        // ALLOCATE MEMORY for the encrypted message
        *msg = OPENSSL_zalloc(*msg_len);
        if (*msg == NULL) {
            fprintf(stderr, "Server: Memory allocation failed.\n");
            return -1;
        }
        printf("Server: Allocated memory for encrypted message.\n");
    }

    // RECEIVE THE ACTUAL ENCRYPTED MESSAGE DATA
    if (recv_all(sockfd, *msg, *msg_len) != (ssize_t)*msg_len) {
        fprintf(stderr, "Server: Failed to receive encrypted message.\n");
        if (auto_alloc && *msg != NULL) {
            OPENSSL_free(*msg);
            *msg = NULL;
        }
        return -1;
    }
    printf("Server: Received encrypted message from client.\n");

    return 0;
}

/*
* Parameters:
*   libctx: The OpenSSL library context.
*   msg: Pointer to the plaintext message.
*   msg_len: Length of the plaintext message.
*   encrypted: Pointer to an unsigned char pointer, where the encrypted message buffer will be stored.
*   encrypted_len: Pointer to a variable that will hold the encrypted message length.
*
* Returns:
*   0 on success, -1 on failure.
*/
int encrypt_message(OSSL_LIB_CTX *libctx,
                    const unsigned char *pub_key_der, size_t pub_key_der_len,
                    const unsigned char *msg, size_t msg_len,
                    unsigned char **encrypted, size_t *encrypted_len)
{
    if (!do_encrypt(libctx, pub_key_der, pub_key_der_len,
                    msg, msg_len, encrypted, encrypted_len)) {
        fprintf(stderr, "Encryption failed.\n");
        return -1;
    }
    printf("Client: Encrypted message.\n");
    return 0;
}

/*
* Parameters:
*   libctx: The OpenSSL library context.
*   encrypted: Pointer to the encrypted message buffer.
*   encrypted_len: Length of the encrypted message.
*   decrypted: Pointer to an unsigned char pointer, where the decrypted message buffer will be stored.
*   decrypted_len: Pointer to a variable that will hold the decrypted message length.
*
* Returns:
*   0 on success, -1 on failure.
*/
int decrypt_message(OSSL_LIB_CTX *libctx,
                    const unsigned char *priv_key_der, size_t priv_key_der_len,
                    const unsigned char *encrypted, size_t encrypted_len,
                    unsigned char **decrypted, size_t *decrypted_len)
{
    if (!do_decrypt(libctx, priv_key_der, priv_key_der_len, encrypted, encrypted_len, decrypted, decrypted_len)) {
        fprintf(stderr, "Decryption failed.\n");
        return -1;
    }
    printf("Decrypted message.\n");
    return 0;
}