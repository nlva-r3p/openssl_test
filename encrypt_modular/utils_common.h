#ifndef UTILS_COMMON_H
#define UTILS_COMMON_H

#include <stdio.h>
#include <stdlib.h>  // for system()
#include <stdint.h>  // for size_t
#include <unistd.h>  // for close()
#include <arpa/inet.h>  // for htonl()
#include <string.h>  // for memcpy
#include <openssl/crypto.h>  // for OPENSSL_free() & OPENSSL_zalloc() 

#include "net_utils.h"
#include "rsa_common.h"  // for get_public_key_der()

int send_message(int sockfd, const unsigned char *msg, size_t msg_len);
int recv_message(int sockfd, unsigned char **msg, size_t *msg_len, int auto_alloc);
int encrypt_message(OSSL_LIB_CTX *libctx,
    const unsigned char *pub_key_der, size_t pub_key_der_len,
    const unsigned char *msg, size_t msg_len,
    unsigned char **encrypted, size_t *encrypted_len);
int decrypt_message(OSSL_LIB_CTX *libctx,
    const unsigned char *priv_key_der, size_t priv_key_der_len,
    const unsigned char *encrypted, size_t encrypted_len,
    unsigned char **decrypted, size_t *decrypted_len);

#endif // UTILS_COMMON_H