#ifndef PSS_HASH_H
#define PSS_HASH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/bio.h>

int sign(OSSL_LIB_CTX *libctx, unsigned char **sig, size_t *sig_len, 
         const char* text_message, const unsigned char *rsa_priv_key, size_t priv_key_len);

int verify(OSSL_LIB_CTX *libctx, const unsigned char *sig, size_t sig_len, 
           const char* text_message, size_t message_len, const unsigned char *rsa_pub_key, size_t pub_key_len);

#endif  // PSS_HASH_H