#ifndef RSA_COMMON_H
#define RSA_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* Encryption and Decryption functions */
int do_encrypt(OSSL_LIB_CTX *libctx,
    const unsigned char *pub_key_der, size_t pub_key_der_len,
    const unsigned char *in, size_t in_len,
    unsigned char **out, size_t *out_len);
int do_decrypt(OSSL_LIB_CTX *libctx,
    const unsigned char *priv_key, size_t priv_key_len,
    const unsigned char *in, size_t in_len,
    unsigned char **out, size_t *out_len);

/* Static get key function */
EVP_PKEY *get_key_from_der(const unsigned char *der, size_t der_len,
                                  OSSL_LIB_CTX *libctx, const char *propq,
                                  int is_public);

void set_optional_params(OSSL_PARAM *p, const char *propq);

#ifdef SERVER_BUILD
/* Get the server public encryption key in DER format */
unsigned char *get_ser_pub_enc_der(size_t *len);
/* Get the server private encryption key in DER format (only available in SERVER_BUILD) */
unsigned char *get_ser_priv_enc_der(size_t *len);
#endif

#ifdef CLIENT_BUILD
/* Get the client public encryption key in DER format */
unsigned char *get_cli_pub_enc_der(size_t *len);
/* Get the client private encryption key in DER format (only available in CLIENT_BUILD) */
unsigned char *get_cli_priv_enc_der(size_t *len);
#endif

#ifdef SERVER_BUILD
/* Get the server public signature key in DER format */
unsigned char *get_ser_pub_sig_der(size_t *len);
/* Get the server private signature key in DER format (only available in SERVER_BUILD) */
unsigned char *get_ser_priv_sig_der(size_t *len);
#endif

#ifdef CLIENT_BUILD
/* Get the client public signature key in DER format */
unsigned char *get_cli_pub_sig_der(size_t *len);
/* Get the client private signature key in DER format (only available in CLIENT_BUILD) */
unsigned char *get_cli_priv_sig_der(size_t *len);
#endif

#endif /* RSA_COMMON_H */