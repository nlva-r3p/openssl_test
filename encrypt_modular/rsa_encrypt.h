#ifndef RSA_ENCRYPT_H
#define RSA_ENCRYPT_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

int do_encrypt(OSSL_LIB_CTX *libctx,
    const unsigned char *in, size_t in_len,
    unsigned char **out, size_t *out_len);

#endif // RSA_ENCRYPT_H