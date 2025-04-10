#ifndef RSA_DECRYPT_H
#define RSA_DECRYPT_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

int do_decrypt(OSSL_LIB_CTX *libctx, const unsigned char *in, size_t in_len,
    unsigned char **out, size_t *out_len);

#endif // RSA_DECRYPT_H