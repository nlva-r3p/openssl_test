#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>
#include "rsa_encrypt.h"
#include "rsa_common.h"

int do_encrypt(OSSL_LIB_CTX *libctx,
               const unsigned char *in, size_t in_len,
               unsigned char **out, size_t *out_len)
{
    int ret = 0, public = 1;
    size_t buf_len = 0;
    unsigned char *buf = NULL;
    const char *propq = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pub_key = NULL;
    OSSL_PARAM params[5];

    /* Select the correct public key based on build type */
#ifdef CLIENT_BUILD
    pub_key = get_ser_enc_key(libctx, propq, public);
#elif defined(SERVER_BUILD)
    pub_key = get_cli_enc_key(libctx, propq, public);
#else
    #error "Define either CLIENT_BUILD or SERVER_BUILD"
#endif

    if (pub_key == NULL) {
        fprintf(stderr, "Get public key failed.\n");
        goto cleanup;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pub_key, propq);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed.\n");
        goto cleanup;
    }

    set_optional_params(params, propq);
    /* If no optional parameters are required then NULL can be passed */
    if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt_init_ex() failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &buf_len, in, in_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt() failed to calculate buffer length.\n");
        goto cleanup;
    }

    buf = OPENSSL_zalloc(buf_len);
    if (buf == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_encrypt(ctx, buf, &buf_len, in, in_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt() failed during encryption.\n");
        goto cleanup;
    }

    *out_len = buf_len;
    *out = buf;
    fprintf(stdout, "Encrypted:\n");
    BIO_dump_indent_fp(stdout, buf, buf_len, 2);
    fprintf(stdout, "\n");
    ret = 1;

cleanup:
    if (!ret)
        OPENSSL_free(buf);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
