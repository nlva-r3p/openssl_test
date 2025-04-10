#include "./cli_enc_keys/cli_pub_enc_key.h"
#ifdef CLIENT_BUILD
#include "./cli_enc_keys/cli_priv_enc_key.h"
#endif

#include "./ser_enc_keys/ser_pub_enc_key.h"
#ifdef SERVER_BUILD
#include "./ser_enc_keys/ser_priv_enc_key.h"
#endif

#include "./cli_sig_keys/cli_pub_sig_key.h"
#ifdef CLIENT_BUILD
#include "./cli_sig_keys/cli_priv_sig_key.h"
#endif

#include "./ser_sig_keys/ser_pub_sig_key.h"
#ifdef SERVER_BUILD
#include "./ser_sig_keys/ser_priv_sig_key.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/decoder.h>

#include "rsa_common.h"

int do_encrypt(OSSL_LIB_CTX *libctx,
    const unsigned char *pub_key_der, size_t pub_key_der_len,
    const unsigned char *in, size_t in_len,
    unsigned char **out, size_t *out_len)
{
int ret = 0;
size_t buf_len = 0;
unsigned char *buf = NULL;
const char *propq = NULL;
EVP_PKEY_CTX *ctx = NULL;
EVP_PKEY *pub_key = NULL;
OSSL_PARAM params[5];

/* Load the public key from DER-formatted data using get_key_from_der */
pub_key = get_key_from_der(pub_key_der, pub_key_der_len, libctx, propq, 1);
if (pub_key == NULL) {
fprintf(stderr, "Failed to load public key.\n");
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

int do_decrypt(OSSL_LIB_CTX *libctx,
               const unsigned char *priv_key_der, size_t priv_key_der_len,
               const unsigned char *in, size_t in_len,
               unsigned char **out, size_t *out_len)
{
    int ret = 0;
    size_t buf_len = 0;
    unsigned char *buf = NULL;
    const char *propq = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *priv_key = NULL;
    OSSL_PARAM params[5];

    /* Load the private key from DER-formatted data using get_key_from_der */
    priv_key = get_key_from_der(priv_key_der, priv_key_der_len, libctx, propq, 0);
    if (priv_key == NULL) {
        fprintf(stderr, "Failed to load private key.\n");
        goto cleanup;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, priv_key, propq);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed.\n");
        goto cleanup;
    }

    set_optional_params(params, propq);
    if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt_init_ex() failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_decrypt(ctx, NULL, &buf_len, in, in_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt() failed when calculating buffer length.\n");
        goto cleanup;
    }

    buf = OPENSSL_zalloc(buf_len);
    if (buf == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_decrypt(ctx, buf, &buf_len, in, in_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_decrypt() failed during decryption.\n");
        goto cleanup;
    }

    *out_len = buf_len;
    *out = buf;
    fprintf(stdout, "Decrypted:\n");
    BIO_dump_indent_fp(stdout, buf, buf_len, 2);
    fprintf(stdout, "\n");
    ret = 1;

cleanup:
    if (!ret)
        OPENSSL_free(buf);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* Helper function to load an EVP_PKEY from DER-encoded data */
EVP_PKEY *get_key_from_der(const unsigned char *der, size_t der_len,
                                  OSSL_LIB_CTX *libctx, const char *propq,
                                  int is_public)
{
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;
    int selection;

    if (is_public)
        selection = EVP_PKEY_PUBLIC_KEY;
    else {
        selection = EVP_PKEY_KEYPAIR;
    }

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, "RSA",
                                         selection, libctx, propq);
    if (dctx == NULL) {
        fprintf(stderr, "Failed to create decoder context.\n");
        return NULL;
    }

    {
        const unsigned char *data = der;
        size_t data_len = der_len;
        if (!OSSL_DECODER_from_data(dctx, &data, &data_len)) {
            fprintf(stderr, "Failed to decode DER data.\n");
            OSSL_DECODER_CTX_free(dctx);
            return NULL;
        }
    }

    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

/* Set optional parameters for OAEP padding */
void set_optional_params(OSSL_PARAM *p, const char *propq)
{
    static unsigned char label[] = "label";

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                             OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                              label, sizeof(label));
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                             "SHA256", 0);
    if (propq != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
                                                 (char *)propq, 0);
    *p = OSSL_PARAM_construct_end();
}

#ifdef SERVER_BUILD
/* Get Server Public Encryption Key DER */
unsigned char *get_ser_pub_enc_der(size_t *len)
{
    if (len)
        *len = sizeof(ser_pub_enc_der);
    return ser_pub_enc_der;
}

/* Get Server Private Encryption Key DER */
unsigned char *get_ser_priv_enc_der(size_t *len)
{
    if (len)
        *len = sizeof(ser_priv_enc_der);
    return ser_priv_enc_der;
}
#endif

#ifdef CLIENT_BUILD
/* Get Client Public Encryption Key DER */
unsigned char *get_cli_pub_enc_der(size_t *len)
{
    if (len)
        *len = sizeof(cli_pub_enc_der);
    return cli_pub_enc_der;
}

/* Get Client Private Encryption Key DER */
unsigned char *get_cli_priv_enc_der(size_t *len)
{
    if (len)
        *len = sizeof(cli_priv_enc_der);
    return cli_priv_enc_der;
}
#endif

#ifdef SERVER_BUILD
/* Get Server Public Signature Key DER */
unsigned char *get_ser_pub_sig_der(size_t *len)
{
    if (len)
        *len = sizeof(ser_pub_sig_der);
    return ser_pub_sig_der;
}

/* Get Server Private Signature Key DER */
unsigned char *get_ser_priv_sig_der(size_t *len)
{
    if (len)
        *len = sizeof(ser_priv_sig_der);
    return ser_priv_sig_der;
}
#endif

#ifdef CLIENT_BUILD
/* Get Client Public Signature Key DER */
unsigned char *get_cli_pub_sig_der(size_t *len)
{
    if (len)
        *len = sizeof(cli_pub_sig_der);
    return cli_pub_sig_der;
}

/* Get Client Private Signature Key DER */
unsigned char *get_cli_priv_sig_der(size_t *len)
{
    if (len)
        *len = sizeof(cli_priv_sig_der);
    return cli_priv_sig_der;
}
#endif
