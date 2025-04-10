#include "pss_hash.h"

int sign(OSSL_LIB_CTX *libctx, unsigned char **sig, size_t *sig_len,
        const char* text_message, const unsigned char *rsa_priv_key, size_t priv_key_len)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    const char *propq = NULL;
    EVP_MD_CTX *mctx = NULL;
    OSSL_PARAM params[2], *p = params;
    const unsigned char *ppriv_key = NULL;
    size_t message_len = strlen(text_message);

    *sig = NULL;

    /* Load DER-encoded RSA private key. */
    ppriv_key = rsa_priv_key;
    pkey = d2i_PrivateKey_ex(EVP_PKEY_RSA, NULL, &ppriv_key,
                             priv_key_len, libctx, propq);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to load private key\n");
        goto end;
    }

    /* Create MD context used for signing. */
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        fprintf(stderr, "Failed to create MD context\n");
        goto end;
    }

    /* Initialize MD context for signing. */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                            OSSL_PKEY_RSA_PAD_MODE_PSS, 0);
    *p = OSSL_PARAM_construct_end();

    if (EVP_DigestSignInit_ex(mctx, NULL, "SHA256", libctx, propq,
                              pkey, params) == 0) {
        fprintf(stderr, "Failed to initialize signing context\n");
        goto end;
    }

    /*
     * Feed data to be signed into the algorithm. This may
     * be called multiple times.
     */
    if (EVP_DigestSignUpdate(mctx, text_message, message_len) == 0) {
        fprintf(stderr, "Failed to hash message into signing context\n");
        goto end;
    }

    /* Determine signature length. */
    if (EVP_DigestSignFinal(mctx, NULL, sig_len) == 0) {
        fprintf(stderr, "Failed to get signature length\n");
        goto end;
    }

    /* Allocate memory for signature. */
    *sig = OPENSSL_malloc(*sig_len);
    if (*sig == NULL) {
        fprintf(stderr, "Failed to allocate memory for signature\n");
        goto end;
    }

    /* Generate signature. */
    if (EVP_DigestSignFinal(mctx, *sig, sig_len) == 0) {
        fprintf(stderr, "Failed to sign\n");
        goto end;
    }

    ret = 1;
end:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    if (ret == 0)
        OPENSSL_free(*sig);

    return ret;
}
