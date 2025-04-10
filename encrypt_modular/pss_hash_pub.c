#include "pss_hash.h"

/*
 * This function demonstrates verification of an RSA signature over an
 * arbitrary-length message using the PSS signature scheme. Hashing is performed
 * automatically.
 */
int verify(OSSL_LIB_CTX *libctx, const unsigned char *sig, size_t sig_len,
            const char* text_message, size_t message_len, const unsigned char *rsa_pub_key, size_t pub_key_len)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    const char *propq = NULL;
    EVP_MD_CTX *mctx = NULL;
    OSSL_PARAM params[2], *p = params;
    const unsigned char *ppub_key = NULL;

    /* Load DER-encoded RSA public key. */
    ppub_key = rsa_pub_key;
    pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &ppub_key, pub_key_len);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to load public key\n");
        goto end;
    }

    /* Create MD context used for verification. */
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        fprintf(stderr, "Failed to create MD context\n");
        goto end;
    }

    /* Initialize MD context for verification. */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                            OSSL_PKEY_RSA_PAD_MODE_PSS, 0);
    *p = OSSL_PARAM_construct_end();

    if (EVP_DigestVerifyInit_ex(mctx, NULL, "SHA256", libctx, propq,
                                pkey, params) == 0) {
        fprintf(stderr, "Failed to initialize signing context\n");
        goto end;
    }

    /* Feed data to be verified into the algorithm. */
    if (EVP_DigestVerifyUpdate(mctx, text_message, message_len) == 0) {
        fprintf(stderr, "Failed to hash message into signing context\n");
        goto end;
    }

    /* Verify signature. */
    if (EVP_DigestVerifyFinal(mctx, sig, sig_len) == 0) {
        fprintf(stderr, "Failed to verify signature; "
                "signature may be invalid\n");
        goto end;
    }

    ret = 1;
end:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ret;
}
