#include <stdio.h>
#include <stdlib.h>  // for system()
#include <stdint.h>  // for size_t
#include <unistd.h>  // for close()
#include <arpa/inet.h>  // for htonl()
#include <string.h>  // for memcpy
#include <openssl/crypto.h>  // for OPENSSL_free() & OPENSSL_zalloc()

#include "net_utils.h"
#include "utils_common.h"
#include "rsa_common.h"  // for get_ser_pub_enc_key()

#define SERVER_PORT 90001
#define SERVER_HOST "127.0.0.1"

static const unsigned char msg[] =
    "To be, or not to be, that is the question,\n"
    "Whether tis nobler in the minde to suffer\n"
    "The slings and arrowes of outragious fortune,\n"
    "Or to take Armes again in a sea of troubles";

int main(void) {
    OSSL_LIB_CTX *libctx = NULL;
    // MESSAGES
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0;
    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;

    // SERVER ENCRYPTION KEYS (DER-encoded) - will receive from server
    unsigned char *ser_pub_enc_der = NULL;
    size_t ser_pub_enc_der_len = 0;
    // SERVER SIGNATURE KEYS (DER-encoded) - will receive from server
    unsigned char *ser_pub_sig_der = NULL;
    size_t ser_pub_sig_der_len = 0;

    // CLIENT ENCRYPTION KEYS (DER-encoded)
    unsigned char *cli_priv_enc_der = NULL;
    size_t cli_priv_enc_der_len = 0;
    unsigned char *cli_pub_enc_der = NULL;
    size_t cli_pub_enc_der_len = 0;
    // CLIENT SIGNATURE KEYS (DER-encoded)
    unsigned char *cli_priv_sig_der = NULL;
    size_t cli_priv_sig_der_len = 0;
    unsigned char *cli_pub_sig_der = NULL;
    size_t cli_pub_sig_der_len = 0;

    int server_sock = -1;
    int ret = EXIT_FAILURE;

    // CONNECT TO THE SERVER
    server_sock = connect_to_server(SERVER_HOST, SERVER_PORT);
    if (server_sock < 0) {
        fprintf(stderr, "Client: Failed to connect to server.\n");
        goto cleanup;
    }
    printf("Client: Connected to server.\n");

    // RUN THE SCRIPT to generate client encryption keys 
    printf("Client: Generating encryption keys...\n");
    if (system("./scripts/client_generate_encryption_keys.sh") != 0) {
        fprintf(stderr, "Client: Failed to generate encryption keys.\n");
        goto cleanup;
    }
    printf("Client: Encryption keys generated successfully.\n");

    // RUN THE SCRIPT to generate client signature keys
    printf("Client: Generating signature keys...\n");
    if (system("./scripts/client_generate_signature_keys.sh") != 0) {
        fprintf(stderr, "Client: Failed to generate signature keys.\n");
        goto cleanup;
    }

    // PULL CLIENT ENCRYPTION / SIGNATURE KEYS
    cli_priv_enc_der = get_cli_priv_enc_der(&cli_priv_enc_der_len);
    cli_pub_enc_der = get_cli_pub_enc_der(&cli_pub_enc_der_len);
    cli_priv_sig_der = get_cli_priv_sig_der(&cli_priv_sig_der_len);
    cli_pub_sig_der = get_cli_pub_sig_der(&cli_pub_sig_der_len);

    /* BEGINNING OF KEY EXCHANGE */
    // 1. Send the client's public keys to the server
    if (send_message(server_sock, cli_pub_enc_der, cli_pub_enc_der_len) != 0) {
        fprintf(stderr, "Client: Failed to send public encryption key.\n");
        goto cleanup;
    }
    printf("Client: Sent public encryption key to server.\n");

    if (send_message(server_sock, cli_pub_sig_der, cli_pub_sig_der_len) != 0) {
        fprintf(stderr, "Client: Failed to send public signature key.\n");
        goto cleanup;
    }
    printf("Client: Sent public signature key to server.\n");

    // 2. Receive the server's public keys from the server
    if (recv_message(server_sock, &ser_pub_enc_der, &ser_pub_enc_der_len, 1) != 0) {
        fprintf(stderr, "Client: Failed to receive server's public encryption key.\n");
        goto cleanup;
    }
    printf("Client: Received server's public encryption key from server.\n");

    if (recv_message(server_sock, &ser_pub_sig_der, &ser_pub_sig_der_len, 1) != 0) {
        fprintf(stderr, "Client: Failed to receive server's public signature key.\n");
        goto cleanup;
    }
    printf("Client: Received server's public signature key from server.\n");
    /* END OF KEY EXCHANGE */

    // ENCRYPT THE MESSAGE using the server's public encryption key
    if (encrypt_message(libctx, ser_pub_enc_der, ser_pub_enc_der_len,
                        msg, sizeof(msg) - 1,
                        &encrypted, &encrypted_len) != 0) {
        goto cleanup;
    }

    // SEND THE ENCRYPTED MESSAGE to the server
    if (send_message(server_sock, encrypted, encrypted_len) != 0) {
        goto cleanup;
    }

    ret = EXIT_SUCCESS;

cleanup:
    if (server_sock >= 0)
        close(server_sock);
    if (encrypted)
        OPENSSL_free(encrypted);
    if (decrypted)
        OPENSSL_free(decrypted);
    // if (cli_priv_enc_der)
    //     OPENSSL_free(cli_priv_enc_der);
    // if (cli_pub_enc_der)
    //     OPENSSL_free(cli_pub_enc_der);
    // if (cli_priv_sig_der)
    //     OPENSSL_free(cli_priv_sig_der);
    // if (cli_pub_sig_der)
    //     OPENSSL_free(cli_pub_sig_der);
    // if (ser_pub_enc_der)
    //     OPENSSL_free(ser_pub_enc_der);
    // if (ser_pub_sig_der)
    //     OPENSSL_free(ser_pub_sig_der);
    return ret;
}
