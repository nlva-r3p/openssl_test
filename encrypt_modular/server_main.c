#include <stdio.h>
#include <stdlib.h>  // for system()
#include <stdint.h>  // for size_t
#include <unistd.h>  // for close()
#include <arpa/inet.h>  // for htonl()
#include <string.h>  // for memcpy
#include <openssl/crypto.h>  // for OPENSSL_free() & OPENSSL_zalloc() 

#include "rsa_common.h"  // for get_public_key_der()
#include "net_utils.h"
#include "utils_common.h"  // for recv_message()

#define SERVER_PORT 90001

int main(void) {
    OSSL_LIB_CTX *libctx = NULL;
    // MESSAGES
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0;
    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;

    // CLIENT ENCRYPTION KEYS (DER-encoded) - will receive from client
    unsigned char *cli_pub_enc_der = NULL;
    size_t cli_pub_enc_der_len = 0;
    // CLIENT SIGNATURE KEYS (DER-encoded) - will receive from client
    unsigned char *cli_pub_sig_der = NULL;
    size_t cli_pub_sig_der_len = 0;

    // SERVER ENCRYPTION KEYS (DER-encoded)
    unsigned char *ser_priv_enc_der = NULL;
    size_t ser_priv_enc_der_len = 0;
    unsigned char *ser_pub_enc_der = NULL;
    size_t ser_pub_enc_der_len = 0;
    // SERVER SIGNATURE KEYS (DER-encoded)
    unsigned char *ser_priv_sig_der = NULL;
    size_t ser_priv_sig_der_len = 0;
    unsigned char *ser_pub_sig_der = NULL;
    size_t ser_pub_sig_der_len = 0;

    int server_sock = -1, client_sock = -1;
    int ret = EXIT_FAILURE;
    
    // CREATE A SERVER socket
    server_sock = create_server_socket(SERVER_PORT);
    if (server_sock < 0) {
        fprintf(stderr, "Server: Failed to create socket.\n");
        goto cleanup;
    }
    printf("Server: Created server socket.\n");

    // ACCEPT A CLIENT connection
    printf("Server: Waiting for connection on port %d...\n", SERVER_PORT);
    client_sock = accept_client(server_sock);
    if (client_sock < 0) {
        fprintf(stderr, "Server: Failed to accept client connection.\n");
        goto cleanup;
    }
    printf("Server: Accepted client connection.\n");

    // RUN THE SCRIPT to generate server encryption keys 
    printf("Server: Generating encryption keys...\n");
    if (system("./scripts/server_generate_encryption_keys.sh") != 0) {
        fprintf(stderr, "Server: Failed to generate encryption keys.\n");
        goto cleanup;
    }
    printf("Server: Encryption keys generated successfully.\n");

    // RUN THE SCRIPT to generate server signature keys
    printf("Server: Generating signature keys...\n");
    if (system("./scripts/server_generate_signature_keys.sh") != 0) {
        fprintf(stderr, "Server: Failed to generate signature keys.\n");
        goto cleanup;
    }

    // PULL SERVER ENCRYPTION / SIGNATURE KEYS
    ser_priv_enc_der = get_ser_priv_enc_der(&ser_priv_enc_der_len);
    ser_pub_enc_der = get_ser_pub_enc_der(&ser_pub_enc_der_len);
    ser_priv_sig_der = get_ser_priv_sig_der(&ser_priv_sig_der_len);
    ser_pub_sig_der = get_ser_pub_sig_der(&ser_pub_sig_der_len);

    /* BEGINNING OF KEY EXCHANGE */
    // 1. Receive the client's public keys
    if (recv_message(client_sock, &cli_pub_enc_der, &cli_pub_enc_der_len, 1) != 0) {
        fprintf(stderr, "Server: Failed to receive client's public encryption key.\n");
        goto cleanup;
    }
    printf("Server: Received client's public encryption key.\n");

    if (recv_message(client_sock, &cli_pub_sig_der, &cli_pub_sig_der_len, 1) != 0) {
        fprintf(stderr, "Server: Failed to receive client's public signature key.\n");
        goto cleanup;
    }
    printf("Server: Received client's public signature key.\n");

    // 2. Send the server's public keys to the client
    if (send_message(client_sock, ser_pub_enc_der, ser_pub_enc_der_len) != 0) {
        fprintf(stderr, "Server: Failed to send public encryption key.\n");
        goto cleanup;
    }
    printf("Server: Sent public encryption key to client.\n");

    if (send_message(client_sock, ser_pub_sig_der, ser_pub_sig_der_len) != 0) {
        fprintf(stderr, "Server: Failed to send public signature key.\n");
        goto cleanup;
    }
    printf("Server: Sent public signature key to client.\n");
    /* END OF KEY EXCHANGE */

    // RECEIVE THE ENCRYPTED MESSAGE from the client
    if (recv_message(client_sock, &encrypted, &encrypted_len, 1) != 0) {
        goto cleanup;
    }
    
    // DECRYPT THE ENCRYPTED MESSAGE
    if (decrypt_message(libctx, ser_priv_enc_der, ser_priv_enc_der_len,
                        encrypted, encrypted_len, &decrypted, &decrypted_len) != 0) {
        goto cleanup;
    }

    // PRINT THE DECRYPTED MESSAGE
    printf("Server: Decrypted message:\n%.*s\n", (int)decrypted_len, decrypted);
    ret = EXIT_SUCCESS;

cleanup:
    if (client_sock >= 0)
        close(client_sock);
    if (server_sock >= 0)
        close(server_sock);
    if (encrypted)
        OPENSSL_free(encrypted);
    if (decrypted)
        OPENSSL_free(decrypted);
    // if (cli_pub_enc_der)
    //     OPENSSL_free(cli_pub_enc_der);
    // if (cli_pub_sig_der)
    //     OPENSSL_free(cli_pub_sig_der);
    // if (ser_priv_enc_der)
    //     OPENSSL_free(ser_priv_enc_der);
    // if (ser_pub_enc_der)
    //     OPENSSL_free(ser_pub_enc_der);
    // if (ser_priv_sig_der)
    //     OPENSSL_free(ser_priv_sig_der);
    // if (ser_pub_sig_der)
    //     OPENSSL_free(ser_pub_sig_der);
    return ret;
}
