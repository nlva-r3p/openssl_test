# https://docs.openssl.org/3.3/man1/openssl-genrsa/
# https://developers.yubico.com/PIV/Guides/Generating_keys_using_OpenSSL.html
# The public exponent is usually set to a standard value such as 65537.
# This value is used across many RSA implementations and does not change
# from one key pair to another.

TARGET_DIR=$(dirname "$0")/..
# echo "Target directory: $TARGET_DIR"

openssl genrsa -out private.pem 2048

# https://docs.openssl.org/1.1.1/man1/rsa/#description
openssl rsa -in private.pem -outform DER -out private.der
openssl rsa -in private.pem -pubout -outform DER -out public.der

# https://www.tutorialspoint.com/unix_commands/xxd.htm
xxd -i -n cli_priv_sig_der private.der > "$TARGET_DIR/cli_sig_keys/cli_priv_sig_key.h"
xxd -i -n cli_pub_sig_der public.der > "$TARGET_DIR/cli_sig_keys/cli_pub_sig_key.h"