/*
    Author: Yashraj221B
    Resources: https://docs.openssl.org/1.1.1/man3/SHA256_Init
*/

// Installing SSL Library: sudo apt install libssl-dev
// Compiling: gcc program.c -o program.out -lcrypto

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

// Suppress deprecated warnings for OpenSSL SHA functions as OpenSSL3 uses EVP API but we'll use older method for sake of simplicity
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/*
 * Function to compute sha256 hash
 *    Parameter 1 => Pointer to input character array (basically a string)
 *    Parameter 2 => Pointer to output character array (again basically a string but will store binary data)
*/
void calculate_sha256(char *str, unsigned char output[SHA256_DIGEST_LENGTH]) {
    // Declare SHA256 context
    SHA256_CTX ctx;

    // Initialize SHA256 context
    SHA256_Init(&ctx);

    // Feed input string into SHA256 computation
    SHA256_Update(&ctx, str, strlen(str));

    // Finalize the computation and store the hash in output
    SHA256_Final(output, &ctx);
}

#pragma GCC diagnostic pop // Restore warnings after deprecated usage....dw about it, I just like my terminal clean

/*
 * Function to print SHA-256 hash in hexadecimal format.
 *    Here the output array holds the hash as raw binary data, but we print it as hexadecimal. 1 byte of the is represented by 2 hexadecimal characters, so we print each byte individually.
 *    Parameter 1 => Pointer to the computed hash to print.
 *    Parameter 2 => Length of the hash in bytes.
 */
void print_hash(unsigned char *hash, int length) {
    for (int i = 0; i < length; i++) {
        // Print each byte as a two-character hexadecimal value
        printf("%02x", hash[i]);
    }
    printf("\n");
}

/*
 * Main function - yeh toh tumko pata hai coz tum smart ho <3
 */
int main() {
    char input[] = "Hello from Yashraj221B";

    unsigned char hash[SHA256_DIGEST_LENGTH];

    calculate_sha256(input, hash);

    printf("SHA-256 hash: ");
    print_hash(hash, SHA256_DIGEST_LENGTH);

    return 0;
}
