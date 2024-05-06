#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

int main() {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_brainpoolP256r1);
    
    if (ec_key == NULL) {
        fprintf(stderr, "Failed to create EC_KEY for secp256k1\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (EC_KEY_generate_key(ec_key) != 1) {
        fprintf(stderr, "Failed to generate EC_KEY key pair\n");
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        return 1;
    }

    printf("ECC key pair generated successfully.\n");

    EC_KEY_free(ec_key);
    return 0;
}
