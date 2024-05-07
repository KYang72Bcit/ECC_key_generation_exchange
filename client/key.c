#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

EC_KEY *create_key(void)
{
	EC_KEY *key;
	if (NULL == (key = EC_KEY_new_by_curve_name(NID_brainpoolP256r1))) {
		printf("Failed to create key curve\n");
		return NULL;
	}

	if (1 != EC_KEY_generate_key(key)) {
		printf("Failed to generate key\n");
		return NULL;
	}
	return key;
}

unsigned char *get_secret(EC_KEY *key, const EC_POINT *peer_pub_key,
			size_t *secret_len)
{
	int field_size;
	unsigned char *secret;

	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	*secret_len = (field_size + 7) / 8;

	if (NULL == (secret = OPENSSL_malloc(*secret_len))) {
		printf("Failed to allocate memory for secret");
		return NULL;
	}

	*secret_len = ECDH_compute_key(secret, *secret_len,
					peer_pub_key, key, NULL);

	if (*secret_len <= 0) {
		OPENSSL_free(secret);
		return NULL;
	}
	return secret;
}


char* get_public_key(EC_KEY* key) {
    if (!key) return "Invalid key";
    EC_POINT* point = EC_KEY_get0_public_key(key);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    char* pub_key = malloc(512); 

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key), point, x, y, NULL)) {
        strcpy(pub_key, "Error getting coordinates");
    } else {
        sprintf(pub_key, "(%s, %s) on brainpoolP256r1 ", BN_bn2dec(x), BN_bn2dec(y));
    }

    BN_free(x);
    BN_free(y);
    return pub_key;
}

char* get_private_key(EC_KEY* key) {
	if (!key) return "Invalid key";
	BIGNUM* priv_key = EC_KEY_get0_private_key(key);
	char *priv_key_str = BN_bn2dec(priv_key);
    if (!priv_key_str) {
        return "Failed to convert key";
    }
	return priv_key_str;
}

void free_string(char* str) {
    free(str);
}