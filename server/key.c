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

char* get_public_key(EC_KEY* key, int* x_length, int* y_length) {
    EC_POINT* point = EC_KEY_get0_public_key(key);
    const EC_GROUP* group = EC_KEY_get0_group(key);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    if (!x || !y) {
        if (x) BN_free(x);
        if (y) BN_free(y);
        return NULL;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL)) {
        BN_free(x);
        BN_free(y);
        return NULL;
    }

    *x_length = BN_num_bytes(x); 
    *y_length = BN_num_bytes(y); 

    char* public_key = malloc(*x_length + *y_length);
    if (!public_key) {
        BN_free(x);
        BN_free(y);
        return NULL;
    }

    BN_bn2bin(x, (unsigned char*) public_key);
    BN_bn2bin(y, (unsigned char*) (public_key + *x_length));

    BN_free(x);
    BN_free(y);
    return public_key;
}

EC_POINT* bytesToECPoint(unsigned char* xBytes, int xLen, unsigned char* yBytes, int yLen) {
    BIGNUM *x = BN_bin2bn(xBytes, xLen, NULL);
    BIGNUM *y = BN_bin2bn(yBytes, yLen, NULL);
    if (x == NULL || y == NULL) {
		BN_free(x);               
		BN_free(y);
        return NULL; 
    }

	EC_KEY *new_key = EC_KEY_new_by_curve_name(NID_brainpoolP256r1);
	if (!new_key) {
		BN_free(x);               
		BN_free(y);
		return NULL;
	}

	const EC_GROUP *group = EC_KEY_get0_group(new_key);
	EC_POINT *pub_key = EC_POINT_new(group);
	if (!pub_key) {
		BN_free(x);               
		BN_free(y);
		return NULL;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(group, pub_key, x, y, NULL)) {
		BN_free(x);               
		BN_free(y);
		return NULL;
	}

    BN_free(x);               
	BN_free(y);

	return pub_key;
}
