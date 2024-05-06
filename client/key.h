#ifndef KEY_H
#define KEY_H

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

EC_KEY *create_key(void);
unsigned char *get_secret(EC_KEY *key, const EC_POINT *peer_pub_key,
			size_t *secret_len);
char* get_public_key(EC_KEY* key);
void free_string(char* str);
char* get_private_key(EC_KEY* key);

#endif // KEY_H