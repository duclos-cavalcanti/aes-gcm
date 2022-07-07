#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    uint8_t *plaintext;
    uint8_t *ciphertext;
    size_t plaintext_size;
    uint8_t *key;
    uint8_t *iv;
    uint8_t *J0;
    uint8_t *ICB
    uint8_t *auth;
    size_t auth_size;
    uint8_t *tag;
} gcm_input_t;

typedef struct {
    int current;
    int last;
    gcm_input_t* gcm;
    uint8_t H[16];
} gcm_context_t;

typedef struct {
    uint8_t *auth;
    size_t auth size;
    uint8_t *ciphertext;
    size_t ciphertext_size;
} ghash_input_t;

void gcmAesEncrypt(gcm_input_t *gcm);
