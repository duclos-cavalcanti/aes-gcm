#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    uint8_t *plaintext;
    size_t plaintext_size;
    uint8_t *ciphertext;
    uint8_t H[16];
    const uint8_t key[16];
    const uint8_t iv[12];
    uint8_t J0[16];
    uint8_t ICB[16];
    const uint8_t *auth;
    size_t auth_size;
    uint8_t tag[16];
} gcm_context_t;

void gcmAesEncrypt(gcm_context_t *gcm);
int gcmAesDecrypt(gcm_context_t *gcm);
