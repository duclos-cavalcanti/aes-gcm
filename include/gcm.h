#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    uint8_t plaintext[1000];
    size_t plaintext_size;
    uint8_t ciphertext[1000];
    uint8_t H[16];
    const uint8_t key[16];
    uint8_t iv[12];
    uint8_t J0[16];
    uint8_t ICB[16];
    const uint8_t auth[50];
    size_t auth_size;
    uint8_t tag[16];
} gcm_context_t;

void gcmAesEncrypt(gcm_context_t *gcm);
int gcmAesDecrypt(gcm_context_t *gcm);
