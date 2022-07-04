#include <stdint.h>
#include <string.h>
#include <stdio.h>

void gcmAesEncrypt(uint8_t *input, const size_t input_size, 
                   const uint8_t *key, const uint8_t *iv, 
                   const uint8_t *auth, const size_t auth_size, 
                   uint8_t *output, uint8_t *tag);

int gcmAesDecrypt(const uint8_t *cipher, const size_t cipher_size, 
                  const uint8_t *key, const uint8_t *iv, 
                  const uint8_t *auth, const size_t auth_size, 
                  uint8_t *output, const uint8_t *tag);

void printArray(const uint8_t* arr, int size, char* header);

