#include <stdio.h>

#include "aes.h"
#include "gcm.h"

void printMatrix(const uint8_t* state, char* header) {
    printf("%s: \n[ ", header);
    printf("\n");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x, ", state[4*j + i]);
        }
        if (i == 3)
            printf("\n]");
        else
            printf("\n");
    }
    printf("\n");
}

void printArray(const uint8_t* arr, int size, char* header) {
    printf("%s: \n[ ", header);
    printf("\n");
    for (int i = 0; i < size; i++) {
        printf("0x%02x, ", arr[i]);
        if ((i + 1) % 4 == 0)
            printf("\n");
    }
    printf("]\n");
}

int compareArray(const uint8_t* a, const uint8_t* b, int size) {
    for (int i = 0; i < size; i++) {
        if (a[i] != b[i])
            return 0;
    }

    return 1;
}

int aesTest() {
    const uint8_t plaintext[16] = { 0x00, 0x11, 0x22, 0x33,
                                    0x44, 0x55, 0x66, 0x77,
                                    0x88, 0x99, 0xaa, 0xbb,
                                    0xcc, 0xdd, 0xee, 0xff };

    const uint8_t key[] =  { 0x00, 0x01, 0x02, 0x03,
                             0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b,
                             0x0c, 0x0d, 0x0e, 0x0f
                            };

    uint8_t enc[16] = { 0 };
    uint8_t dec[16] = { 0 };

    const uint8_t g_encryption[] = { 0x69, 0xc4, 0xe0, 0xd8,
                                     0x6a, 0x7b, 0x04, 0x30,
                                     0xd8, 0xcd, 0xb7, 0x80,
                                     0x70, 0xb4, 0xc5, 0x5a
                                   };

    printf( "========= AES =========\n");
    printMatrix(plaintext, "Input");

    aesEncrypt(plaintext, key, enc);
    printMatrix(enc, "Encryption");

    printMatrix(g_encryption, "Correct Encryption");

    aesDecrypt(enc, key, dec);
    printMatrix(dec, "Decryption");


    if (!compareArray(enc, g_encryption, 16)) {
        printf("Encryption doesnt match");
        return 0;
    }

    if (!compareArray(dec, plaintext, 16)) {
        printf("Decryption doesnt match");
        return 0;
    }

    return 1;
}

int main(int argc, char *argv[]) {
    aesTest();
}
