#include "aes_test.h"

#include "aes.h"
#include "util.h"

int aesTest() {
    uint8_t encrypted[16] = { 0 };
    uint8_t decrypted [16] = { 0 };

    const uint8_t plaintext[16] =
    {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    const uint8_t key[] =
    {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    const uint8_t correct_encrypted[] =
    {
        0x69, 0xc4, 0xe0, 0xd8,
        0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80,
        0x70, 0xb4, 0xc5, 0x5a
    };

    printf( "========= AES =========\n");
    printArray(plaintext, 16, "Input");

    aesEncrypt(plaintext, key, encrypted);

    printArray(encrypted, 16, "Encryption");
    printArray(correct_encrypted, 16, "Correct Encryption");

    aesDecrypt(encrypted, key, decrypted);

    printArray(decrypted, 16, "Decryption");

    if (!equalArrays(encrypted, correct_encrypted, 16)) {
        printf("Encryption doesnt match\n");
        return 0;
    }

    if (!equalArrays(decrypted, plaintext, 16)) {
        printf("Decryption doesnt match\n");
        return 0;
    }


    printf("Success!\n\n");
    return 1;
}

