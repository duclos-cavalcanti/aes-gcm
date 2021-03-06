#include "gcm_test.h"

#include "gcm.h"
#include "util.h"

int gcmTest() {

    int ret;

    const uint8_t key[16] =
    {
        0xFE, 0xFF, 0xE9, 0x92,
        0x86, 0x65, 0x73, 0x1C,
        0x6D, 0x6A, 0x8F, 0x94,
        0x67, 0x30, 0x83, 0x08,
    };

    uint8_t plaintext[60] =
    {
        0xD9, 0x31, 0x32, 0x25,
        0xF8, 0x84, 0x06, 0xE5,
        0xA5, 0x59, 0x09, 0xC5,
        0xAF, 0xF5, 0x26, 0x9A,
        0x86, 0xA7, 0xA9, 0x53,
        0x15, 0x34, 0xF7, 0xDA,
        0x2E, 0x4C, 0x30, 0x3D,
        0x8A, 0x31, 0x8A, 0x72,
        0x1C, 0x3C, 0x0C, 0x95,
        0x95, 0x68, 0x09, 0x53,
        0x2F, 0xCF, 0x0E, 0x24,
        0x49, 0xA6, 0xB5, 0x25,
        0xB1, 0x6A, 0xED, 0xF5,
        0xAA, 0x0D, 0xE6, 0x57,
        0xBA, 0x63, 0x7B, 0x39,
    };

    const uint8_t iv[12] =
    {
        0xCA, 0xFE, 0xBA, 0xBE,
        0xFA, 0xCE, 0xDB, 0xAD,
        0xDE, 0xCA, 0xF8, 0x88,
    };

    const uint8_t a[28] =
    {
        0xFE, 0xED, 0xFA, 0xCE,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xFA, 0xCE,
        0xDE, 0xAD, 0xBE, 0xEF,
        0xAB, 0xAD, 0xDA, 0xD2,
    };

    const uint8_t correct_encrypted[] =
    {
        0x42, 0x83, 0x1E, 0xC2,
        0x21, 0x77, 0x74, 0x24,
        0x4B, 0x72, 0x21, 0xB7,
        0x84, 0xD0, 0xD4, 0x9C,
        0xE3, 0xAA, 0x21, 0x2F,
        0x2C, 0x02, 0xA4, 0xE0,
        0x35, 0xC1, 0x7E, 0x23,
        0x29, 0xAC, 0xA1, 0x2E,
        0x21, 0xD5, 0x14, 0xB2,
        0x54, 0x66, 0x93, 0x1C,
        0x7D, 0x8F, 0x6A, 0x5A,
        0xAC, 0x84, 0xAA, 0x05,
        0x1B, 0xA3, 0x0B, 0x39,
        0x6A, 0x0A, 0xAC, 0x97,
        0x3D, 0x58, 0xE0, 0x91,
    };

    const uint8_t correct_tag[] =
    {
        0x5B, 0xC9, 0x4F, 0xBC,
        0x32, 0x21, 0xA5, 0xDB,
        0x94, 0xFA, 0xE9, 0x5A,
        0xE7, 0x12, 0x1A, 0x47,
    };

    gcm_context_t gcm = {
        .plaintext = { 0 },
        .plaintext_size = 0,
        .ciphertext = { 0 },
        .H = { 0 },
        .key = { 0 },
        .iv = { 0 },
        .J0 = { 0 },
        .ICB = { 0 },
        .auth = { 0 },
        .auth_size = 0,
        .tag = { 0 }
    };

    memcpy(gcm.plaintext, plaintext, 60);
    memcpy(gcm.iv, iv, 12);
    memcpy(gcm.key, key, 16);
    memcpy(gcm.auth, a, 20);

    gcm.plaintext_size = 60;
    gcm.auth_size = 20;

    printf( "\n========= GCM =========\n");
    printArray(gcm.plaintext, 60, "Input");

    gcmAesEncrypt(&gcm);

    printArray(gcm.ciphertext, 60, "Encryption");
    printArray(correct_encrypted, 60, "Correct Encryption");

    printArray(gcm.tag, 16, "Tag");
    printArray(correct_tag, 16, "Correct Tag");

    if (!equalArrays(gcm.tag, correct_tag, 16)) {
        printf("Tag doesnt match\n");
        return 0;
    }

    if (!equalArrays(gcm.ciphertext, correct_encrypted, 60)) {
        printf("Encryption doesnt match\n");
        return 0;
    }

    ret = gcmAesDecrypt(&gcm);

    printArray(gcm.plaintext, 60, "Decryption");
    printArray(plaintext, 60, "Correct Decryption");

    printArray(gcm.tag, 16, "Tag");
    printArray(correct_tag, 16, "Correct Tag");
    printf("ret %d\n", ret);

    if (!equalArrays(gcm.plaintext, plaintext, 60)) {
        printf("Decryption doesnt match\n");
        return 0;
    }

    if (!equalArrays(gcm.tag, correct_tag, 16)) {
        printf("Tag doesnt match\n");
        return 0;
    }

    return 1;
}

int gcmTestRobotCommand(){

    int result;

    //key flattened out for use on online Encryption-Decryption platforms
    //05b2cdea86c52d112103dd97f5827ade
    const uint8_t key8[16] =
    {
        0x05, 0xb2, 0xcd, 0xea,
        0x86, 0xc5, 0x2d, 0x11,
        0x21, 0x03, 0xdd, 0x97,
        0xf5, 0x82, 0x7a, 0xde
    };

    //iv flattened out for use on online Encryption-Decryption platforms
    //cafebabefacedbaddecaf888
    const uint8_t iv8[12] =
    {
        0xca, 0xfe, 0xba, 0xbe,
        0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };


    const uint8_t add8[21] =
    {
        0x72, 0x6f, 0x62, 0x6f,
        0x74, 0x43, 0x6f, 0x6e,
        0x74, 0x72, 0x6f, 0x6c,
        0x4d, 0x61, 0x74, 0x65,
        0x72, 0x69, 0x61, 0x6c,
        0x00
    };

    char string[346] = { 0 };
    uint8_t plain8[346] = { 0 };

    //cipertext flattened out for use on online Encryption-Decryption platforms
    //59326c404b3b7273bde647e4cedd710ce83a5c342a2730425925590d69650de21ed5bfd69b48472e01a3a56263298b7a7bcc342ddc9fd7e8824a8a89cc6a61ef762d77ae439a7b12b1ace8b5fb6e3daa61f668f588bc52fd6cc89e399e2d2d470aaa2e6666d8603abdcdc338c8e12139386cecd484cd62a8b36dfe7192c397f1ecc0fd444a61047c90e079c3beb41426e1e600cb830436c30b6fe0938a4328c0f4c43579a4ffb7450c0ae0f0418e9a261ce54fbc7718e77a5c329f13c614c6993c70a1c68b11f0e8e33b8ba1240cb83075e1f5d3ced8326fb22e8bd07fa20c0accdfc28d90170d7d06ff243fbec7601ef10a46d15a487e9449ff3ba06415f7ef94f3773e2bbd3a45b1bc67c93e6fa6f266e72227e178147b7d1187f071e1646c783cf9622181bff39e1bddad7e19a2072a3f89bdd5b33b2c0ad71faa8171f8edead44ad0cfc38170ad7602edeba7909463690f5a12092c1cab41
    uint8_t cipher8[346] =
    {
        0x59, 0x32, 0x6c, 0x40,
        0x4b, 0x3b, 0x72, 0x73,
        0xbd, 0xe6, 0x47, 0xe4,
        0xce, 0xdd, 0x71, 0x0c,
        0xe8, 0x3a, 0x5c, 0x34,
        0x2a, 0x27, 0x30, 0x42,
        0x59, 0x25, 0x59, 0x0d,
        0x69, 0x65, 0x0d, 0xe2,
        0x1e, 0xd5, 0xbf, 0xd6,
        0x9b, 0x48, 0x47, 0x2e,
        0x01, 0xa3, 0xa5, 0x62,
        0x63, 0x29, 0x8b, 0x7a,
        0x7b, 0xcc, 0x34, 0x2d,
        0xdc, 0x9f, 0xd7, 0xe8,
        0x82, 0x4a, 0x8a, 0x89,
        0xcc, 0x6a, 0x61, 0xef,
        0x76, 0x2d, 0x77, 0xae,
        0x43, 0x9a, 0x7b, 0x12,
        0xb1, 0xac, 0xe8, 0xb5,
        0xfb, 0x6e, 0x3d, 0xaa,
        0x61, 0xf6, 0x68, 0xf5,
        0x88, 0xbc, 0x52, 0xfd,
        0x6c, 0xc8, 0x9e, 0x39,
        0x9e, 0x2d, 0x2d, 0x47,
        0x0a, 0xaa, 0x2e, 0x66,
        0x66, 0xd8, 0x60, 0x3a,
        0xbd, 0xcd, 0xc3, 0x38,
        0xc8, 0xe1, 0x21, 0x39,
        0x38, 0x6c, 0xec, 0xd4,
        0x84, 0xcd, 0x62, 0xa8,
        0xb3, 0x6d, 0xfe, 0x71,
        0x92, 0xc3, 0x97, 0xf1,
        0xec, 0xc0, 0xfd, 0x44,
        0x4a, 0x61, 0x04, 0x7c,
        0x90, 0xe0, 0x79, 0xc3,
        0xbe, 0xb4, 0x14, 0x26,
        0xe1, 0xe6, 0x00, 0xcb,
        0x83, 0x04, 0x36, 0xc3,
        0x0b, 0x6f, 0xe0, 0x93,
        0x8a, 0x43, 0x28, 0xc0,
        0xf4, 0xc4, 0x35, 0x79,
        0xa4, 0xff, 0xb7, 0x45,
        0x0c, 0x0a, 0xe0, 0xf0,
        0x41, 0x8e, 0x9a, 0x26,
        0x1c, 0xe5, 0x4f, 0xbc,
        0x77, 0x18, 0xe7, 0x7a,
        0x5c, 0x32, 0x9f, 0x13,
        0xc6, 0x14, 0xc6, 0x99,
        0x3c, 0x70, 0xa1, 0xc6,
        0x8b, 0x11, 0xf0, 0xe8,
        0xe3, 0x3b, 0x8b, 0xa1,
        0x24, 0x0c, 0xb8, 0x30,
        0x75, 0xe1, 0xf5, 0xd3,
        0xce, 0xd8, 0x32, 0x6f,
        0xb2, 0x2e, 0x8b, 0xd0,
        0x7f, 0xa2, 0x0c, 0x0a,
        0xcc, 0xdf, 0xc2, 0x8d,
        0x90, 0x17, 0x0d, 0x7d,
        0x06, 0xff, 0x24, 0x3f,
        0xbe, 0xc7, 0x60, 0x1e,
        0xf1, 0x0a, 0x46, 0xd1,
        0x5a, 0x48, 0x7e, 0x94,
        0x49, 0xff, 0x3b, 0xa0,
        0x64, 0x15, 0xf7, 0xef,
        0x94, 0xf3, 0x77, 0x3e,
        0x2b, 0xbd, 0x3a, 0x45,
        0xb1, 0xbc, 0x67, 0xc9,
        0x3e, 0x6f, 0xa6, 0xf2,
        0x66, 0xe7, 0x22, 0x27,
        0xe1, 0x78, 0x14, 0x7b,
        0x7d, 0x11, 0x87, 0xf0,
        0x71, 0xe1, 0x64, 0x6c,
        0x78, 0x3c, 0xf9, 0x62,
        0x21, 0x81, 0xbf, 0xf3,
        0x9e, 0x1b, 0xdd, 0xad,
        0x7e, 0x19, 0xa2, 0x07,
        0x2a, 0x3f, 0x89, 0xbd,
        0xd5, 0xb3, 0x3b, 0x2c,
        0x0a, 0xd7, 0x1f, 0xaa,
        0x81, 0x71, 0xf8, 0xed,
        0xea, 0xd4, 0x4a, 0xd0,
        0xcf, 0xc3, 0x81, 0x70,
        0xad, 0x76, 0x02, 0xed,
        0xeb, 0xa7, 0x90, 0x94,
        0x63, 0x69, 0x0f, 0x5a,
        0x12, 0x09, 0x2c, 0x1c,
        0xab, 0x41
    };

    const uint8_t tag8[16] =
    {
        0xc3, 0x14, 0x62, 0x1e,
        0xa2, 0x71, 0xe0, 0x4c,
        0x65, 0x4f, 0xbb, 0x26,
        0x71, 0xae, 0x5a, 0x9a
    };

    gcm_context_t gcm = {
        .plaintext = { 0 },
        .plaintext_size = 0,
        .ciphertext = { 0 },
        .H = { 0 },
        .key = { 0 },
        .iv = { 0 },
        .J0 = { 0 },
        .ICB = { 0 },
        .auth = { 0 },
        .auth_size = 0,
        .tag = { 0 }
    };

    memcpy(gcm.ciphertext, cipher8, 346);
    memcpy(gcm.key, key8, 16);
    memcpy(gcm.iv, iv8, 12);
    memcpy(gcm.auth, add8, 21);

    gcm.plaintext_size = 346;
    gcm.auth_size = 21;

    gcmAesDecrypt(&gcm);

    printArray(gcm.plaintext, 346, "Decryption");

    printArray(gcm.tag, 16, "Tag");
    printArray(tag8, 16, "Correct Tag");

    if (!equalArrays(gcm.tag, tag8, 16)) {
        printf("Tag doesnt match\n");
        return 0;
    }

    printf("Tags match\n");

    formatArrayString(gcm.plaintext, 346, string);
    printf("Text: \n%s\n\n", string);

    return 1;
}

int gcmLedTest() {

  int result;

  gcm_context_t gcm = {
      .plaintext = { 0 },
      .plaintext_size = 0,
      .ciphertext = { 0 },
      .H = { 0 },
      .key = {
        0xAD, 0x7A, 0x2B, 0xD0,
        0x3E, 0xAC, 0x83, 0x5A,
        0x6F, 0x62, 0x0F, 0xDC,
        0xB5, 0x06, 0xB3, 0x45,
      },
      .iv = {
        0x00, 0x06, 0x35, 0x24,
        0xC0, 0x89, 0x5E, 0x81,
        0xB2, 0xC2, 0x84, 0x65,
      },
      .J0 = { 0 },
      .ICB = { 0 },
      .auth = {
        0xD6, 0x09, 0xB1, 0xF0,
        0x56, 0x63, 0x7A, 0x0D,
        0x46, 0xDF, 0x99, 0x8D,
        0x88, 0xE5, 0x2E, 0x00,
        0xB2, 0xC2, 0x84, 0x65,
        0x12, 0x15, 0x35, 0x24,
        0xC0, 0x89, 0x5E, 0x81,
      },
      .auth_size = 28,
      .tag = { 0 }
  };

    uint8_t LED_ON[6] = { 0x4c,  0x45,  0x44,  0x5f,  0x4f,  0x4E };

    printf( "\n========= LED ON =========\n");
    memcpy(gcm.plaintext, LED_ON, 6);
    printArray(gcm.plaintext, 6, "Input");

    gcm.plaintext_size = 6;
    gcmAesEncrypt(&gcm);

    printArray(gcm.ciphertext, 6, "Enc");

    printArray(gcm.tag, 16, "Tag");

    result = gcmAesDecrypt(&gcm);

    printArray(gcm.plaintext, 6, "DEC");

    if (!equalArrays(gcm.plaintext, LED_ON, 6)) {
        printf("Decryption doesnt match\n");
        return 0;
    }

    return 1;
}
