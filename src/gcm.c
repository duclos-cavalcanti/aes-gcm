#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "gcm.h"

void gcmAesEncrypt(uint8_t *input, const size_t input_size,
                   const uint8_t *key, const uint8_t *iv,
                   const uint8_t *auth, const size_t auth_size,
                   uint8_t *output, uint8_t *tag);

const uint8_t R[16] = {
    0xe1, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

const uint8_t zero[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

const uint64_t msb = 0x80;
const uint64_t lsb = 0x01;

uint8_t table[16][256][16] = {};

typedef struct {
    int round;
    int last;
    uint8_t tag[16];
    uint8_t H[16];
} gcm_context_t;

void flipHalfBlock(uint8_t* buf) {
    uint8_t tmp[4];
    memcpy(tmp, buf, 4);

    tmp[0] = buf[3];
    tmp[1] = buf[2];
    tmp[2] = buf[1];
    tmp[3] = buf[0];

    memcpy(buf, tmp, 4);
}

void flipBlock(uint8_t* buf) {
    uint8_t tmp[8];
    memcpy(tmp, buf, 8);

    tmp[0] = buf[7];
    tmp[1] = buf[6];
    tmp[2] = buf[5];
    tmp[3] = buf[4];
    tmp[4] = buf[3];
    tmp[5] = buf[2];
    tmp[6] = buf[1];
    tmp[7] = buf[0];

    memcpy(buf, tmp, 8);
}

void multiplyBlocks(const uint8_t *x, const uint8_t *y, uint8_t *res) {
    for (int i = 0; i < 16; i++) {
        res[i] = x[i] * y[i];
    }
}

void xorBlocks(const uint8_t *x, const uint8_t *y, uint8_t *res) {
    for (int i = 0; i < 16; i++) {
        res[i] = x[i] ^ y[i];
    }
}

void shiftBlockRight(const uint8_t *b, uint8_t *res) {
    uint8_t tmp[16];
    uint8_t bit, last_bit;
    memcpy(tmp, b, 16);
    for (int i = 0; i < 16; ++i) {
        if (i > 0) {
            bit = (msb & (tmp[i] << 7));
            tmp[i] = last_bit | (tmp[i] >> 1);
            last_bit = bit;
        } else {
            bit = (msb & (tmp[i] << 7));
            tmp[i] >>= 1;
            last_bit = bit;
        }
    }
    memcpy(res, tmp, 16);
}

void shiftBlockLeft(const uint8_t *b, uint8_t *res) {
    uint8_t tmp[16];
    uint8_t bit, last_bit;
    memcpy(tmp, b, 16);
    for (int i = 0; i < 16; ++i) {
        if (i > 0) {
            bit = (msb & tmp[i]);
            tmp[i] = (tmp[i] << 1) | last_bit;
            last_bit = bit;
        } else {
            bit = (msb & tmp[i]);
            tmp[i] <<= 1;
            last_bit = bit;
        }
    }
    memcpy(res, tmp, 16);
}

void shiftBlockRightMultiple(const uint8_t *b, uint8_t *res, int n) {
    for (int i = 0; i < n; ++i) {
        shiftBlockRight(res, res);
    }
}

void gcmMultiply(const uint8_t *x, const uint8_t *y, uint8_t *res) {
    uint8_t V[16] = { 0 }, Z[16] = { 0 };
    int i, j;
    memcpy(V, y, 16);
    for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & 1 << (7 - j)) {
                /* Z_(i + 1) = Z_i XOR V_i */
				xorBlocks(Z, V ,Z);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (V[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shiftBlockRight(V, V);
				/* R = 11100001 || 0^120 */
				V[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shiftBlockRight(V, V);
			}
		}
	}
    memcpy(res, Z, 16);
}

// unfinished
void gcmGenTables(const uint8_t *H) {
    uint16_t J;
    uint8_t res[16];
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 256; j++) {
            J = j << (8 * i);
            gcmMultiply(H, &J, res);
            memcpy(table[i][j], res, 16);
        }
    }
}

void gcmInitializeJ(uint8_t *J, const uint8_t *iv) {
    const uint8_t one[4] = { 0x00, 0x00, 0x00, 0x01};
    memcpy(J, iv, 12);
    memcpy(J + 12, one, 4);
}

void gcmGenerateHashKey(gcm_context_t* context, const uint8_t *key) {
    aesEncrypt(zero, key, context->H); // generate hash subkey
}

void gcmHash(const uint8_t* auth, size_t auth_size,
             const uint8_t* cipher, size_t cipher_size,
             gcm_context_t* context) {

    static uint8_t pre_tag[16] = { 0 };
    static uint8_t lengths[16] = { 0 };

    if (context->round == 0) {
        xorBlocks(zero, auth, pre_tag);
        gcmMultiply(pre_tag, context->H, pre_tag);

    } else if (context->round == context->last) {
        uint64_t a_size = auth_size * 8;
        uint64_t c_size = cipher_size * 8;

        memcpy(lengths, &a_size, 8);
        flipBlock(lengths);

        memcpy(lengths + 8, &c_size, 8);
        flipBlock(lengths + 8);

        xorBlocks(pre_tag, cipher, pre_tag);
        gcmMultiply(pre_tag, context->H, pre_tag);

        xorBlocks(pre_tag, lengths, pre_tag);
        gcmMultiply(pre_tag, context->H, pre_tag);

        memcpy(context->tag, pre_tag, 16);
    } else {
        xorBlocks(pre_tag, cipher, pre_tag);
        gcmMultiply(pre_tag, context->H, pre_tag);
    }
}

void gcmInitializeCounter(uint8_t* counter, const uint8_t* J) {
    memcpy(counter, J,  16);
}

void gcmIncrement(uint8_t *counter) {
    uint32_t iter = 0;
    memcpy(&iter, counter + 12, 4);
    iter++;
    memcpy(counter + 12, &iter, 4);
}

void gcmGCTR(uint8_t* plaintext, uint8_t plaintext_size,
                 const uint8_t *key, const uint8_t *ICB,
                 uint8_t* ciphertext) {
    uint8_t tmp[16] = { 0 };
    uint8_t counter[16] = { 0 };

    uint8_t n = (plaintext_size % 16 == 0) ? plaintext_size / 16 : plaintext_size / 16 + 1;
    uint8_t rem = plaintext_size % 16;

    gcmInitializeCounter(counter, ICB);

    for (int i = 1; i < n; i++) {
        if (i >= 2)
            gcmIncrement(counter);

        aesEncrypt(counter, key, tmp);
        xorBlocks(tmp, plaintext + (i - 1)*16, tmp);
        memcpy(ciphertext + (i - 1)*16, tmp, 16);
    }

    aesEncrypt(counter, key, tmp);
    xorBlocks(tmp, plaintext + (n - 1)*16, tmp);
    memcpy(ciphertext + (n - 1)*16, tmp, rem);
}

void gcmAesEncrypt(uint8_t *input, const size_t input_size,
                   const uint8_t *key, const uint8_t *iv,
                   const uint8_t *auth, const size_t auth_size,
                   uint8_t *output, uint8_t *tag) {

    uint8_t cipher[16], counter_enc[16], J[16];
    uint8_t counter[16] = { 0 };

    gcm_context_t context = {
            .round = 0,
            .last = (input_size % 16 == 0) ? input_size / 16 : input_size / 16 + 1,
    };

    gcmGenerateHashKey(&context, key);
    gcmInitializeJ(J, iv);
    gcmInitializeCounter(counter, iv);

    gcmIncrement(counter);
    aesEncrypt(counter, key, J);
    gcmHash(auth, auth_size, cipher, input_size, &context);

    for (context.round = 1; context.round < context.last + 1; context.round++) {
        gcmIncrement(counter);
        aesEncrypt(counter, key, counter_enc);
        xorBlocks(counter_enc, input + (context.round - 1)*16, cipher);

        if (context.round == context.last) {
            gcmHash(auth, auth_size, cipher, input_size, &context);

            memcpy(tag, context.tag, 16);
            xorBlocks(tag, J, tag);
        } else {
            gcmHash(auth, auth_size, cipher, input_size, &context);
        }
        memcpy(output + (context.round - 1) * 16, cipher, 16);
    }
}

int gcmAesDecrypt(const uint8_t *cipher, const size_t cipher_size,
                  const uint8_t *key, const uint8_t *iv,
                  const uint8_t *auth, const size_t auth_size,
                  uint8_t *output, const uint8_t *tag) {

    uint8_t plain[16], counter_enc[16], J[16];
    uint8_t counter[16] = { 0 };

    gcm_context_t context = {
            .round = 0,
            .last = (cipher_size % 16 == 0) ? cipher_size / 16 : cipher_size / 16 + 1,
    };

    gcmGenerateHashKey(&context, key);
    gcmInitializeJ(J, iv);
    gcmInitializeCounter(counter, J);

    gcmIncrement(counter);
    aesEncrypt(counter, key, J);
    gcmHash(auth, auth_size, cipher, cipher_size, &context);

    for (context.round = 1; context.round < context.last + 1; context.round++) {
        gcmIncrement(counter);
        aesEncrypt(counter, key, counter_enc);
        xorBlocks(counter_enc, cipher + (context.round - 1)*16, plain);

        if (context.round == context.last) {
            gcmHash(auth, auth_size, cipher + (context.round - 1)*16, cipher_size, &context);

            xorBlocks(context.tag, J, context.tag);
        } else {
            gcmHash(auth, auth_size, cipher + (context.round - 1)*16, cipher_size, &context);
        }
        memcpy(output + (context.round - 1) * 16, plain, 16);
    }

    if (memcmp(tag, context.tag, 16) != 0)
        return -1;
    else
        return 0;
}

