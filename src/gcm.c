#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "gcm.h"

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

void gcmInitializeHashKey(uint8_t *H, const uint8_t *key) {
    aesEncrypt(zero, key, H); // generate hash subkey
}

void gcmInitializeJ(uint8_t *J, const uint8_t *iv) {
    const uint8_t one[4] = { 0x00, 0x00, 0x00, 0x01};

    memcpy(J, iv, 12);      // 96 bits
    memcpy(J + 12, one, 4); // 32 bits
}

void gcmInitializeCounter(uint8_t* counter, const uint8_t* J) {
    memcpy(counter, J,  16);
}

void gcmIncrement(uint8_t *counter, uint8_t *res) {
    uint32_t iter = 0;
    memcpy(&iter, counter + 12, 4);
    iter++;
    memcpy(res, counter, 12);
    memcpy(res + 12, &iter, 4);
}

void gcmPreGHASH(gcm_context_t *gcm, uint8_t *X, size_t* X_size) {
    size_t c_rem = gcm->plaintext_size % 16;
    size_t a_rem = gcm->auth_size % 16;
    uint64_t a_size = gcm->auth_size, c_size = gcm->plaintext_size;

    memcpy(X, gcm->auth, gcm->auth_size);
    *X_size += gcm->auth_size;

    if (a_rem > 0) {
        memcpy(X + *X_size, zero, a_rem);
        *X_size += a_rem;
    }

    memcpy(X + *X_size, gcm->ciphertext, gcm->plaintext_size);
    *X_size += gcm->plaintext_size;
    if (c_rem > 0) {
        memcpy(X + *X_size, zero, c_rem);
        *X_size += c_rem;
    }

    memcpy(X + *X_size, &a_size, 64);
    *X_size += 64;

    memcpy(X + *X_size, &c_size, 64);
    *X_size += 64;
}

void gcmGHASH(gcm_context_t *gcm, uint8_t *X, const size_t X_size, uint8_t* data) {
    uint8_t y_[16] = { 0 };
    uint8_t tmp[16] = { 0 };

    uint8_t n = (X_size % 16 == 0) ?
                 X_size / 16 :
                 X_size / 16 + 1;
    for (int i = 0; i < n; ++i) {
        if (i == 0)
            xorBlocks(X, zero, tmp);
        else
            xorBlocks(X + (16 * i), y_, tmp);

        gcmMultiply(tmp, gcm->H, tmp);
        memcpy(y_, tmp, 16);
    }
    memcpy(data, tmp, 16);
}

void gcmGCTREncrypt(uint8_t* input, uint8_t input_size,
                    const uint8_t *key, const uint8_t *ICB,
                    uint8_t* output) {
    uint8_t tmp[16] = { 0 };
    uint8_t counter[16] = { 0 };

    uint8_t n = (input_size % 16 == 0) ? input_size / 16 : input_size / 16 + 1;
    uint8_t rem = input_size % 16;

    gcmInitializeCounter(counter, ICB); // CB1 = ICB

    for (int i = 1; i < n; i++) {
        if (i >= 2)
            gcmIncrement(counter, counter);

        aesEncrypt(counter, key, tmp);
        xorBlocks(tmp, input + (i - 1)*16, tmp);
        memcpy(output + (i - 1)*16, tmp, 16);
    }

    aesEncrypt(counter, key, tmp);
    xorBlocks(tmp, input + (n - 1)*16, tmp);
    memcpy(output + (n - 1)*16, tmp, rem);
}

void gcmGCTRDecrypt(uint8_t* input, uint8_t input_size,
                    const uint8_t *key, const uint8_t *ICB,
                    uint8_t* output) {
    uint8_t tmp[16] = { 0 };
    uint8_t counter[16] = { 0 };

    uint8_t n = (input_size % 16 == 0) ? input_size / 16 : input_size / 16 + 1;
    uint8_t rem = input_size % 16;

    gcmInitializeCounter(counter, ICB); // CB1 = ICB

    for (int i = 1; i < n; i++) {
        if (i >= 2)
            gcmIncrement(counter, counter);

        aesDecrypt(counter, key, tmp);
        xorBlocks(tmp, input + (i - 1)*16, tmp);
        memcpy(output + (i - 1)*16, tmp, 16);
    }

    aesDecrypt(counter, key, tmp);
    xorBlocks(tmp, input + (n - 1)*16, tmp);
    memcpy(output + (n - 1)*16, tmp, rem);
}

// LIMITATIONS
// maximum size of plaintext + authentication = 1000 Bytes!
// ciphertext in struct has to have some size!
void gcmAesEncrypt(gcm_context_t *gcm) {

    uint8_t data[16] = { 0 };
    uint8_t X[1000] = { 0 };
    size_t X_size = 0;

    gcmInitializeHashKey(gcm->H, gcm->key);   // Hash key is encypted 0 (128 bits)
    gcmInitializeJ(gcm->J0, gcm->iv);         // Jo = IV || 0 (31 bits) || 1
    gcmIncrement(gcm->J0, gcm->ICB);


    gcmGCTREncrypt(gcm->plaintext,
                   gcm->plaintext_size,
                   gcm->key,
                   gcm->ICB,
                   gcm->ciphertext);

    gcmPreGHASH(gcm, X, &X_size);
    gcmGHASH(gcm, X, X_size, data);

    gcmGCTREncrypt(data,
                   16,
                   gcm->key,
                   gcm->J0,
                   data);

    // assuming tag size is 16 bytes
    memcpy(gcm->tag, data, 16);
}

int gcmAesDecrypt(gcm_context_t *gcm) {

    uint8_t data[16] = { 0 };
    uint8_t X[1000] = { 0 };
    size_t X_size = 0;

    gcmInitializeHashKey(gcm->H, gcm->key);   // Hash key is encypted 0 (128 bits)
    gcmInitializeJ(gcm->J0, gcm->iv);         // Jo = IV || 0 (31 bits) || 1
    gcmIncrement(gcm->J0, gcm->ICB);


    gcmGCTREncrypt(gcm->ciphertext,
                   gcm->plaintext_size,
                   gcm->key,
                   gcm->ICB,
                   gcm->plaintext);

    gcmPreGHASH(gcm, X, &X_size);
    gcmGHASH(gcm, X, X_size, data);

    gcmGCTREncrypt(data,
                   16,
                   gcm->key,
                   gcm->J0,
                   data);

    // assuming tag size is 16 bytes
    if (memcmp(data, gcm->tag, 16) != 0)
        return -1;
    else
        return 0;
}
