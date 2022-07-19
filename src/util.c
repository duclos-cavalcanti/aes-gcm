#include "util.h"

void printArray(const uint8_t* arr, int size, char* header) {
    printf("-- %s --\n", header);
    for (int i = 0; i < size; i++) {
        if (i % 4 == 0) {
            if (i == 0)
                printf("[ ");
            else
                printf("  ");
        }

        printf("0x%02x", arr[i]);

        if ((i + 1) % 4 == 0) {
            if ((i + 1) != size)
                printf(",\n");
            else
                printf(" ]\n");
        } else {
            printf(", ");
        }
    }
    printf("\n");
}

void formatArray(const uint8_t* arr, int size, char* buf) {
    char* str = buf;
    for (int i = 0; i < size; i++) {
        if (i == 0) {           // first byte
            if (size >= 8) {
                sprintf(str, "\n\r[");
                str += 3;
            } else {
                sprintf(str, "[ ");
                str += 2;
            }
        } else {
            sprintf(str, "  ");
            str += 2;
        }

        sprintf(str, "0x%02x", arr[i]);
        str += 4;

       if (i == size - 1) {     // last byte
            if (size >= 8) {
                sprintf(str, "]\r\n");
                str += 3;
            } else {
                sprintf(str, "]");
                str += 1;
            }
        } else {
            if (size >= 8 && (i + 1) % 4 == 0) {
                sprintf(str, ",\r\n");
                str += 3;
            } else {
                sprintf(str, ",");
                str += 1;
            }
        }
    }
}

void formatArrayString(const uint8_t* arr, int size, char* buf) {
    char* str = buf;
    for (int i = 0; i < size; i++) {
        sprintf(str, "%c", arr[i]);
        str += 1;

        if (i == size - 1) { // last byte
            sprintf(str, "\r\n");
            str += 2;
        }
    }
}

int equalArrays(const uint8_t* a, const uint8_t* b, int size) {
    for (int i = 0; i < size; i++) {
        if (a[i] != b[i])
            return 0;
    }

    return 1;
}

void resetArray(uint8_t* a, const uint8_t val, int size) {
    for (int i = 0; i < size; i++) {
        a[i] = val;
    }
}
