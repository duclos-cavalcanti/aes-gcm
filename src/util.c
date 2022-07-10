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

int equalArrays(const uint8_t* a, const uint8_t* b, int size) {
    for (int i = 0; i < size; i++) {
        if (a[i] != b[i])
            return 0;
    }

    return 1;
}

