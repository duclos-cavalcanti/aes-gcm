#include <stdio.h>
#include <stdint.h>

void printArray(const uint8_t* arr, int size, char* header);

void formatArray(const uint8_t* arr, int size, char* buf);

void formatArrayString(const uint8_t* arr, int size, char* buf);

int equalArrays(const uint8_t* a, const uint8_t* b, int size);

void resetArray(uint8_t* a, const uint8_t val, int size);
