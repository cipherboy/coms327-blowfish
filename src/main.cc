/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * main method
*/

#include "blowfish.h"

#include <cstdint>
#include "stdio.h"

using namespace std;

int main(int argc, char* argv[])
{
    char data[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};

    uint64_t temp = *((uint64_t *) &data);

    uint8_t b[4];
    b[3] = (uint8_t) (temp >>  0u);
    b[2] = (uint8_t) (temp >>  8u);
    b[1] = (uint8_t) (temp >> 16u);
    b[0] = (uint8_t) (temp >> 24u);
    uint32_t left = *((uint32_t*) &b);

    b[3] = (uint8_t) (temp >> 32u);
    b[2] = (uint8_t) (temp >> 40u);
    b[1] = (uint8_t) (temp >> 48u);
    b[0] = (uint8_t) (temp >> 56u);
    uint32_t right = *((uint32_t*) &b);

    printf("%u, %u\n", left, right);

    char file[4] = {0x24, 0x3f, 0x6a, 0x88};
    uint32_t d = *((uint32_t *) &file);
    uint32_t e = 0;
    e = ((d & 0xFF000000) >> 24) |
        ((d & 0x00FF0000) >>  8) |
        ((d & 0x0000FF00) <<  8) |
        ((d & 0x000000FF) << 24);
    uint32_t f = 0x243f6a88;

    printf("%u, %u, %u\n", d, e, f);
}
