/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Implement for blowfish cryptographic primitive
*/

#include "blowfish.hh"
#include "blowfish_ecb.hh"

#include <stdio.h>
#include <cstdlib>

blowfish_ecb::blowfish_ecb(char* key_data, int key_length) : blowfish(key_data, key_length)
{
}

char* blowfish_ecb::block_encrypt(char* data, int data_length)
{
    uint32_t left;
    uint32_t right;
    char* result;

    result = (char *) malloc(sizeof(char) * 8);

    left = ((uint8_t) data[0] << 24) + ((uint8_t) data[1] << 16) + ((uint8_t) data[2] << 8) + (uint8_t) data[3];
    right = ((uint8_t) data[4] << 24) + ((uint8_t) data[5] << 16) + ((uint8_t) data[6] << 8) + (uint8_t) data[7];

    this->encrypt(&left, &right);

    result[0] = (left & 0xFF000000) >> 24;
    result[1] = (left & 0x00FF0000) >> 16;
    result[2] = (left & 0x0000FF00) >> 8;
    result[3] = left & 0x000000FF;
    result[4] = (right & 0xFF000000) >> 24;
    result[5] = (right & 0x00FF0000) >> 16;
    result[6] = (right & 0x0000FF00) >> 8;
    result[7] = right & 0x000000FF;
    return result;

}

char* blowfish_ecb::block_decrypt(char* data, int data_length)
{
    uint32_t left;
    uint32_t right;
    char* result;

    result = (char *) malloc(sizeof(char) * 8);

    left = ((uint8_t) data[0] << 24) + ((uint8_t) data[1] << 16) + ((uint8_t) data[2] << 8) + (uint8_t) data[3];
    right = ((uint8_t) data[4] << 24) + ((uint8_t) data[5] << 16) + ((uint8_t) data[6] << 8) + (uint8_t) data[7];

    this->decrypt(&left, &right);

    result[0] = (left & 0xFF000000) >> 24;
    result[1] = (left & 0x00FF0000) >> 16;
    result[2] = (left & 0x0000FF00) >> 8;
    result[3] = left & 0x000000FF;
    result[4] = (right & 0xFF000000) >> 24;
    result[5] = (right & 0x00FF0000) >> 16;
    result[6] = (right & 0x0000FF00) >> 8;
    result[7] = right & 0x000000FF;

    return result;
}
