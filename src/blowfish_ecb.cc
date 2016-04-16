/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Implementation for blowfish in ECB block mode
*/

#include "blowfish.hh"
#include "blowfish_ecb.hh"

#include <cstdlib>

blowfish_ecb::blowfish_ecb(char* key_data,
                           int key_length) : blowfish(key_data, key_length)
{
}

char* blowfish_ecb::block_encrypt(char* data, int data_length)
{
    if (data_length % 8 != 0) {
        // TODO: throw error
        return NULL;
    }

    uint32_t left;
    uint32_t right;
    char* result;
    int i = 0;

    result = (char *) malloc(sizeof(char) * data_length);

    for (i = 0; i < data_length; i+=8) {
        left = ((uint8_t) data[i+0] << 24) + ((uint8_t) data[i+1] << 16) + ((
                    uint8_t) data[i+2] << 8) + (uint8_t) data[i+3];
        right = ((uint8_t) data[i+4] << 24) + ((uint8_t) data[i+5] << 16) + ((
                    uint8_t) data[i+6] << 8) + (uint8_t) data[i+7];

        this->encrypt(&left, &right);

        result[i+0] = (left & 0xFF000000) >> 24;
        result[i+1] = (left & 0x00FF0000) >> 16;
        result[i+2] = (left & 0x0000FF00) >> 8;
        result[i+3] = left & 0x000000FF;
        result[i+4] = (right & 0xFF000000) >> 24;
        result[i+5] = (right & 0x00FF0000) >> 16;
        result[i+6] = (right & 0x0000FF00) >> 8;
        result[i+7] = right & 0x000000FF;
    }
    return result;

}

char* blowfish_ecb::block_decrypt(char* data, int data_length)
{
    if (data_length % 8 != 0) {
        // TODO: throw error
        return NULL;
    }

    uint32_t left;
    uint32_t right;
    char* result;
    int i = 0;

    result = (char *) malloc(sizeof(char) * data_length);

    for (i = 0; i < data_length; i+=8) {
        left = ((uint8_t) data[i+0] << 24) + ((uint8_t) data[i+1] << 16) + ((
                    uint8_t) data[i+2] << 8) + (uint8_t) data[i+3];
        right = ((uint8_t) data[i+4] << 24) + ((uint8_t) data[i+5] << 16) + ((
                    uint8_t) data[i+6] << 8) + (uint8_t) data[i+7];

        this->decrypt(&left, &right);

        result[i+0] = (left & 0xFF000000) >> 24;
        result[i+1] = (left & 0x00FF0000) >> 16;
        result[i+2] = (left & 0x0000FF00) >> 8;
        result[i+3] = left & 0x000000FF;
        result[i+4] = (right & 0xFF000000) >> 24;
        result[i+5] = (right & 0x00FF0000) >> 16;
        result[i+6] = (right & 0x0000FF00) >> 8;
        result[i+7] = right & 0x000000FF;
    }

    return result;
}
