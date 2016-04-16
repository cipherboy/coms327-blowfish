/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Implementation for blowfish in ECB block mode
*/

#include "blowfish.hh"
#include "blowfish_ecb.hh"

#include <cstdlib>


/**
 * Initialize the blowfish sub-keys and s-boxes based off the given key; same
 * as blowfish(); constructor.
 *
 * See /docs/src/blowfish_ecb.txt for more details.
**/
blowfish_ecb::blowfish_ecb(char* key_data,
                           int key_length) : blowfish(key_data, key_length)
{
    // Do nothing but call parent constructor.
}


/**
 * Input length required to be a multiple of 8 (block size), otherwise
 * NULL is returned as output. Returned char* pointer must freed.
 *
 * See /docs/src/blowfish_ecb.txt for more details.
**/
char* blowfish_ecb::block_encrypt(char* data, int data_length)
{
    uint32_t left;
    uint32_t right;
    char* result;
    int i = 0;

    if (data_length % 8 != 0) {
        return NULL;
    }

    result = (char *) malloc(sizeof(char) * data_length);

    /*
        for each 8-byte block to length of input:
            encrypt(block)
            append block to result
    */
    for (i = 0; i < data_length; i+=8) {
        left = ((uint8_t) data[i+0] << 24) + ((uint8_t) data[i+1] << 16) +
               ((uint8_t) data[i+2] << 8) + (uint8_t) data[i+3];
        right = ((uint8_t) data[i+4] << 24) + ((uint8_t) data[i+5] << 16) +
                ((uint8_t) data[i+6] << 8) + (uint8_t) data[i+7];

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


/**
 * Input length required to be a multiple of 8 (block size), otherwise
 * NULL is returned as output. Returned char* pointer must freed.
 *
 * See /docs/src/blowfish_ecb.txt for more details.
**/
char* blowfish_ecb::block_decrypt(char* data, int data_length)
{
    uint32_t left;
    uint32_t right;
    char* result;
    int i = 0;

    if (data_length % 8 != 0) {
        return NULL;
    }


    result = (char *) malloc(sizeof(char) * data_length);

    /*
        for each 8-byte block to length of input:
            decrypt(block)
            append block to result
    */
    for (i = 0; i < data_length; i+=8) {
        left = ((uint8_t) data[i+0] << 24) + ((uint8_t) data[i+1] << 16) +
               ((uint8_t) data[i+2] << 8) + (uint8_t) data[i+3];
        right = ((uint8_t) data[i+4] << 24) + ((uint8_t) data[i+5] << 16) +
                ((uint8_t) data[i+6] << 8) + (uint8_t) data[i+7];

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
