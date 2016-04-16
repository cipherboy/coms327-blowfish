/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Implementation for blowfish in CBC block mode
*/

#include "blowfish.hh"
#include "blowfish_cbc.hh"

#include <cstdlib>

blowfish_cbc::blowfish_cbc(char* key_data,
                           int key_length) : blowfish(key_data, key_length)
{
}

char* blowfish_cbc::block_encrypt(char* data, char* iv, int data_length)
{
    if (data_length % 8 != 0) {
        // TODO: throw error
        return NULL;
    }

    uint32_t left;
    uint32_t right;
    uint32_t last_left;
    uint32_t last_right;
    char* result;
    int i = 0;

    result = (char *) malloc(sizeof(char) * data_length);

    last_left = ((uint8_t) iv[0] << 24) + ((uint8_t) iv[1] << 16) + ((
                    uint8_t) iv[2] << 8) + (uint8_t) iv[3];
    last_right = ((uint8_t) iv[4] << 24) + ((uint8_t) iv[5] << 16) + ((
                     uint8_t) iv[6] << 8) + (uint8_t) iv[7];

    for (i = 0; i < data_length; i+=8) {
        left = ((uint8_t) data[i+0] << 24) + ((uint8_t) data[i+1] << 16) + ((
                    uint8_t) data[i+2] << 8) + (uint8_t) data[i+3];
        right = ((uint8_t) data[i+4] << 24) + ((uint8_t) data[i+5] << 16) + ((
                    uint8_t) data[i+6] << 8) + (uint8_t) data[i+7];

        left = left ^ last_left;
        right = right ^ last_right;

        this->encrypt(&left, &right);

        last_left = left;
        last_right = right;

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

char* blowfish_cbc::block_decrypt(char* data, char* iv, int data_length)
{
    if (data_length % 8 != 0) {
        // TODO: throw error
        return NULL;
    }

    uint32_t left;
    uint32_t right;
    uint32_t save_left;
    uint32_t save_right;
    uint32_t last_left;
    uint32_t last_right;
    char* result;
    int i = 0;

    result = (char *) malloc(sizeof(char) * data_length);

    last_left = ((uint8_t) iv[0] << 24) + ((uint8_t) iv[1] << 16) + ((
                    uint8_t) iv[2] << 8) + (uint8_t) iv[3];
    last_right = ((uint8_t) iv[4] << 24) + ((uint8_t) iv[5] << 16) + ((
                     uint8_t) iv[6] << 8) + (uint8_t) iv[7];

    for (i = 0; i < data_length; i+=8) {
        left = ((uint8_t) data[i+0] << 24) + ((uint8_t) data[i+1] << 16) + ((
                    uint8_t) data[i+2] << 8) + (uint8_t) data[i+3];
        right = ((uint8_t) data[i+4] << 24) + ((uint8_t) data[i+5] << 16) + ((
                    uint8_t) data[i+6] << 8) + (uint8_t) data[i+7];

        save_left = left;
        save_right = right;

        this->decrypt(&left, &right);

        left = left ^ last_left;
        right = right ^ last_right;

        last_left = save_left;
        last_right = save_right;

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
