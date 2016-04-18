/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Implementation for blowfish in CBC block mode
*/

#include "blowfish.hh"
#include "blowfish_cbc.hh"

#include <cstdlib>
#include <cstring>
#include <string>


/**
 * Initialize the blowfish sub-keys and s-boxes based off the given key; same
 * as blowfish(); constructor.
 *
 * See /docs/src/blowfish_cbc.txt for more details.
**/
blowfish_cbc::blowfish_cbc(std::string key) : blowfish_cbc(key.c_str(),
            key.length())
{
}


/**
 * Initialize the blowfish sub-keys and s-boxes based off the given key; same
 * as blowfish(); constructor.
 *
 * See /docs/src/blowfish_cbc.txt for more details.
**/
blowfish_cbc::blowfish_cbc(const char* key_data,
                           int key_length) : blowfish(key_data, key_length)
{
    // Do nothing but call parent constructor.
}


/**
 * Input length required to be a multiple of 8 (block size), otherwise
 * NULL is returned as output. Returned char* pointer must freed.
 *
 * See /docs/src/blowfish_cbc.txt for more details.
**/
char* blowfish_cbc::block_encrypt(const char* data, const char* iv,
                                  int data_length)
{
    int i = 0;

    uint32_t left;
    uint32_t right;

    uint32_t last_left;
    uint32_t last_right;

    char* result;

    if (data_length % 8 != 0) {
        return NULL;
    }

    result = (char *) malloc(sizeof(char) * data_length);

    /*
        set last_block to IV

        for each 8-byte block to length of input:
            current = block xor last_block
            blowfish->encrypt(current)
            last_block = current
            append current to result
    */

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

std::string blowfish_cbc::block_encrypt(std::string data, std::string iv)
{
    char* result = this->block_encrypt(data.c_str(), iv.c_str(), data.length());

    if (result == NULL) {
        return "";
    }

    // Construct a string with length equal to the original data's length
    std::string str_result(result, data.length());
    free(result);

    return str_result;
}


/**
 * Input length required to be a multiple of 8 (block size), otherwise
 * NULL is returned as output. Returned char* pointer must freed.
 *
 * See /docs/src/blowfish_cbc.txt for more details.
**/
char* blowfish_cbc::block_decrypt(const char* data, const char* iv,
                                  int data_length)
{
    int i = 0;

    uint32_t left;
    uint32_t right;

    uint32_t save_left;
    uint32_t save_right;

    uint32_t last_left;
    uint32_t last_right;

    char* result;

    if (data_length % 8 != 0) {
        return NULL;
    }

    result = (char *) malloc(sizeof(char) * data_length);

    /*
        set last_block to IV

        for each 8-byte block to length of input:
            saved_block = block
            blowfish->decrypt(block)
            block = block xor last_block
            last_block = saved_block
            append block to result
    */

    last_left = ((uint8_t) iv[0] << 24) + ((uint8_t) iv[1] << 16) +
                ((uint8_t) iv[2] << 8) + (uint8_t) iv[3];
    last_right = ((uint8_t) iv[4] << 24) + ((uint8_t) iv[5] << 16) +
                 ((uint8_t) iv[6] << 8) + (uint8_t) iv[7];

    for (i = 0; i < data_length; i+=8) {
        left = ((uint8_t) data[i+0] << 24) + ((uint8_t) data[i+1] << 16) +
               ((uint8_t) data[i+2] << 8) + (uint8_t) data[i+3];
        right = ((uint8_t) data[i+4] << 24) + ((uint8_t) data[i+5] << 16) +
                ((uint8_t) data[i+6] << 8) + (uint8_t) data[i+7];

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

std::string blowfish_cbc::block_decrypt(std::string data, std::string iv)
{
    char* result = this->block_decrypt(data.c_str(), iv.c_str(), data.length());

    if (result == NULL) {
        return "";
    }

    // Construct a string with length equal to the original data's length
    std::string str_result(result, data.length());
    free(result);

    return str_result;
}
