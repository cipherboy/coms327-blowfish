/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Implementation for the blowfish cryptographic primitive
*/

#include "blowfish.hh"
#include "blowfish_constants.hh"

#include <cstdlib>


/**
 * Initialize the blowfish sub-keys and s-boxes based off the given key.
 *
 * See /docs/src/blowfish.txt for more details.
**/
blowfish::blowfish(char* key_data, int key_length)
{
    int i = 0;
    int key_loc = 0;

    uint32_t zero_left = 0;
    uint32_t zero_right = 0;

    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;

    uint32_t key_segment;

    // Initialize with digits of Pi
    for (i = 0; i < 18; i++) {
        this->subkeys[i] = blowfish_init_subkeys[i];
    }
    for (i = 0; i < 256; i++) {
        this->sboxes[0][i] = blowfish_init_sbox_0[i];
    }
    for (i = 0; i < 256; i++) {
        this->sboxes[1][i] = blowfish_init_sbox_1[i];
    }
    for (i = 0; i < 256; i++) {
        this->sboxes[2][i] = blowfish_init_sbox_2[i];
    }
    for (i = 0; i < 256; i++) {
        this->sboxes[3][i] = blowfish_init_sbox_3[i];
    }

    // xor all sub-keys with key segments.
    for (i = 0; i < 18; i++) {
        a = key_data[(key_loc+0) % key_length];
        b = key_data[(key_loc+1) % key_length];
        c = key_data[(key_loc+2) % key_length];
        d = key_data[(key_loc+3) % key_length];
        key_segment = (a << 24) + (b << 16) + (c << 8) + d;

        this->subkeys[i] = this->subkeys[i] ^ key_segment;

        key_loc = (key_loc+4) % key_length;
    }

    // Beginning with zero vectors, update sub-keys and s-boxes with encrypted
    // forms; ensures key gets propegated to all parts of the cipher
    for (i = 0; i < 18; i+=2) {
        this->encrypt(&zero_left, &zero_right);
        this->subkeys[i] = zero_left;
        this->subkeys[i+1] = zero_right;
    }

    for (i = 0; i < 256; i+=2) {
        this->encrypt(&zero_left, &zero_right);
        this->sboxes[0][i] = zero_left;
        this->sboxes[0][i+1] = zero_right;
    }

    for (i = 0; i < 256; i+=2) {
        this->encrypt(&zero_left, &zero_right);
        this->sboxes[1][i] = zero_left;
        this->sboxes[1][i+1] = zero_right;
    }

    for (i = 0; i < 256; i+=2) {
        this->encrypt(&zero_left, &zero_right);
        this->sboxes[2][i] = zero_left;
        this->sboxes[2][i+1] = zero_right;
    }

    for (i = 0; i < 256; i+=2) {
        this->encrypt(&zero_left, &zero_right);
        this->sboxes[3][i] = zero_left;
        this->sboxes[3][i+1] = zero_right;
    }
}


/**
 * Private function. Implements the Feistel function from the blowfish
 * specification; this is where the s-boxes are used.
 *
 * See /docs/src/blowfish.txt for more details.
**/
uint32_t blowfish::function_f(uint32_t data)
{
    // Set up each part
    uint8_t a = (data & 0xFF000000) >> 24;
    uint8_t b = (data & 0x00FF0000) >> 16;
    uint8_t c = (data & 0x0000FF00) >> 8;
    uint8_t d = data & 0x000000FF;

    // Feistel function; ensure 32-bit unsigned integer
    uint32_t result = ((this->sboxes[0][a] + this->sboxes[1][b]) ^
                       (this->sboxes[2][c])) + this->sboxes[3][d];

    return result;
}


/**
 * Encrypt either 8 bytes of data or two 4-byte integer halves.
 *
 * See /docs/src/blowfish.txt for more details.
**/
void blowfish::encrypt(uint32_t* left, uint32_t* right)
{
    uint32_t l = *left;
    uint32_t r = *right;

    /*
        With sub-keys i=0...15:
            left = left xor subkey[i]
            right = right xor f(left)
            swap left, right
        ~~
        Fully unrolled below.
    */
    l = l ^ this->subkeys[0];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[1];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[2];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[3];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[4];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[5];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[6];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[7];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[8];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[9];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[10];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[11];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[12];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[13];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[14];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[15];
    l = l ^ this->function_f(r);

    /*
        swap left, right
        right = right xor subkey[16]
        left = left xor subkey[17]
        ~~
        Or don't bother swapping and swap on assignment.
    */
    l = l ^ this->subkeys[16];
    r = r ^ this->subkeys[17];

    *right = l;
    *left = r;
}


/**
 * Encrypt either 8 bytes of data or two 4-byte integer halves.
 * char* result must be freed after use, uint32_t* need not be.
 *
 * See /docs/src/blowfish.txt for more details.
**/
char* blowfish::encrypt(char data[8])
{
    uint32_t left;
    uint32_t right;
    char* result;

    result = (char *) malloc(sizeof(char) * 8);

    left = ((uint8_t) data[0] << 24) + ((uint8_t) data[1] << 16) + ((
                uint8_t) data[2] << 8) + (uint8_t) data[3];
    right = ((uint8_t) data[4] << 24) + ((uint8_t) data[5] << 16) + ((
                uint8_t) data[6] << 8) + (uint8_t) data[7];

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


/**
 * Decrypt either 8 bytes of data or two 4-byte integer halves.
 *
 * See /docs/src/blowfish.txt for more details.
**/
void blowfish::decrypt(uint32_t* left, uint32_t* right)
{
    uint32_t l = *left;
    uint32_t r = *right;

    /*
        With sub-keys i=17...2:
            left = left xor subkey[i]
            right = right xor f(left)
            swap left, right
        ~~
        Fully unrolled below.
    */
    l = l ^ this->subkeys[17];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[16];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[15];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[14];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[13];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[12];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[11];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[10];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[9];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[8];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[7];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[6];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[5];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[4];
    l = l ^ this->function_f(r);
    l = l ^ this->subkeys[3];
    r = r ^ this->function_f(l);
    r = r ^ this->subkeys[2];
    l = l ^ this->function_f(r);

    /*
        swap left, right
        right = right xor subkey[1]
        left = left xor subkey[0]
        ~~
        Or don't bother swapping and swap on assignment.
    */
    l = l ^ this->subkeys[1];
    r = r ^ this->subkeys[0];

    *right = l;
    *left = r;
}


/**
 * Decrypt either 8 bytes of data or two 4-byte integer halves.
 * char* pointer must be freed after use.
 *
 * See /docs/src/blowfish.txt for more details.
**/
char* blowfish::decrypt(char data[8])
{
    uint32_t left;
    uint32_t right;
    char* result;

    result = (char *) malloc(sizeof(char) * 8);

    left = ((uint8_t) data[0] << 24) + ((uint8_t) data[1] << 16) + ((
                uint8_t) data[2] << 8) + (uint8_t) data[3];
    right = ((uint8_t) data[4] << 24) + ((uint8_t) data[5] << 16) + ((
                uint8_t) data[6] << 8) + (uint8_t) data[7];

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
