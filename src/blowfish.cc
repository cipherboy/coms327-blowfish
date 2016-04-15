/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Implement for blowfish cryptographic primitive
*/

#include "blowfish.hh"

#include <stdio.h>
#include <cstdlib>

blowfish::blowfish(char* key_data, int key_length)
{
    int i = 0;
    int key_loc = 0;

    uint32_t zero_left = 0;
    uint32_t zero_right = 0;

    for (i = 0; i < 18; i++) {
        this->subkeys[i] = this->init_subkeys[i];
    }
    for (i = 0; i < 256; i++) {
        this->sboxes[0][i] = this->init_sbox_0[i];
    }
    for (i = 0; i < 256; i++) {
        this->sboxes[1][i] = this->init_sbox_1[i];
    }
    for (i = 0; i < 256; i++) {
        this->sboxes[2][i] = this->init_sbox_2[i];
    }
    for (i = 0; i < 256; i++) {
        this->sboxes[3][i] = this->init_sbox_3[i];
    }

    for (i = 0; i < 18; i++) {
        uint8_t a = key_data[(key_loc+0) % key_length];
        uint8_t b = key_data[(key_loc+1) % key_length];
        uint8_t c = key_data[(key_loc+2) % key_length];
        uint8_t d = key_data[(key_loc+3) % key_length];
        uint32_t key_segment = (a << 24) + (b << 16) + (c << 8) + d;
        key_loc = (key_loc+4) % key_length;

        this->subkeys[i] = this->subkeys[i] ^ key_segment;
    }

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

uint32_t blowfish::function_f(uint32_t data)
{
    uint8_t a = (data & 0xFF000000) >> 24;
    uint8_t b = (data & 0x00FF0000) >> 16;
    uint8_t c = (data & 0x0000FF00) >> 8;
    uint8_t d = data & 0x000000FF;

    uint32_t result = ((this->sboxes[0][a] + this->sboxes[1][b]) ^ (this->sboxes[2][c])) + this->sboxes[3][d];

    return result;
}

void blowfish::encrypt(uint32_t* left, uint32_t* right)
{
    int i = 0;
    uint32_t tmp = *left;

    uint32_t l = *left;
    uint32_t r = *right;
    // Funrolling of loops ^.^;
    /*
        xL = xL XOR Pi
        xR = F(xL) XOR xR
        Swap xL and xR
    */
    for (i = 0; i < 16; i+=2) {
        l = l ^ this->subkeys[i];
        r = r ^ this->function_f(l);
        r = r ^ this->subkeys[i+1];
        l = l ^ this->function_f(r);
    }

    /*
        Swap xL and xR (Undo the last swap.)
        xR = xR XOR P17
        xL = xL XOR P18
        Recombine xL and xR
    */
    tmp = l;
    l = r;
    r = tmp;

    r = r ^ this->subkeys[16];
    l = l ^ this->subkeys[17];

    *right = r;
    *left = l;
}

void blowfish::decrypt(uint32_t* left, uint32_t* right)
{
    int i = 0;
    uint32_t tmp = *left;

    uint32_t l = *left;
    uint32_t r = *right;

    /*
        xL = xL XOR Pi
        xR = F(xL) XOR xR
        Swap xL and xR
    */
    for (i = 16; i >= 2; i-=2) {
        l = l ^ this->subkeys[i+1];
        r = r ^ this->function_f(l);
        r = r ^ this->subkeys[i];
        l = l ^ this->function_f(r);
    }

    /*
        Swap xL and xR (Undo the last swap.)
        xR = xR XOR P17
        xL = xL XOR P18
        Recombine xL and xR
    */
    tmp = l;
    l = r;
    r = tmp;

    r = r ^ this->subkeys[1];
    l = l ^ this->subkeys[0];

    *right = r;
    *left = l;
}

char* blowfish::encrypt(char data[8])
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

char* blowfish::decrypt(char data[8])
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
