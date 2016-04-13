/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Header file for blowfish cryptographic primitive
*/

#pragma once
#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <cstdint>

using namespace std;

extern const uint32_t init_subkeys[18];
extern const uint32_t init_sbox_0[256];
extern const uint32_t init_sbox_1[256];
extern const uint32_t init_sbox_2[256];
extern const uint32_t init_sbox_3[256];

class blowfish
{
private:
    char* key;
    uint32_t subkeys[18];
    uint32_t sboxes[4][256];

    void function_f(uint32_t data, uint32_t bytes);

public:
    char* encrypt(char bytes[8]);
    void decrypt(char bytes[8], char* plaintext);

    blowfish(char key_data[32]);
};

#endif
