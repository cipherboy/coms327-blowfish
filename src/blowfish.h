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
    int key_length; // In bytes
    uint32_t subkeys[18];
    uint32_t sboxes[4][256];

    uint32_t function_f(uint32_t data);
    void encrypt_helper(uint32_t* left, uint32_t* right);
    void decrypt_helper(uint32_t* left, uint32_t* right);
public:
    char* encrypt(char bytes[8]);
    char* decrypt(char data[8]);

    blowfish(char key_data[32]);
};

#endif
