/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Header file defining the blowfish cryptographic primitive
*/

#pragma once
#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <cstdint>

class blowfish
{
private:
    uint32_t subkeys[18];
    uint32_t sboxes[4][256];

    uint32_t function_f(uint32_t data);
public:
    char* encrypt(char* bytes);
    char* decrypt(char* data);
    void  encrypt(uint32_t* left, uint32_t* right);
    void  decrypt(uint32_t* left, uint32_t* right);

    blowfish(char* key_data, int key_length); // in bytes
};

#endif
