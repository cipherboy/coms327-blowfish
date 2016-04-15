/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Header file for blowfish cryptographic primitive
*/

#pragma once
#ifndef BLOWFISH_ECB_H
#define BLOWFISH_ECB_H

#include <cstdint>
#include "blowfish.hh"

class blowfish_ecb : blowfish
{
public:
    char* block_encrypt(char* bytes, int length);
    char* block_decrypt(char* data, int length);

    blowfish_ecb(char* key_data, int key_length);
};

#endif
