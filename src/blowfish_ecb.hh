/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Header file for blowfish cryptographic primitive
*/

#pragma once
#ifndef BLOWFISH_ECB_H
#define BLOWFISH_ECB_H

#include "blowfish.hh"

class blowfish_ecb : blowfish
{
public:
    char* block_encrypt(const char* data, int data_length);
    char* block_decrypt(const char* data, int data_length);

    std::string block_encrypt(std::string data);
    std::string block_decrypt(std::string data);

    blowfish_ecb(const char* key_data, int key_length);
    blowfish_ecb(std::string key);
};

#endif
