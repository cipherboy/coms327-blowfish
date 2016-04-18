/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Header file for blowfish cryptographic primitive
*/

#pragma once
#ifndef BLOWFISH_CBC_H
#define BLOWFISH_CBC_H

#include "blowfish.hh"
#include <string>

class blowfish_cbc : blowfish
{
public:
    char* block_encrypt(const char* data, const char* iv, int data_length);
    char* block_decrypt(const char* data, const char* iv, int data_length);
    std::string block_encrypt(std::string data, std::string iv);
    std::string block_decrypt(std::string data, std::string iv);

    blowfish_cbc(const char* key_data, int key_length);
    blowfish_cbc(std::string key);
};

#endif
