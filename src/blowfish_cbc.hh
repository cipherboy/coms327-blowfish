/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * Header file for blowfish cryptographic primitive
*/

#pragma once
#ifndef BLOWFISH_CBC_H
#define BLOWFISH_CBC_H

#include "blowfish.hh"

class blowfish_cbc : blowfish
{
public:
    char* block_encrypt(char* data, char* iv, int data_length);
    char* block_decrypt(char* data, char* iv, int data_length);

    blowfish_cbc(char* key_data, int key_length);
};

#endif
