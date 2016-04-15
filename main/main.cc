/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * main method
*/

#include "../src/blowfish.hh"
#include "../src/blowfish_cbc.hh"

#include <cstdint>
#include <iostream>
#include <cstring>
#include "stdio.h"

using namespace std;

int main(int argc, char* argv[])
{
    char key_data[] = "TESTKEY";
    int length = 7;
    blowfish* ciph = new blowfish(key_data, length);
    char* plain_text= (char*) malloc(sizeof(char) * 8);
    strcpy(plain_text, "Hi All!");

    uint32_t zero_left = 1;
    uint32_t zero_right = 2;
    ciph->encrypt(&zero_left, &zero_right);
    cout << "l: " << zero_left << endl << "r: " << zero_right << endl << endl << endl;
    printf("%08X %08X\n", zero_left, zero_right);
    ciph->decrypt(&zero_left, &zero_right);
    cout << "l: " << zero_left << endl << "r: " << zero_right << endl;

    char* cipher_text = ciph->encrypt(plain_text);
    char* plaintext = ciph->decrypt(cipher_text);

    cout << plain_text << " "  << plaintext << endl;

    free(cipher_text);
    free(plaintext);

    char* plain_text_2 = (char*) malloc(sizeof(char) * 40);
    strncpy(plain_text_2, "12345678 Hello World! This is a test.78", 40);

    char* iv = (char*) malloc(sizeof(char) * 9);
    strncpy(iv, "12345678", 9);

    blowfish_cbc* ciph2 = new blowfish_cbc(key_data, length);
    char* cipher_text_2 = ciph2->block_encrypt(plain_text_2, iv, 40);
    char* plaintext2 = ciph2->block_decrypt(cipher_text_2, iv, 40);

    cout << plain_text_2 << " " << plaintext2 << endl;

    free(plain_text);
    free(plain_text_2);
    free(cipher_text_2);
    free(plaintext2);

    delete ciph;
    delete ciph2;
}
