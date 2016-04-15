/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * main method
*/

#include "blowfish.h"

#include <cstdint>
#include <iostream>
#include "stdio.h"

using namespace std;

int main(int argc, char* argv[])
{
    char key_data[16] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'};
    int length = 16;
    blowfish* ciph = new blowfish(key_data, length);
    char* plain_text= (char*) malloc(sizeof(char) * 9);
    plain_text[0] = 'H';
    plain_text[1] = 'I';
    plain_text[2] = ' ';
    plain_text[3] = 'T';
    plain_text[4] = 'H';
    plain_text[5] = 'E';
    plain_text[6] = 'R';
    plain_text[7] = 'E';
    plain_text[8] = '\0';

    uint32_t l = *((uint32_t *) &plain_text[0]);
    uint32_t r = *((uint32_t *) &plain_text[4]);

    cout << endl << endl << endl;
    cout << endl << endl << endl;
    cout << endl << endl << endl;
    cout << endl << endl << endl;
    cout << endl << endl << endl;

    uint32_t zero_left = 0;
    uint32_t zero_right = 0;
    ciph->encrypt_helper(&zero_left, &zero_right);
    cout << "l: " << zero_left << endl << "r: " << zero_right << endl << endl << endl;
    ciph->decrypt_helper(&zero_left, &zero_right);
    cout << "l: " << zero_left << endl << "r: " << zero_right << endl;

    cout << "l: "<< l << " || r: " << r << endl;
    ciph->encrypt_helper(&l, &r);
    cout << "l: "<< l << " || r: " << r << endl;
    ciph->decrypt_helper(&l, &r);
    cout << "l: "<< l << " || r: " << r << endl;

}
