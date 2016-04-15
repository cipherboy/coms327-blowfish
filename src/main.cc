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
    char key_data[] = "TESTKEY";
    int length = 7;
    blowfish* ciph = new blowfish(key_data, length);
    char* plain_text= (char*) malloc(sizeof(char) * 8);
    plain_text[0] = 'H';
    plain_text[1] = 'I';
    plain_text[2] = ' ';
    plain_text[3] = 'T';
    plain_text[4] = 'H';
    plain_text[5] = 'E';
    plain_text[6] = 'R';
    plain_text[7] = 'E';

    uint32_t zero_left = 1;
    uint32_t zero_right = 2;
    ciph-> encrypt(&zero_left, &zero_right);
    cout << "l: " << zero_left << endl << "r: " << zero_right << endl << endl << endl;
    printf("%08X %08X\n", zero_left, zero_right);
    ciph-> decrypt(&zero_left, &zero_right);
    cout << "l: " << zero_left << endl << "r: " << zero_right << endl;


}
