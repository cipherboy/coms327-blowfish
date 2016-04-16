# Project 2

    u: Alexander Scheel
    e: <scheel@iastate.edu>
    l: BSD: 2-clause

## Overview
This is my final project for COM S 327. The goal of this project are as follows:

1. Implement the Blowfish cryptographic primitive
2. Implement block modes on top of the primitive
3. Demonstrate attacks against the various block modes

For clarity of data typing, this project uses C++-11 for the availability of
uint32_t and uint8_t; many other implementations use "unsigned long", which
is not compatible across operating systems. In particular, a number of systems
define this as an 64-bit type, but it is necessary to have it as a 32-bit type
for the implementation of blowfish.


## Running
To compile and run the tests to ensure validity of the implementation:

    make all
    ./bin/tests

The attacks are implemented in main/main.cc; to run:

    make all
    ./bin/blowfish
