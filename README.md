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

The source for the primitive and various abstracted block modes are in the
/src directory. The two currently implemented block modes are ECB and CBC.
Eventually, CTR mode (stream cipher) might be implemented. For the block
modes, the block_(en/de)crypt functions have been overloaded to support both
the encryption of char* style strings and std::string style strings.

The source for the testing of this implementation are located in the /test
directory. The test vectors are those given by Schneier, attributed to 
Young. This is the defacto set of test vectors, matched by Go's and LibreSSL's
Blowfish implementations, along with many other reference implementations.

Finally, the source for the attacks against the various block modes are 
located in the /main directory. As of the time of submission, there are
two attacks implemented: appended-string decryption with unknown key, 
and a mock privilege escalation attack, as if given an encrypted cookie. These
attacks are modeled after Cryptopals challenges 12 and 13. 


Documentation of Blowfish, block mode APIs, and of the attacks are located
in the /docs directory.


## Running
To compile and run the tests to ensure validity of the implementation:

    make all
    ./bin/tests

The attacks are implemented in main/main.cc; to run:

    make all
    ./bin/blowfish
