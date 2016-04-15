#include "../src/blowfish.h"
#include <cstdlib>
#include <iostream>

extern bool schneier_ecb_test();
extern bool schneier_set_key_test();

int main(void)
{
    if (!schneier_ecb_test()) {
        std::cout << "Tests failed" << std::endl;
        return 1;
    }

    if (!schneier_set_key_test()) {
        std::cout << "Tests failed" << std::endl;
        return 1;
    }
    return 0;
}
