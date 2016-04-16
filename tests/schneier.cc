#include "../src/blowfish.hh"
#include <cstdlib>
#include <iostream>

bool schneier_ecb_test()
{
    char keys[34][8] = {{(char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00},
        {(char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF},
        {(char) 0x30, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00},
        {(char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11},
        {(char) 0x01, (char) 0x23, (char) 0x45, (char) 0x67, (char) 0x89, (char) 0xAB, (char) 0xCD, (char) 0xEF},
        {(char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11, (char) 0x11},
        {(char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00},
        {(char) 0xFE, (char) 0xDC, (char) 0xBA, (char) 0x98, (char) 0x76, (char) 0x54, (char) 0x32, (char) 0x10},
        {(char) 0x7C, (char) 0xA1, (char) 0x10, (char) 0x45, (char) 0x4A, (char) 0x1A, (char) 0x6E, (char) 0x57},
        {(char) 0x01, (char) 0x31, (char) 0xD9, (char) 0x61, (char) 0x9D, (char) 0xC1, (char) 0x37, (char) 0x6E},
        {(char) 0x07, (char) 0xA1, (char) 0x13, (char) 0x3E, (char) 0x4A, (char) 0x0B, (char) 0x26, (char) 0x86},
        {(char) 0x38, (char) 0x49, (char) 0x67, (char) 0x4C, (char) 0x26, (char) 0x02, (char) 0x31, (char) 0x9E},
        {(char) 0x04, (char) 0xB9, (char) 0x15, (char) 0xBA, (char) 0x43, (char) 0xFE, (char) 0xB5, (char) 0xB6},
        {(char) 0x01, (char) 0x13, (char) 0xB9, (char) 0x70, (char) 0xFD, (char) 0x34, (char) 0xF2, (char) 0xCE},
        {(char) 0x01, (char) 0x70, (char) 0xF1, (char) 0x75, (char) 0x46, (char) 0x8F, (char) 0xB5, (char) 0xE6},
        {(char) 0x43, (char) 0x29, (char) 0x7F, (char) 0xAD, (char) 0x38, (char) 0xE3, (char) 0x73, (char) 0xFE},
        {(char) 0x07, (char) 0xA7, (char) 0x13, (char) 0x70, (char) 0x45, (char) 0xDA, (char) 0x2A, (char) 0x16},
        {(char) 0x04, (char) 0x68, (char) 0x91, (char) 0x04, (char) 0xC2, (char) 0xFD, (char) 0x3B, (char) 0x2F},
        {(char) 0x37, (char) 0xD0, (char) 0x6B, (char) 0xB5, (char) 0x16, (char) 0xCB, (char) 0x75, (char) 0x46},
        {(char) 0x1F, (char) 0x08, (char) 0x26, (char) 0x0D, (char) 0x1A, (char) 0xC2, (char) 0x46, (char) 0x5E},
        {(char) 0x58, (char) 0x40, (char) 0x23, (char) 0x64, (char) 0x1A, (char) 0xBA, (char) 0x61, (char) 0x76},
        {(char) 0x02, (char) 0x58, (char) 0x16, (char) 0x16, (char) 0x46, (char) 0x29, (char) 0xB0, (char) 0x07},
        {(char) 0x49, (char) 0x79, (char) 0x3E, (char) 0xBC, (char) 0x79, (char) 0xB3, (char) 0x25, (char) 0x8F},
        {(char) 0x4F, (char) 0xB0, (char) 0x5E, (char) 0x15, (char) 0x15, (char) 0xAB, (char) 0x73, (char) 0xA7},
        {(char) 0x49, (char) 0xE9, (char) 0x5D, (char) 0x6D, (char) 0x4C, (char) 0xA2, (char) 0x29, (char) 0xBF},
        {(char) 0x01, (char) 0x83, (char) 0x10, (char) 0xDC, (char) 0x40, (char) 0x9B, (char) 0x26, (char) 0xD6},
        {(char) 0x1C, (char) 0x58, (char) 0x7F, (char) 0x1C, (char) 0x13, (char) 0x92, (char) 0x4F, (char) 0xEF},
        {(char) 0x01, (char) 0x01, (char) 0x01, (char) 0x01, (char) 0x01, (char) 0x01, (char) 0x01, (char) 0x01},
        {(char) 0x1F, (char) 0x1F, (char) 0x1F, (char) 0x1F, (char) 0x0E, (char) 0x0E, (char) 0x0E, (char) 0x0E},
        {(char) 0xE0, (char) 0xFE, (char) 0xE0, (char) 0xFE, (char) 0xF1, (char) 0xFE, (char) 0xF1, (char) 0xFE},
        {(char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x00},
        {(char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF},
        {(char) 0x01, (char) 0x23, (char) 0x45, (char) 0x67, (char) 0x89, (char) 0xAB, (char) 0xCD, (char) 0xEF},
        {(char) 0xFE, (char) 0xDC, (char) 0xBA, (char) 0x98, (char) 0x76, (char) 0x54, (char) 0x32, (char) 0x10}
    };

    uint32_t plaintexts[34][2] = {{0x00000000, 0x00000000},
        {0xFFFFFFFF, 0xFFFFFFFF},
        {0x10000000, 0x00000001},
        {0x11111111, 0x11111111},
        {0x11111111, 0x11111111},
        {0x01234567, 0x89ABCDEF},
        {0x00000000, 0x00000000},
        {0x01234567, 0x89ABCDEF},
        {0x01A1D6D0, 0x39776742},
        {0x5CD54CA8, 0x3DEF57DA},
        {0x0248D438, 0x06F67172},
        {0x51454B58, 0x2DDF440A},
        {0x42FD4430, 0x59577FA2},
        {0x059B5E08, 0x51CF143A},
        {0x0756D8E0, 0x774761D2},
        {0x762514B8, 0x29BF486A},
        {0x3BDD1190, 0x49372802},
        {0x26955F68, 0x35AF609A},
        {0x164D5E40, 0x4F275232},
        {0x6B056E18, 0x759F5CCA},
        {0x004BD6EF, 0x09176062},
        {0x480D3900, 0x6EE762F2},
        {0x437540C8, 0x698F3CFA},
        {0x072D43A0, 0x77075292},
        {0x02FE5577, 0x8117F12A},
        {0x1D9D5C50, 0x18F728C2},
        {0x30553228, 0x6D6F295A},
        {0x01234567, 0x89ABCDEF},
        {0x01234567, 0x89ABCDEF},
        {0x01234567, 0x89ABCDEF},
        {0xFFFFFFFF, 0xFFFFFFFF},
        {0x00000000, 0x00000000},
        {0x00000000, 0x00000000},
        {0xFFFFFFFF, 0xFFFFFFFF}
    };

    uint32_t ciphertexts[34][2] = {{0x4EF99745, 0x6198DD78},
        {0x51866FD5, 0xB85ECB8A},
        {0x7D856F9A, 0x613063F2},
        {0x2466DD87, 0x8B963C9D},
        {0x61F9C380, 0x2281B096},
        {0x7D0CC630, 0xAFDA1EC7},
        {0x4EF99745, 0x6198DD78},
        {0x0ACEAB0F, 0xC6A0A28D},
        {0x59C68245, 0xEB05282B},
        {0xB1B8CC0B, 0x250F09A0},
        {0x1730E577, 0x8BEA1DA4},
        {0xA25E7856, 0xCF2651EB},
        {0x353882B1, 0x09CE8F1A},
        {0x48F4D088, 0x4C379918},
        {0x432193B7, 0x8951FC98},
        {0x13F04154, 0xD69D1AE5},
        {0x2EEDDA93, 0xFFD39C79},
        {0xD887E039, 0x3C2DA6E3},
        {0x5F99D04F, 0x5B163969},
        {0x4A057A3B, 0x24D3977B},
        {0x452031C1, 0xE4FADA8E},
        {0x7555AE39, 0xF59B87BD},
        {0x53C55F9C, 0xB49FC019},
        {0x7A8E7BFA, 0x937E89A3},
        {0xCF9C5D7A, 0x4986ADB5},
        {0xD1ABB290, 0x658BC778},
        {0x55CB3774, 0xD13EF201},
        {0xFA34EC48, 0x47B268B2},
        {0xA7907951, 0x08EA3CAE},
        {0xC39E072D, 0x9FAC631D},
        {0x014933E0, 0xCDAFF6E4},
        {0xF21E9A77, 0xB71C49BC},
        {0x24594688, 0x5754369A},
        {0x6B5C5A9C, 0x5D9E0A5A}
    };

    int i = 0;

    std::cout << "Starting test case: ecb @ schneier.cc..." << std::endl;

    for (i = 0; i < 34; i++) {
        blowfish* ciph = new blowfish(keys[i], 8);
        uint32_t l = plaintexts[i][0];
        uint32_t r = plaintexts[i][1];
        ciph->encrypt(&l, &r);
        if (l != ciphertexts[i][0]) {
            std::cerr << "Error with test case: " << i << "::" << l << "::" <<
                      ciphertexts[i][0] << std::endl;
            return false;
        } else if (r != ciphertexts[i][1]) {
            std::cerr << "Error with test case: " << i << "::" << r << "::" <<
                      ciphertexts[i][1] << std::endl;
            return false;
        }

        ciph->decrypt(&l, &r);
        if (l != plaintexts[i][0]) {
            std::cerr << "Error with test case: " << i << "::" << l << "::" <<
                      plaintexts[i][0] << std::endl;
            return false;
        } else if (r != plaintexts[i][1]) {
            std::cerr << "Error with test case: " << i << "::" << r << "::" <<
                      plaintexts[i][1] << std::endl;
            return false;
        }

        delete ciph;
    }

    std::cout << "Passed test case: ecb @ schneier.cc" << std::endl;

    return true;
}

bool schneier_set_key_test()
{
    uint32_t plaintext_l = 0xFEDCBA98;
    uint32_t plaintext_r = 0x76543210;
    char key[24] = {(char) 0xF0, (char) 0xE1, (char) 0xD2, (char) 0xC3, (char) 0xB4, (char) 0xA5, (char) 0x96, (char) 0x87, (char) 0x78, (char) 0x69, (char) 0x5A, (char) 0x4B, (char) 0x3C, (char) 0x2D, (char) 0x1E, (char) 0x0F, (char) 0x00, (char) 0x11, (char) 0x22, (char) 0x33, (char) 0x44, (char) 0x55, (char) 0x66, (char) 0x77};

    uint32_t ciphertexts[24][2] = {{0xF9AD597C, 0x49DB005E},
        {0xE91D21C1, 0xD961A6D6},
        {0xE9C2B70A, 0x1BC65CF3},
        {0xBE1E6394, 0x08640F05},
        {0xB39E4448, 0x1BDB1E6E},
        {0x9457AA83, 0xB1928C0D},
        {0x8BB77032, 0xF960629D},
        {0xE87A244E, 0x2CC85E82},
        {0x15750E7A, 0x4F4EC577},
        {0x122BA70B, 0x3AB64AE0},
        {0x3A833C9A, 0xFFC537F6},
        {0x9409DA87, 0xA90F6BF2},
        {0x884F8062, 0x5060B8B4},
        {0x1F85031C, 0x19E11968},
        {0x79D9373A, 0x714CA34F},
        {0x93142887, 0xEE3BE15C},
        {0x03429E83, 0x8CE2D14B},
        {0xA4299E27, 0x469FF67B},
        {0xAFD5AED1, 0xC1BC96A8},
        {0x10851C0E, 0x3858DA9F},
        {0xE6F51ED7, 0x9B9DB21F},
        {0x64A6E14A, 0xFD36B46F},
        {0x80C7D7D4, 0x5A5479AD},
        {0x05044B62, 0xFA52D080}
    };

    int i = 1;

    std::cout << "Starting test case: set_key @ schneier.cc..." << std::endl;

    for (i = 0; i < 24; i++) {
        blowfish* ciph = new blowfish(key, i+1);
        uint32_t l = plaintext_l;
        uint32_t r = plaintext_r;

        ciph->encrypt(&l, &r);
        if (l != ciphertexts[i][0]) {
            std::cerr << "Error with test case: " << i << "::" << l << "::" <<
                      ciphertexts[i][0] << std::endl;
            return false;
        } else if (r != ciphertexts[i][1]) {
            std::cerr << "Error with test case: " << i << "::" << r << "::" <<
                      ciphertexts[i][1] << std::endl;
            return false;
        }

        ciph->decrypt(&l, &r);
        if (l != plaintext_l) {
            std::cerr << "Error with test case: " << i << "::" << l << "::" << plaintext_l
                      << std::endl;
            return false;
        } else if (r != plaintext_r) {
            std::cerr << "Error with test case: " << i << "::" << r << "::" << plaintext_r
                      << std::endl;
            return false;
        }

        delete ciph;
    }

    std::cout << "Passed test case: set_key @ schneier.cc" << std::endl;

    return true;
}
