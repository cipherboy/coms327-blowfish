/*
 * Copyright (c) 2016 Alexander Scheel
 *
 * main method
*/

#include "../src/blowfish.hh"
#include "../src/blowfish_ecb.hh"
#include "../src/blowfish_cbc.hh"

#include <cstdint>
#include <iostream>
#include <cstring>
#include "stdio.h"

using namespace std;

string ecb_decryption_attack_magic_key = "gCJIT5voUktvtFqFlNq8V5bUShmrid";
string ecb_cut_and_paste_attack_magic_key = "VoXzMNXhxLD4NPJn2QjG9HT9iN2Ur8";

string ecb_decryption_attack_encrypt_helper(string str)
{
    blowfish_ecb ciph(ecb_decryption_attack_magic_key);
    string text = str +
                  "\x0d\x0a\x4c\x6f\x21\x20\x74\x68\x65\x20\x53\x70\x65\x61\x72\x2d\x44\x61\x6e\x65\x73\x27\x20\x67\x6c\x6f\x72\x79\x20\x74\x68\x72\x6f\x75\x67\x68\x20\x73\x70\x6c\x65\x6e\x64\x69\x64\x20\x61\x63\x68\x69\x65\x76\x65\x6d\x65\x6e\x74\x73\x0d\x0a\x54\x68\x65\x20\x66\x6f\x6c\x6b\x2d\x6b\x69\x6e\x67\x73\x27\x20\x66\x6f\x72\x6d\x65\x72\x20\x66\x61\x6d\x65\x20\x77\x65\x20\x68\x61\x76\x65\x20\x68\x65\x61\x72\x64\x20\x6f\x66\x2c\x0d\x0a\x48\x6f\x77\x20\x70\x72\x69\x6e\x63\x65\x73\x20\x64\x69\x73\x70\x6c\x61\x79\x65\x64\x20\x74\x68\x65\x6e\x20\x74\x68\x65\x69\x72\x20\x70\x72\x6f\x77\x65\x73\x73\x2d\x69\x6e\x2d\x62\x61\x74\x74\x6c\x65\x2e\x0d\x0a\x4f\x66\x74\x20\x53\x63\x79\x6c\x64\x20\x74\x68\x65\x20\x53\x63\x65\x66\x69\x6e\x67\x20\x66\x72\x6f\x6d\x20\x73\x63\x61\x74\x68\x65\x72\x73\x20\x69\x6e\x20\x6e\x75\x6d\x62\x65\x72\x73\x0d\x0a\x46\x72\x6f\x6d\x20\x6d\x61\x6e\x79\x20\x61\x20\x70\x65\x6f\x70\x6c\x65\x20\x74\x68\x65\x69\x72\x20\x6d\x65\x61\x64\x2d\x62\x65\x6e\x63\x68\x65\x73\x20\x74\x6f\x72\x65\x2e\x0d\x0a\x53\x69\x6e\x63\x65\x20\x66\x69\x72\x73\x74\x20\x68\x65\x20\x66\x6f\x75\x6e\x64\x20\x68\x69\x6d\x20\x66\x72\x69\x65\x6e\x64\x6c\x65\x73\x73\x20\x61\x6e\x64\x20\x77\x72\x65\x74\x63\x68\x65\x64\x2c\x0d\x0a\x54\x68\x65\x20\x65\x61\x72\x6c\x20\x68\x61\x64\x20\x68\x61\x64\x20\x74\x65\x72\x72\x6f\x72\x3a\x20\x63\x6f\x6d\x66\x6f\x72\x74\x20\x68\x65\x20\x67\x6f\x74\x20\x66\x6f\x72\x20\x69\x74\x2c\x0d\x0a\x57\x61\x78\x65\x64\x20\x27\x6e\x65\x61\x74\x68\x20\x74\x68\x65\x20\x77\x65\x6c\x6b\x69\x6e\x2c\x20\x77\x6f\x72\x6c\x64\x2d\x68\x6f\x6e\x6f\x72\x20\x67\x61\x69\x6e\x65\x64\x2c\x0d\x0a\x54\x69\x6c\x6c\x20\x61\x6c\x6c\x20\x68\x69\x73\x20\x6e\x65\x69\x67\x68\x62\x6f\x72\x73\x20\x6f\x27\x65\x72\x20\x73\x65\x61\x20\x77\x65\x72\x65\x20\x63\x6f\x6d\x70\x65\x6c\x6c\x65\x64\x20\x74\x6f\x0d\x0a\x42\x6f\x77\x20\x74\x6f\x20\x68\x69\x73\x20\x62\x69\x64\x64\x69\x6e\x67\x20\x61\x6e\x64\x20\x62\x72\x69\x6e\x67\x20\x68\x69\x6d\x20\x74\x68\x65\x69\x72\x20\x74\x72\x69\x62\x75\x74\x65\x3a\x0d\x0a\x41\x6e\x20\x65\x78\x63\x65\x6c\x6c\x65\x6e\x74\x20\x61\x74\x68\x65\x6c\x69\x6e\x67\x21\x20\x41\x66\x74\x65\x72\x20\x77\x61\x73\x20\x62\x6f\x72\x6e\x65\x20\x68\x69\x6d\x0d\x0a\x41\x20\x73\x6f\x6e\x20\x61\x6e\x64\x20\x68\x65\x69\x72\x2c\x20\x79\x6f\x75\x6e\x67\x20\x69\x6e\x20\x68\x69\x73\x20\x64\x77\x65\x6c\x6c\x69\x6e\x67\x2c\x0d\x0a\x57\x68\x6f\x6d\x20\x47\x6f\x64\x2d\x46\x61\x74\x68\x65\x72\x20\x73\x65\x6e\x74\x20\x74\x6f\x20\x73\x6f\x6c\x61\x63\x65\x20\x74\x68\x65\x20\x70\x65\x6f\x70\x6c\x65\x2e";

    int byte = 8 - (text.length() % 8);
    int i = 0;
    for (i = 0; i < byte; i++) {
        text += (char) byte;
    }

    return ciph.block_encrypt(text);
}

void ecb_decryption_attack()
{
    int target_length = ecb_decryption_attack_encrypt_helper("1").length();
    string start = "AAAAAAA";
    string known = "";
    string block = "AAAAAAA";

    int target_block = 0;
    for (int i = 0; i < target_length; i++) {
        string target = ecb_decryption_attack_encrypt_helper(start).substr(
                            target_block*8,
                            8);

        for (int j = 0; j < 255; j++) {
            string current = ecb_decryption_attack_encrypt_helper(block +
                             (char) j).substr(0, 8);
            if (current.compare(target) == 0) {
                known += (char) j;
                break;
            }
        }

        if (start.length() == 0) {
            start = "AAAAAAA";
            target_block += 1;
        } else {
            start = start.substr(1);
        }

        block = block.substr(1);
        block = block + known.substr(known.length()-1);
    }

    cout << known << endl;
}

string ecb_cut_and_paste_attack_profile_for(string email)
{
    blowfish_ecb ciph(ecb_decryption_attack_magic_key);

    size_t found = email.find("=");
    if (found != string::npos) {
        return "";
    }

    size_t found2 = email.find("&");
    if (found2 != string::npos) {
        return "";
    }

    string text = "email=" + email + "&uid=10&role=user";

    int byte = 8 - (text.length() % 8);
    int i = 0;
    for (i = 0; i < byte; i++) {
        text += (char) byte;
    }

    return ciph.block_encrypt(text);
}

bool ecb_cut_and_paste_attack_is_admin(string profile)
{
    blowfish_ecb ciph(ecb_decryption_attack_magic_key);
    string plain_text = ciph.block_decrypt(profile);

    size_t found = plain_text.find("role=admin");
    if (found != string::npos) {
        return true;
    }
    return false;
}

int ecb_cut_and_paste_attack_has_duplicate_block(string ciphertext)
{
    for (unsigned int i = 0; i < (ciphertext.length()-1)/8; i++) {
        for (unsigned int j = i+1; j < (ciphertext.length())/8; j++) {
            if (ciphertext.substr(i*8, 8).compare(ciphertext.substr(j*8, 8)) == 0) {
                return j;
            }
        }
    }

    return -1;
}

void ecb_cut_and_paste_attack()
{
    // Detect length of content.
    int initial_length = ecb_cut_and_paste_attack_profile_for("").length();
    int next_length = ecb_cut_and_paste_attack_profile_for("").length();
    string block = "";
    while (initial_length == next_length) {
        block += "A";
        next_length = ecb_cut_and_paste_attack_profile_for(block).length();
    }

    int total_content_length = initial_length - block.length();

    cout  << "Length of content not controlled by attacker: " <<
          total_content_length << endl;

    // Detect initial prefix length, mod blocksize
    block = "";
    // Under ECB, will encrypt to the same string iff aligned to a block size.
    string detect =
        "\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08";
    for (int i = 0; i < 8; i++) {
        string encrypted = ecb_cut_and_paste_attack_profile_for(block + detect);
        if (ecb_cut_and_paste_attack_has_duplicate_block(encrypted) == -1) {
            block += "A";
        }
    }

    cout << "Length of prefix, mod blocksize: " << 8-block.length() << endl;

    string cut = "admin\x03\x03\x03";
    string encrypted = ecb_cut_and_paste_attack_profile_for(block + detect + cut);
    cout << "Last duplicate block: " <<
         ecb_cut_and_paste_attack_has_duplicate_block(encrypted) << endl;
    string paste = encrypted.substr((ecb_cut_and_paste_attack_has_duplicate_block(
                                         encrypted)+1)*8, 8);

    // Now, to align user to a boundary, notice that we have total_content_length
    // characters. To push over a boundary, add enough characters until
    // total_content_length + extra % 8 == 4
    block = "";
    int extra = 0;
    while ((total_content_length+extra) % 8 != 4) {
        extra += 1;
        block += "A";
    }

    string profile = ecb_cut_and_paste_attack_profile_for(block);
    profile = profile.substr(0, profile.length() - 8);
    profile += paste;
    cout << "Is admin? " << ecb_cut_and_paste_attack_is_admin(profile) << endl;
}

int main(int argc, char* argv[])
{
    cout << "Beginning ECB Decryption Attack..." << endl;
    ecb_decryption_attack();
    cout << "Beginning ECB Cut and Paste Attack..." << endl;
    ecb_cut_and_paste_attack();
}
