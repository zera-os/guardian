#pragma once

#include <string>
#include "signatures.h"

class GuardianConfig{

    public:
    static void set_threshold(const uint32_t threshold);
    static uint32_t get_threshold();
    static void set_config();
    static KeyPair get_key_pair();
    static std::string get_public_key_b58();
    static void set_trusted_zera_public_key_b58();
    static std::string get_solana_public_key_b58();

    static int get_number_of_guardians();
    static int get_guardian_index();

    static std::string get_trusted_zera_public_key_b58();
    static std::string get_trusted_zera_public_key();


    //in public becuase this will change as time goes on and the number of guardians is updated
    static void set_number_of_guardians(const int number_of_guardians);
    static void set_guardian_index(const int guardian_index);

    static void set_solana_public_key();

    private:
    static KeyPair key_pair_;
    static std::string public_key_b58_;
    static int number_of_guardians_;
    static int guardian_index_;
    static std::string trusted_zera_public_key_b58_;
    static std::string trusted_zera_public_key_;
    static std::string solana_public_key_b58_;
    static uint32_t threshold_;


    static void set_key_pair();
    static void set_public_key_b58();
};