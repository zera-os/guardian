#include "guardian_config.h"
#include "encoding.h"

std::string GuardianConfig::public_key_b58_ = "";
KeyPair GuardianConfig::key_pair_;
int GuardianConfig::number_of_guardians_ = 1;
int GuardianConfig::guardian_index_ = 0;
std::string GuardianConfig::trusted_zera_public_key_b58_ = "";
std::string GuardianConfig::trusted_zera_public_key_ = "";
std::string GuardianConfig::solana_public_key_b58_ = "";
uint32_t GuardianConfig::threshold_ = 2;

void GuardianConfig::set_config(){
    set_key_pair();
    set_public_key_b58();
    set_solana_public_key();
    set_trusted_zera_public_key_b58();

}

void GuardianConfig::set_key_pair(){
   auto public_key = std::getenv("PUBLIC_KEY");
   auto private_key = std::getenv("PRIVATE_KEY");
   key_pair_.public_key = base58_decode_public_key(public_key);
   key_pair_.private_key = base58_decode(private_key);

}

void GuardianConfig::set_trusted_zera_public_key_b58(){
    auto public_key = std::getenv("TRUSTED_VALIDATOR_PUBLIC_KEY");
    trusted_zera_public_key_b58_ = public_key;
}

std::string GuardianConfig::get_solana_public_key_b58(){
    return solana_public_key_b58_;
}

void GuardianConfig::set_solana_public_key(){
    auto public_key = std::getenv("GUARDIAN_SOL_PUBLIC_KEY");
    solana_public_key_b58_ = public_key;
}

void GuardianConfig::set_public_key_b58(){
    public_key_b58_ = base58_encode_public_key(key_pair_.public_key);
}

void GuardianConfig::set_threshold(const uint32_t threshold){
    threshold_ = threshold;
}

uint32_t GuardianConfig::get_threshold(){
    return threshold_;
}

KeyPair GuardianConfig::get_key_pair(){
    return key_pair_;
}

std::string GuardianConfig::get_public_key_b58(){
    return public_key_b58_;
}

void GuardianConfig::set_number_of_guardians(const int number_of_guardians){
    number_of_guardians_ = number_of_guardians;
}

void GuardianConfig::set_guardian_index(const int guardian_index){
    guardian_index_ = guardian_index;
}

int GuardianConfig::get_number_of_guardians(){
    return number_of_guardians_;
}

int GuardianConfig::get_guardian_index(){
    return guardian_index_;
}

std::string GuardianConfig::get_trusted_zera_public_key_b58(){
    return trusted_zera_public_key_b58_;
}

std::string GuardianConfig::get_trusted_zera_public_key(){
    return trusted_zera_public_key_;
}
