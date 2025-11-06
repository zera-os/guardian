#pragma once

#include <sodium.h>
#include <string>
#include <vector>
#include <iostream>
#include "validator.pb.h"
#include "zera_api.pb.h"


struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};
enum class KeyType {
    ED25519,
    ED448,
    ERROR_TYPE
};

namespace signatures {

    template <typename TXType>
    void sign_txns(TXType* txn, KeyPair key_pair);

    bool verify_multi(const std::string& public_key, const std::string& signature, const std::string& message); 
    KeyType get_key_type(const std::string &public_key, bool restricted = false);
    int get_key_size(const KeyType& key_type);
    void sign_activity_request(zera_api::ActivityRequest& request, KeyPair key_pair);
    bool verify_activity_response(const zera_api::SmartContractEventsResponse *request);
    std::vector<uint8_t> sign_hash(std::vector<uint8_t> &hash, KeyPair key_pair);
    bool verify_contract_response(const zera_api::ContractResponse *response);
    bool verify_hash(const std::string& hash, const std::string& signature, const std::string& public_key, bool is_zera);
    // bool verify_signature(const std::vector<unsigned char>& message, std::vector<unsigned char>& signature, std::vector<unsigned char>& public_key);
};