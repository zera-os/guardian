#pragma once

#include "guardian.pb.h"

class payload {
    public:
    static void process_solana_payload(zera_guardian::SolanaPayload& payload, std::vector<uint8_t>& hash, const std::string& txn_hash, const uint64_t timestamp);
    static void process_zera_payload(zera_guardian::ZeraPayload& payload, std::vector<uint8_t>& hash, const std::string& txn_signature);
    static void store_payload(const std::string &txn_hash, zera_guardian::SolanaPayload &payload);
    static void store_payload(const std::string &tx_signature, zera_guardian::ZeraPayload &payload);
};

