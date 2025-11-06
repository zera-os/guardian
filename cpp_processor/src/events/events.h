#pragma once

#include "zera_api.pb.h"

enum class EventType
{
    UNKNOWN = 0,
    SEND_NATIVE_ZERA_TO_SOLANA = 1,
    RELEASE_NATIVE_SOLANA_TO_SOLANA = 2,
    MINT_NATIVE_SOLANA_TO_ZERA = 3,
    RELEASE_NATIVE_ZERA_TO_ZERA = 4,
    CREATE_WRAPPED_SOLANA_TO_ZERA = 5,
    PAUSE_BRIDGE = 6,
    UPDATE_TOKEN_BRIDGE = 7,
    UPDATE_CORE_BRIDGE = 8,
    UPDATE_GUARDIAN_KEYS = 9
};

struct ZeraToSolana
{
    std::string contract_id;
    std::string solana_address;
    std::string amount;
};

namespace events
{
    void process_zera_events(const zera_api::SmartContractEventsResponse *request);
    // Functions to read events from the zera network and make payloads to send to the solana network
    void send_native_zera_to_solana(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp);
    void release_native_solana_to_solana(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp);
    void create_wrapped_zera_to_solana(const std::string contract_id, const std::string amount, const std::string solana_address, const std::string txn_hash, const uint64_t timestamp);
    void mint_native_zera_to_solana(const std::string contract_id, const std::string amount, const std::string solana_address, const std::string txn_hash, const uint64_t timestamp);
    void update_guardian_keys(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp);

    void process_solana_events(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string& slot, const std::string& tx_signature);
    // Functions to read events from the solana network and make payloads to send to the zera network
    void create_wrapped_solana_to_zera(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string& slot, const std::string& tx_signature);
    void release_native_zera_to_zera(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string& slot, const std::string& tx_signature);
    void mint_native_solana_to_zera(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string& slot, const std::string& tx_signature);

    //Governace events
    void upgrade_token_bridge(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp, const bool token_bridge);
    void pause_bridge(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp);
}
inline EventType GetEventType(const std::string &event_type)
{
    if (event_type == "SEND_NATIVE_ZERA_TO_SOLANA")
    {
        return EventType::SEND_NATIVE_ZERA_TO_SOLANA;
    }
    else if (event_type == "RELEASE_NATIVE_SOLANA_TO_SOLANA")
    {
        return EventType::RELEASE_NATIVE_SOLANA_TO_SOLANA;
    }
    else if (event_type == "MINT_NATIVE_SOLANA_TO_ZERA")
    {
        return EventType::MINT_NATIVE_SOLANA_TO_ZERA;
    }
    else if (event_type == "RELEASE_NATIVE_ZERA_TO_ZERA")
    {
        return EventType::RELEASE_NATIVE_ZERA_TO_ZERA;
    }
    else if (event_type == "CREATE_WRAPPED_SOLANA_TO_ZERA")
    {
        return EventType::CREATE_WRAPPED_SOLANA_TO_ZERA;
    }
    else if(event_type == "SEND_WRAPPED_SOLANA_TO_SOLANA")
    {
        //TOD REMOVE THIS EVENT AND CHANGE ON ZERA NETWORK
        return EventType::RELEASE_NATIVE_SOLANA_TO_SOLANA;
    }
    else if(event_type == "RELEASE_ZERA")
    {
        return EventType::RELEASE_NATIVE_ZERA_TO_ZERA;
    }
    else if(event_type == "PAUSE_SOLANA_BRIDGE")
    {
        return EventType::PAUSE_BRIDGE;
    }
    else if (event_type == "UPDATE_TOKEN_BRIDGE")
    {
        return EventType::UPDATE_TOKEN_BRIDGE;
    }
    else if(event_type == "UPDATE_CORE_BRIDGE")
    {
        return EventType::UPDATE_CORE_BRIDGE;
    }
    else if(event_type == "UPDATE_GUARDIAN_KEYS")
    {
        return EventType::UPDATE_GUARDIAN_KEYS;
    }
    else
    {
        return EventType::UNKNOWN;
    }
}