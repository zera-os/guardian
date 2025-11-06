#pragma once

#include <iostream>
#include <string>
#include <vector>

struct LockEvent {
    std::string version;
    std::string payer;
    std::string vault;
    uint64_t amount = 0; // little-endian
    std::string zera_address;
    std::string solana_mint_id;
    uint64_t slot = 0;
    std::string signature;
    std::string zera_contract_id;
    std::string solana_sender;
    bool is_wrapped = false;
    
    // Check if event is valid (not empty)
    explicit operator bool() const {
        return !signature.empty() && slot > 0;
    }
};

struct ParsedLog {
    std::string kind;        // "invoke" | "log" | "data" | "consumed" | "success"
    std::string program;     // base58 program id (when present)
    int depth = -1;          // from invoke [n] (when present)
    std::string message;     // for "Program log: ..."
    LockEvent event;    // for "Program data: ..."
    uint64_t cu_used = 0, cu_limit = 0; // for consumed
};

class solana_subscriber
{
    public:
    static void parse_and_process_program_data(const char *signature, uint64_t slot, const char *logs_json);
};
