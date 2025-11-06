#include "solana_subscriber.h"
#include <string>
#include <vector>
#include "encoding.h"
#include "events.h"
#include "threadpool.h"
#include <regex>
#include "nlohmann/json.hpp"
#include "encoding.h"
#include <optional>
#include <cstring>
#include <iostream>
#include "const.h"
#include "db_base.h"

namespace
{

    LockEvent parseLockEvent(const std::string &jsonStr, uint64_t slot, const std::string &signature)
    {

        bool is_spl = false;
        bool is_wrapped = false;
        // Parse JSON
        nlohmann::json j;
        try
        {
            j = nlohmann::json::parse(jsonStr);
        }
        catch (...)
        {
            return LockEvent();
        }
        if(j.contains("event"))
        {
            if(j["event"] == "Lock_SOL")
            {
                is_spl = false;
            }
            else if(j["event"] == "Lock_SPL")
            {
                std::cout << "Lock_SPL" << std::endl;
                is_spl = true;
            }
            else if(j["event"] == "Burn_Wrapped")
            {
                is_wrapped = true;
            }
            else
            {
                return LockEvent();
            }
        }
        else
        {
            return LockEvent();
        }
        
        

        // Read fields (amount/nonce may be strings or numbers)
        auto to_u64 = [](const nlohmann::json &v) -> uint64_t
        {
            if (v.is_string())
                return std::stoull(v.get<std::string>());
            if (v.is_number_unsigned())
                return v.get<uint64_t>();
            if (v.is_number_integer())
                return static_cast<uint64_t>(v.get<long long>());
            throw std::runtime_error("bad amount type");
        };

        try
        {
            if(is_wrapped)
            {
                LockEvent evt{
                    j.at("version").get<std::string>(),
                    j.at("authority").get<std::string>(),
                    "N/A",
                    to_u64(j.at("amount")),
                    j.at("zera_address").get<std::string>(),
                    j.at("mint").get<std::string>(),
                    slot,
                    signature,
                    j.at("zera_contract_id").get<std::string>(),
                    j.at("solana_sender").get<std::string>(),
                    true
                };
                return evt;
            }
            else if(is_spl)
            {
                LockEvent evt{
                    j.at("version").get<std::string>(),
                    j.at("payer").get<std::string>(),
                    j.at("vault_ata").get<std::string>(),
                    to_u64(j.at("amount")),
                    j.at("zera_address").get<std::string>(),
                    j.at("mint").get<std::string>(),
                    slot,
                    signature,
                    "N/A",
                    j.at("solana_sender").get<std::string>(),
                    false
                };
                return evt;
            }
            else
            {
                LockEvent evt{
                    j.at("version").get<std::string>(),
                    j.at("payer").get<std::string>(),
                    j.at("vault").get<std::string>(),
                    to_u64(j.at("amount")),
                    j.at("zera_address").get<std::string>(),
                    SOL_MINT_ID,
                    slot,
                    signature,
                    "N/A",
                    j.at("solana_sender").get<std::string>(),
                    false
                };
                return evt;
            }
        }
        catch (...)
        {
            return LockEvent();
        }

        return LockEvent();
    }

    ParsedLog parseSolanaLogs(const std::string &s, uint64_t slot, const std::string &signature)
    {

        std::cout << "s=" << s << std::endl;
        std::vector<std::string> lines = nlohmann::json::parse(s).get<std::vector<std::string>>();
        ParsedLog out;

        std::regex reInvoke(R"(^\s*Program\s+(\S+)\s+invoke\s+\[(\d+)\]\s*$)");
        std::regex reLog(R"(^\s*Program\s+log:\s*(.*)\s*$)");
        std::regex reData(R"(^\s*Program\s+data:\s*([A-Za-z0-9+/=]+)\s*$)");
        std::regex reConsumed(R"(^\s*Program\s+(\S+)\s+consumed\s+(\d+)\s+of\s+(\d+)\s+compute\s+units\s*$)");
        std::regex reSuccess(R"(^\s*Program\s+(\S+)\s+success\s*$)");
        std::smatch m;
        std::string event_data;
        for (const auto &line : lines)
        {

            if (std::regex_match(line, m, reInvoke))
            {
                out.program = m[1];
                out.depth = std::stoi(m[2]);
            }
            else if (std::regex_match(line, m, reLog))
            {
                out.event = parseLockEvent(m[1], slot, signature);
            }
            else if (std::regex_match(line, m, reConsumed))
            {
                out.cu_used = std::stoull(m[2]);
                out.cu_limit = std::stoull(m[3]);
            }
            else if (std::regex_match(line, m, reSuccess))
            {
                out.kind = "success";
            }
            else
            {
                continue;
            }
        }
        return out;
    }

    void process_solana_events(const ParsedLog &parsed_logs)
    {

        std::vector<std::string> keys;
        std::vector<std::string> values;

        std::string mint_id = parsed_logs.event.solana_mint_id;
        std::string mint_data;

        if(parsed_logs.event.is_wrapped)
        {
            std::cout << "RELEASE_ZERA" << std::endl;
            keys.push_back("EVENT");
            values.push_back("RELEASE_ZERA");
            keys.push_back("zera_contract_id");
            values.push_back(parsed_logs.event.zera_contract_id);
            mint_id = "N/A";
        }
        else if(db_contracts::exist(mint_id))
        {
            std::cout << "MINT SOLANA" << std::endl;
            keys.push_back("EVENT");
            values.push_back("MINT_NATIVE_SOLANA_TO_ZERA");
        }
        else
        {
            std::cout << "CREATE WRAPPED SOLANA" << std::endl;
            keys.push_back("EVENT");
            values.push_back("CREATE_WRAPPED_SOLANA_TO_ZERA");
            db_contracts::store_single(mint_id, "1");
        }
        
        keys.push_back("amount");
        values.push_back(std::to_string(parsed_logs.event.amount));
        keys.push_back("solana_mint_id");
        values.push_back(mint_id);
        keys.push_back("recipient");
        values.push_back(parsed_logs.event.zera_address);
        std::string slot_str = std::to_string(parsed_logs.event.slot);
        std::string signature_str = parsed_logs.event.signature;
        events::process_solana_events(keys, values, slot_str, signature_str);
    }
}

void solana_subscriber::parse_and_process_program_data(const char *signature, uint64_t slot, const char *logs_json)
{

    if (!logs_json)
    {
        return;
    }

    const std::string s(logs_json);
    size_t pos = 0;


    ParsedLog parsed_logs = parseSolanaLogs(s, slot, signature);

    // Check if event is valid before processing
    if (!parsed_logs.event) {
        std::cout << "Empty or invalid event, skipping processing" << std::endl;
        return;
    }

    process_solana_events(parsed_logs);
}