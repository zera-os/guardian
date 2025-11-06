#include "events.h"
#include "hashing.h"
#include "guardian.pb.h"
#include "payload.h"


void events::upgrade_token_bridge(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp, const bool token_bridge)
{
    std::cout << "Upgrading token bridge" << std::endl;

    std::string buffer_address;
    std::string spill_address;

    for(int i = 0; i < keys.size(); i++)
    {
        std::cout << keys[i] << ": " << values[i] << std::endl;

        if(keys[i] == "buffer")
        {
            buffer_address = values[i];
        }
        else if(keys[i] == "spill")
        {
            spill_address = values[i];
        }
    }

    if(buffer_address.empty() || spill_address.empty())
    {
        std::cout << "Missing required fields" << std::endl;
        return;
    }

    zera_guardian::SolanaUpgradeBridgePayload upgrade_payload;

    upgrade_payload.set_buffer_address(buffer_address);
    upgrade_payload.set_spill_address(spill_address);
    upgrade_payload.set_txn_hash(txn_hash);
    upgrade_payload.set_token_bridge(token_bridge);

    auto hash = Hashing::build_upgrade_token_bridge_hash(buffer_address, spill_address, txn_hash, timestamp, token_bridge);

    auto hash_hex = to_hex(hash);

    zera_guardian::SolanaPayload solana_payload;
    //solana_payload.mutable_timestamp()->set_seconds(timestamp);

    solana_payload.set_signed_hash(hash_hex);

    solana_payload.mutable_upgrade_bridge_payload()->CopyFrom(upgrade_payload);

    payload::process_solana_payload(solana_payload, hash, txn_hash, timestamp);

    std::cout << "Upgrading bridge" << std::endl;

}

void events::pause_bridge(const std::vector<std::string> &keys, const std::vector<std::string> &values, const std::string txn_hash, const uint64_t timestamp)
{

    std::string pause_level_str;
    std::string pause_duration_str;
    
    for(int i = 0; i < keys.size(); i++)
    {
        std::cout << keys[i] << ": " << values[i] << std::endl;

        if(keys[i] == "pause_level")
        {
            pause_level_str = values[i];
        }
        else if(keys[i] == "pause_duration")
        {
            pause_duration_str = values[i];
        }
    }
    
    // Validate and parse pause level
    int pause_level;
    try {
        pause_level = std::stoi(pause_level_str);
        std::cout << "Pause level: " << pause_level << std::endl;
    } catch (const std::invalid_argument& e) {
        std::cerr << "❌ ERROR: Invalid pause_level - not a number: '" << pause_level_str << "'" << std::endl;
        return;
    } catch (const std::out_of_range& e) {
        std::cerr << "❌ ERROR: Pause level out of range: '" << pause_level_str << "'" << std::endl;
        return;
    }

    // Validate and parse pause duration
    uint64_t pause_duration;
    try {
        pause_duration = std::stoull(pause_duration_str);
        std::cout << "Pause duration: " << pause_duration << std::endl;
    } catch (const std::invalid_argument& e) {
        std::cerr << "❌ ERROR: Invalid pause_duration - not a number: '" << pause_duration_str << "'" << std::endl;
        return;
    } catch (const std::out_of_range& e) {
        std::cerr << "❌ ERROR: Pause duration out of range: '" << pause_duration_str << "'" << std::endl;
        return;
    }

    zera_guardian::SolanaPausePayload pause_payload;

    pause_payload.set_pause_level(pause_level);
    pause_payload.set_pause_duration(pause_duration);
    pause_payload.set_txn_hash(txn_hash);

    auto hash = Hashing::build_wrapped_pause_hash(pause_level, pause_duration, txn_hash, timestamp);
    auto hash_hex = to_hex(hash);

    zera_guardian::SolanaPayload solana_payload;
    solana_payload.set_signed_hash(hash_hex);
    solana_payload.mutable_pause_payload()->CopyFrom(pause_payload);
    //solana_payload.mutable_timestamp()->set_seconds(timestamp);

    payload::process_solana_payload(solana_payload, hash, txn_hash, timestamp);

    std::cout << "Pausing bridge" << std::endl;
}